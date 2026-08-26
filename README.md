# rqft

**RQFT** — robust file transfer over unreliable serial links (USB CDC,
Bluetooth SPP bridges, raw UARTs). Designed for embedded devices and host
software while remaining transport- and device-agnostic.

Two independent, interoperable implementations of one spec:

| Where | What |
|---|---|
| [`SPEC.md`](SPEC.md) | Normative protocol spec (framing, reliability, sessions) |
| [`c/`](c/) | `librqft` — C++17 with a C-callable API, zero heap, zero globals, and non-blocking polls; builds with CMake and packages for PlatformIO |
| [`python/`](python/) | `rqft` — sans-io protocol core + blocking `SyncClient` + pyserial transport |
| [`testvectors/`](testvectors/) | Golden JSON vectors + byte-exact session traces shared by both implementations |
| [`interop/`](interop/) | C↔Python fault-injection interop harness (the robustness proof) |

## C++ library quickstart

`c/` is a C++17 library with a C-callable API, no heap allocation, no globals,
and caller-owned contexts. It builds directly with CMake and includes
PlatformIO package metadata. Install a tagged GitHub release archive:

```ini
[env:device]
lib_deps =
    rqft=https://github.com/Tapio-Measurement-Technologies/rqft/releases/download/v1.0.0/rqft-platformio-1.0.0.tar.gz
```

Standalone CMake build, install, and `find_package()` instructions are in
[`c/README.md`](c/README.md).

Create one static driver, provide transport/event/filesystem callbacks, and
poll it from the superloop. The driver owns the session, drains RX before
polling timers, and completes partial writes. Filesystem callbacks implement
the `rqft_fs_ops_t` interface documented in
[`session.h`](c/include/rqft/session.h).

Read callbacks must be non-blocking and return zero when currently available
RX is drained. Write callbacks may return partial progress; zero or a negative
value is a transport failure. Call `rqft_session_driver_poll()` again for each
extra bounded work slice. Process passthrough events synchronously, and pause
text-protocol transmission while `rqft_session_active()` is true. Access the
owned session with `rqft_session_driver_session()` for operations, state,
progress, and abort. Driver context stores self-references: do not move or copy
it after `rqft_session_driver_init()`. Hosts that already own a transport pump
may instead use the lower-level `rqft_session_*` API and obey its documented
RX-first and complete-transmit contracts. See
[`rqft_fs_ops_t`](c/include/rqft/session.h) for temp-write/commit, listing,
reading, and delete callback contracts.

A device-side cancel (user input, storage unmount, shutdown) ends the session
from the superloop with
`rqft_session_abort(rqft_session_driver_session(&driver),
RQFT_ABORT_E_USER, millis())` — any in-flight
transfer's temporary file is discarded and the ENDED event fires. For a
clean shutdown send `RQFT_ABORT_CLOSE` the same way, ideally once
`rqft_session_work_pending()` is false so the outbound stream is quiescent.

For a transfer progress display, call `rqft_session_progress()` from the
superloop: while a file transfer is in flight it reports the bytes done and
the total (from FILE_INFO, PUT_REQ, or the filesystem callbacks), for the
GET the device is serving as well as the PUT it is receiving. No extra wire
traffic is involved; rate-limit the redraw, not the call.

## Python client quickstart

Install Python package plus pyserial adapter from a GitHub release wheel:

```sh
python -m pip install "rqft[serial] @ https://github.com/Tapio-Measurement-Technologies/rqft/releases/download/v1.0.0/rqft-1.0.0-py3-none-any.whl"
```

Download files missing or changed under a local directory. Existing files
match only when size and CRC32 both match; downloads preserve relative paths
and publish through a temporary file only after verification.

```python
from pathlib import Path

from rqft.client import SyncClient, SyncProgress
from rqft.serial_transport import SerialTransport


def report(progress: SyncProgress) -> None:
    print(
        progress.phase.value,
        progress.path or "",
        f"{progress.files_done}/{progress.files_total}",
        f"{progress.bytes_done}/{progress.bytes_total}",
    )


transport = SerialTransport("/dev/ttyACM0", baudrate=115200)
client = SyncClient(transport, Path("downloads"), progress=report)
try:
    result = client.sync_from_peer(delete_remote=False)
    print(f"fetched={len(result.fetched)} skipped={len(result.skipped)}")
finally:
    client.close()
```

`delete_remote=True` removes each remote file only after verified local
commit, and requires responder delete capability plus its per-request gate.
Pass a `threading.Event` as `cancel_event` to send `ABORT(E_USER)` on
cancellation. For GUI integration, run `SyncClient` in a worker thread; it is
blocking and has no GUI imports.

Hosts driving `rqft.session.Session` directly get per-file byte counters
from `Session.progress()`: between pump turns it snapshots the in-flight
GET or PUT (bytes done plus the total once known) for either role, mirroring
`rqft_session_progress()` on the C side. `Session.diagnostics()` returns an
immutable snapshot of frame counters, including valid inactive-session
candidates discarded by idle flush, retransmitted DATA frames, NAKs,
duplicates, and gaps, plus current link RTT, RTO, and flight state for host
status displays. Active sessions retain partial frame candidates across
transport gaps and resynchronize on delimiters instead of idle-flushing them.

Hosts needing operations beyond `SyncClient` can pair a sans-io `Session`
with any `ByteTransport` through `BlockingSessionDriver`. One `pump()` turn
flushes pending output, performs one bounded read, feeds received bytes into
the session before running due timers and bounded work, then returns typed
events plus the raw received-byte count. RX-first ordering prevents a buffered
frame delimiter from losing a race with the parser's idle-flush deadline.

## Interactive demo client

`rqft-demo` (also `python -m rqft.demo`) is a shell-like terminal client
for exploring an RQFT device: pick a serial port from an interactive
menu, then browse the remote tree (`ls`, `cd`, `tree`, tab completion),
transfer files (`get`, `put`, `cat`, `sync`), delete (`rm`, `rmdir`),
and inspect the link (`stats` for session/link/frame counters, `log`
for a timestamped protocol debug log including DATA retransmissions
and device passthrough text). A background thread keeps the session
keepalive running while the prompt is idle.

```sh
rqft-demo                     # scan serial ports, pick interactively
rqft-demo --port /dev/ttyACM0 # open a specific port
rqft-demo --loopback          # no hardware: in-process demo responder
```

Downloads and upload staging live in a local mirror directory
(`--dir`, default `./rqft-local`). The `--loopback` mode serves a
seeded temporary directory from an in-process responder session —
useful for trying the protocol without a device. The responder thread
stops and its temporary directory is removed when the demo exits.

## API and conformance

- C embedded entrypoint: [`c/include/rqft/driver.h`](c/include/rqft/driver.h)
- C sans-I/O session: [`c/include/rqft/session.h`](c/include/rqft/session.h)
- C complete umbrella: [`c/include/rqft/rqft.h`](c/include/rqft/rqft.h)
- C protocol layers: [`c/include/rqft/`](c/include/rqft/)
- Python blocking client: [`python/src/rqft/client.py`](python/src/rqft/client.py)
- Python generic blocking pump: `rqft.client.BlockingSessionDriver`
- Python local directory provider: `rqft.client.LocalDirFs`
- Python sans-io session: [`python/src/rqft/session.py`](python/src/rqft/session.py)
- Clause checklist and verification evidence: [`CONFORMANCE.md`](CONFORMANCE.md)

## Running the tests

```sh
# C (native)
cmake -S c -B c/build -DCMAKE_BUILD_TYPE=Debug
cmake --build c/build
ctest --test-dir c/build --output-on-failure

# Python
pip install -e 'python[dev]'
mypy --strict python/src/rqft
pytest python/tests

# Interop matrix (needs both of the above)
pytest interop
```

Everything is deterministic — scripted clocks, seeded fault injection, no
sleeps, and no hardware required.

## Design in one paragraph

Frames are COBS-encoded and 0x00-delimited with a CRC32 trailer, so
arbitrary junk on the line is either passed through to the host (between
frames) or rejected and resynced (inside a frame). A Go-Back-N window of 4
with adaptive RTO gives reliability and flow control without hardware
handshaking. On top rides a controller/responder session: HELLO handshake
(either side may initiate — a responder HELLO is just a doorbell), then
LIST / GET / PUT / DEL / PLAN messages with per-file CRC verification and
temp-write-then-commit semantics. The C context is caller-allocated
(about 10 KiB for a session), the library never allocates, and one
`rqft_session_poll()` call does a bounded slice of work — safe inside a
bare-metal superloop next to a GUI.

## Releases

Exact `vMAJOR.MINOR.PATCH` Git tag is release-version source for Python,
CMake, and PlatformIO packages. No version source files need editing.
Three-component tags are required:

```sh
git tag v1.0.0
git push origin v1.0.0
```

Python builds use tag through `setuptools-scm`. Release packaging uses
`tools/release.py` to put same version into CMake and PlatformIO source
archives that no longer contain Git metadata. After all CI gates pass, tag
workflow publishes one GitHub Release containing:

- `rqft-MAJOR.MINOR.PATCH-py3-none-any.whl`;
- `rqft-MAJOR.MINOR.PATCH.tar.gz`;
- `rqft-platformio-MAJOR.MINOR.PATCH.tar.gz`;
- `SHA256SUMS`.

## License

Copyright © 2026
[Tapio Measurement Technologies Oy](https://tapiotechnologies.com).

Licensed under GNU General Public License v3.0 only. See [`LICENSE`](LICENSE). The copyright owner may use and license its own code separately.
