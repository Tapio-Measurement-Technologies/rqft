# RQFT v1 conformance

This checklist maps every normative subsection of [`SPEC.md`](SPEC.md) to
both implementations and automated evidence. `[x]` means implemented and
covered. Informative text has no conformance requirement and is marked
`N/A`.

Paths below are repository-relative. C tests run through `ctest`; Python and
interop evidence names are pytest modules unless a specific test is named.

## 1. Conventions

- [x] **§1 integer representation.** All multi-byte wire fields use
  little-endian helpers in `c/src/frame.cpp`, `c/src/message.cpp`,
  `python/src/rqft/frame.py`, and `python/src/rqft/messages.py`. Byte-exact
  coverage: `testvectors/frames.json`, `testvectors/messages.json`, and both
  `test_frame` / `test_messages` suites.
- [x] **§1 unreliable ordered byte stream.** Neither implementation assumes
  message-sized reads. Byte-at-a-time, re-chunk, loss, duplication,
  corruption, burst loss, and injected foreign traffic are covered by
  `test_frame`, `test_link_loopback`, and `interop/test_fault_matrix.py`.
- [x] **§1 paths.** Both `rqft_path_valid()` and `path_valid()` enforce the
  128-byte limit, strict UTF-8, relative non-empty segments, and rejection of
  leading `/`, empty segments, `.`, `..`, NUL, and backslash. Empty path is
  accepted only when caller permits LIST root. Evidence:
  `c/tests/test_message.c`, `python/tests/test_messages.py`, and invalid-path
  cases in every session operation suite.
- [x] **§1 monotonic timers.** Time enters both sans-io APIs through explicit
  monotonic millisecond values. Wrap-safe C subtraction and deterministic
  scripted-clock behavior are covered by frame, link, RTO, handshake, and
  keepalive tests.

## 2. Layering

- [x] **§2 separation.** CRC32, COBS, frame, link, message, and session layers
  have separate C and Python modules. Python transport I/O exists only in
  `serial_transport.py`; C transport and storage enter through callbacks.
  `rqft_session_driver_t` provides safe RX-first polling and complete partial
  writes without coupling protocol state to a specific transport. Focused C
  headers expose each layer independently in both C99 and C++17.
- [x] **§2 independent verification.** Pure codec vectors, isolated link
  tests, session traces, and cross-language interop tests exercise each layer
  at its boundary. Standalone-header build targets verify every public header
  without relying on umbrella include order.

## 3. Frame layer

- [x] **§3.1 COBS framing and delimiters.** Senders emit leading/trailing
  zero delimiters; receivers tolerate shared or repeated delimiters. Complete
  and streaming COBS codecs reject malformed bodies. C transmit callbacks
  receive the complete delimited wire frame in one call. Evidence:
  `testvectors/cobs.json`, `test_cobs`, `test_session`, and
  repeated-delimiter frame tests.
- [x] **§3.2 decoded layout and CRC32.** Header fields, payload, and
  little-endian CRC-32/ISO-HDLC match zlib. Incremental and one-shot CRC APIs
  share `testvectors/crc32.json`; full wire frames share
  `testvectors/frames.json`.
- [x] **§3.3 frame types and shape validation.** HELLO, HELLO_OK, DATA, ACK,
  ACK+NAK, and ABORT shapes are typed and checked. Unknown types, reserved
  flags, zero sid, and invalid payload sizes are dropped and counted by
  `test_frame`.
- [x] **§3.4 limits.** Both APIs expose 512-byte payload and 523-byte encoded
  limits. Maximum-body vectors plus oversize parser tests cover boundaries.
- [x] **§3.5 HUNT/FRAME parser.** Parsers accept arbitrary chunks, flush
  invalid candidates, resynchronize on zero, enforce the 50 ms idle flush
  while inactive, retain partial candidates across active-session transport
  gaps, and recover after oversize input. Session-driver tests require
  buffered RX to be delivered before polling at the idle deadline. Evidence:
  `test_frame`, `test_session`, `test_client.py`, Hypothesis
  `test_frame_fuzz.py`, libFuzzer `c/tests/fuzz_frame.c`, and deterministic C
  soak `test_frame_soak`.
- [x] **§3.5 no allocation/no crash.** C fuzz runs with ASan/UBSan; exercised
  C library paths run with poisoned `malloc/calloc/realloc/free` in
  `test_no_heap`, including the safe transport driver. Python fuzz asserts
  arbitrary input never escapes as a parser exception.
- [x] **§3.6 passthrough.** Foreign bytes are delivered in order while idle
  and dropped/counted while active. Evidence: frame and session passthrough
  tests plus `test_chatter_between_frames`, `test_chatter_inside_frame`, and
  `test_binary_garbage_flood`.
- [x] **§3.7 diagnostics.** Both parser APIs expose `frames_ok`,
  `frames_crc_fail`, `frames_oversize`, `frames_dropped`,
  idle-flushed candidate/byte/valid-candidate counts, `bytes_passthrough`,
  and `bytes_dropped_in_session`; counter transitions are asserted in frame
  tests.

## 4. Link layer

- [x] **§4.1 session id.** Initiated sids are non-zero, wrong-sid non-HELLO
  frames are dropped/counted, active endpoints reject a different HELLO with
  `E_BUSY`, and same-sid HELLO is idempotent. Evidence: link/session tests and
  `test_stale_session_frames`.
- [x] **§4.2 handshake.** HELLO retry count/timing, highest common version,
  parameter minimums, declarative capabilities, role complement, doorbell,
  lower-sid collision winner, and equal-sid redraw are mirrored in
  `c/src/session.cpp` and `python/src/rqft/session.py`. Evidence:
  `test_session`, doorbell golden trace, and `test_hello_collision`.
- [x] **§4.3 Go-Back-N sender.** Window limits, cumulative ACK, modulo-256
  wrap, byte-identical flight retransmission, timeout backoff, retry death,
  progress reset, and one NAK go-back per flight are asserted in both
  `test_link` suites.
- [x] **§4.3 receiver.** Only expected DATA is delivered; duplicates and
  gaps produce ACK+NAK without redelivery. Retransmitted-frame, NAK,
  duplicate, and gap counters distinguish each recovery path. Lossy
  bidirectional loopbacks assert exactly-once in-order delivery.
- [x] **§4.4 adaptive RTO.** First sample, fixed-point convergence, min/max
  clamp, and Karn exclusion share `testvectors/rto.json` and are covered by
  `test_rto`, `test_link`, and handshake tests; the handshake round trip
  seeding no samples is asserted at session level.
- [x] **§4.5 keepalive and idle death.** Controller-only PING after 2000 ms,
  PONG echo, valid-frame idle reset, wrong-sid exclusion, and 10000 ms local
  timeout are covered for both roles by `test_session_keepalive`. The same
  suite pins the operation phases: PING while LIST or DEL awaits its reply,
  while a PUT source hashes, and while PUT_DONE is awaited; none from
  GET_REQ or PUT_REQ until the stream closes. Slow-hash runs on a simulated
  clock keep a LIST `want_crc` and a PUT alive through five times `T_DEAD`
  of hashing.
- [x] **§4.6 ABORT.** Typed reason codes, immediate peer termination,
  best-effort local timeout/user abort, host-initiated abort in both
  implementations (`rqft_session_abort()` / `Session.abort()`), clean
  Python client close, and temp cleanup on termination are covered by
  link/session/client tests, `test_session_abort`, `abort.trace`,
  `user_abort.trace`, `test_abort_mid_file_cleanup`, and
  `test_c_responder_cancels_mid_get`.

## 5. Session layer

- [x] **§5.1 roles.** Exactly one controller drives sequential operations;
  responder only answers — NOTIFY is the responder's only unsolicited
  message. Same-role handshake aborts with `E_PROTO`.
  Responder-initiated doorbell makes replier controller. Evidence:
  `test_session`, `doorbell.trace`, and clean interop in both role
  assignments.
- [x] **§5.2 HELLO bodies.** Eight-byte layouts, reserved-zero fields
  (a nonzero HELLO byte 7 is rejected as malformed), version ranges, roles,
  payload/window limits, and reserved capability bits are encoded and
  validated by both message modules against shared vectors.
- [x] **§5.3 DATA message envelope.** One typed message occupies each DATA
  payload and never spans frames. All v1 message bodies and ERR codes have
  byte-exact shared vectors and structural rejection tests.
- [x] **§5.3 error behavior.** ERR fails one operation without killing the
  session. Unknown messages between operations receive `E_UNSUPPORTED`;
  unexpected messages inside GET/PUT streams cause `ABORT(E_PROTO)`.
  Evidence: message, session misc, GET, and PUT suites.
- [x] **§5.4 sequential operations.** Controller APIs reject overlap and
  responder state machines do not interleave replies. Wrong-state messages
  produce `E_BAD_STATE` where non-fatal. Covered across all operation suites.
- [x] **§5.4 LIST.** Callback/iterator policy controls entries; optional CRC
  hashing is incremental and bounded per poll; unreadable files are skipped
  with a best-effort informational `ERR(E_FS_READ)` that controllers surface
  without failing the listing; received paths and LIST_END count are
  validated. Evidence: `test_session_list` in both languages.
- [x] **§5.4 GET.** FILE_INFO/DATA/END streams preserve size and CRC, zero-byte
  files work, receives use temp-write-then-commit, verification retries once,
  and operation errors leave later batch work possible. Non-zero offset gets
  `E_UNSUPPORTED`. Mid-file byte counters are public on both sides through
  `rqft_session_progress()` / `Session.progress()`. Evidence: both
  `test_session_get` suites.
- [x] **§5.4 GET_DONE.** The controller answers every processed FILE_END with
  exactly one `GET_DONE(status)` — including the `E_CRC_FILE` attempt that
  precedes the single retry — queued ahead of any follow-up request. The
  responder correlates it to its most recently served GET without blocking:
  status 0 raises `GetServed` / `GET_SERVED`, non-zero raises the operation
  failure event, a stray GET_DONE gets `E_BAD_STATE`, and any new request
  supersedes the served-GET record. Evidence: both `test_session_get` suites,
  `hello_list_get.trace`, and `get_served` assertions across
  `interop/test_clean_line.py` and the fault matrix batch runs.
- [x] **§5.4 PUT.** Source hashing is bounded, PUT_REQ and FILE_END CRCs must
  agree, destination count/CRC is verified before commit, and write/open
  failures discard temp state and return operation status. Hash and stream
  byte counters are public on both sides through `rqft_session_progress()` /
  `Session.progress()`. Evidence: both `test_session_put` suites.
- [x] **§5.4 DEL.** Capability advertisement and per-request callback both
  gate deletes; file and recursive-directory paths return DEL_OK or typed
  ERR. Evidence: both `test_session_del` suites.
- [x] **§5.4 PLAN, NOTIFY, and PING.** PLAN surfaces totals and NOTIFY
  surfaces sync flags without occupying the operation slot; NOTIFY is
  strict-send/lenient-receive with a forward-compatible body (extra bytes
  ignored, short body malformed); PING receives token-identical PONG.
  Evidence: `test_session_misc`, `test_session_keepalive`, and
  `doorbell_notify.trace`.
- [x] **§5.4 temp/commit and resume.** Both receiver roles discard partial
  files on error, abort, or idle death and commit only after verification.
  `SyncClient` re-LISTs and size+CRC diffs for file-granular resume. Evidence:
  GET/PUT cleanup tests, `test_abort_mid_file_cleanup`,
  `test_reconnect_resume`, and `test_client`.

## 6–8. Constants, coexistence, and conformance gates

- [x] **§6 constants.** Public constants match SPEC v1 and are asserted by
  version, frame, link, RTO, handshake, and keepalive tests in both languages.
- **§7 coexistence: N/A (informative).** Recommended dispatcher order and
  text-protocol gating appear in README C quickstart. Normative passthrough
  behavior remains covered under §3.6.
- [x] **§8 golden vectors.** Both implementations consume CRC32, COBS, frame,
  message, RTO, and byte-exact session trace vectors from `testvectors/`.
- [x] **§8 parser invariants.** Hypothesis and libFuzzer cover recovery and
  validated-frame delivery; C sanitizer and poisoned-allocator gates cover
  memory safety and no-heap behavior.
- [x] **§8 cross-implementation matrix.** `interop/test_clean_line.py` covers
  LIST/GET/PUT in both role assignments. `interop/test_fault_matrix.py`
  covers chatter, garbage, burst loss, random byte corruption, random byte
  drops, combined asymmetric noise, over-budget lines dying cleanly with
  `E_TIMEOUT` and nothing committed, collision, stale frames, one-byte
  delivery, duplicate ACKs, mid-file abort cleanup, and reconnect/resume.
  `interop/test_soak.py` adds manual ten-minute seeded randomized batches.

## Verification commands

```sh
cmake -S c -B c/build -DCMAKE_BUILD_TYPE=Debug
cmake --build c/build
ctest --test-dir c/build --output-on-failure

python -m pip install -e 'python[dev]'
mypy --strict python/src/rqft
pytest python/tests
pytest interop
```

Manual soak:

```sh
RQFT_RUN_SOAK=1 RQFT_SOAK_SECONDS=600 RQFT_SOAK_SEED=0xD18 \
    pytest interop/test_soak.py
```
## License

Copyright © 2026
[Tapio Measurement Technologies Oy](https://tapiotechnologies.com).

Licensed under GNU General Public License v3.0 only. See [`LICENSE`](LICENSE). The copyright owner may use and license its own code separately.
