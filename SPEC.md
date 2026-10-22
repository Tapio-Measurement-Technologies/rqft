# RQFT Protocol Specification

**Version 1 — normative for `librqft` (C) and `rqft` (Python) v1.x**

RQFT is a point-to-point file-transfer protocol for unreliable byte streams:
USB CDC serial, Bluetooth SPP bridges, UARTs without flow control, pipes,
sockets.

Design goals, in priority order:

1. **Robust resynchronization** on dirty shared lines — the stream may carry
   unrelated ASCII traffic (text commands, console/debug output) between and
   even inside frames.
2. **Bounded static memory** — a conforming implementation can run with a
   fixed, caller-allocated context of a few KB and zero heap allocation.
3. **Non-blocking** — all processing happens in short, bounded polls suitable
   for a bare-metal superloop.
4. **Bidirectional file operations** (download, upload, delete, list) with
   session initiation from either endpoint.
5. **Observability** — progress and status are first-class.

Non-goals: multi-peer routing, encryption, compression, interoperability with
other serial based file-transfer protocols.

---

## 1. Conventions

- Key words MUST / MUST NOT / SHOULD / MAY are per RFC 2119.
- All multi-byte integers are **little-endian**. Types written `u8`, `u16`,
  `u32`.
- **Channel model.** The byte stream is ordered but unreliable: bytes may be
  lost (including long contiguous bursts, e.g. UART RX overruns), corrupted,
  or duplicated, and **foreign bytes** (typically ASCII text lines) may be
  interleaved with protocol traffic. The channel does **not** reorder bytes.
- **Path** encoding: `u8 len` (0–128) followed by `len` bytes of UTF-8.
  Segments separated by `/`. MUST be relative: no leading `/`, no empty
  segments, no `.` or `..` segments, no NUL bytes, no `\`. A zero-length path
  is legal only where explicitly stated (LIST_REQ root = whole tree).
  Paths carry the full relative folder location — transfers **preserve
  directory structure** (the expected workload is many folders of a few
  files each).
  A responder MUST validate every received path and answer `ERR(E_PATH)` on
  violation. Receivers of LIST_ENTRY MUST apply the same validation before
  using the path locally.
- All timers are in milliseconds and use a monotonic clock.

## 2. Layering

```
host application        sync policy, UI, progress display
  └─ session layer      messages (LIST/GET/PUT/DEL/...), roles, handshake   §5
      └─ link layer     reliability: Go-Back-N, ACK/NAK, RTO, session id    §4
          └─ frame layer  COBS framing, CRC32, resync, passthrough          §3
              └─ byte transport  UART / USB CDC / BT SPP / pipe / socket
```

Each layer is independently testable; the golden test vectors in
`testvectors/` pin the byte-exact behavior of the frame and session layers.

## 3. Frame layer

### 3.1 Wire format

```
encoded_frame := 0x00  COBS(decoded_frame)  0x00
```

- Frames are COBS-encoded ([Consistent Overhead Byte
  Stuffing](https://ieeexplore.ieee.org/document/769765)) so the encoded body
  contains **no 0x00 byte**; `0x00` is therefore an unambiguous frame
  delimiter and resync point.
- A sender MUST emit a leading `0x00` before every frame and a trailing
  `0x00` after it. Receivers MUST accept any number of consecutive `0x00`
  bytes between frames (a trailing delimiter may serve as the next frame's
  leading delimiter).

### 3.2 Decoded frame layout

| Offset | Size    | Field     | Description |
|-------:|--------:|-----------|-------------|
| 0      | 1       | `ftype`   | Frame type, §3.3 |
| 1      | 1       | `sid`     | Session id, §4.1. Never 0x00 except as noted. |
| 2      | 1       | `seq`     | Sequence number, meaning depends on `ftype` |
| 3      | 1       | `flags`   | Bit flags, meaning depends on `ftype`; unused bits MUST be 0 |
| 4      | 0–512   | `payload` | Frame-type-specific payload |
| len−4  | 4       | `crc32`   | CRC over decoded bytes `[0, len−4)`, stored LE |

CRC32 is **CRC-32/ISO-HDLC** (polynomial `0xEDB88320` reflected, init
`0xFFFFFFFF`, xor-out `0xFFFFFFFF`) — identical to zlib `crc32()`.

### 3.3 Frame types

| `ftype` | Name      | `seq`                       | `flags`        | `payload` |
|--------:|-----------|-----------------------------|----------------|-----------|
| 0x01    | HELLO     | 0                           | 0              | HELLO body, §5.2 |
| 0x02    | HELLO_OK  | 0                           | 0              | HELLO_OK body, §5.2 |
| 0x03    | DATA      | stream sequence number      | 0              | exactly one message, §5.3 |
| 0x04    | ACK       | next expected inbound `seq` | bit0 = NAK     | empty |
| 0x05    | ABORT     | 0                           | 0              | `u8 reason`, §4.6 |

A frame with an unknown `ftype`, a non-zero value in reserved `flags` bits,
or a payload size outside its type's bounds MUST be dropped silently
(diagnostics counter only).

### 3.4 Size limits

| Constant                | Value | Meaning |
|-------------------------|------:|---------|
| `RQFT_MAX_PAYLOAD`      | 512   | protocol-absolute max frame payload |
| max decoded frame       | 520   | 4 header + 512 payload + 4 CRC |
| `RQFT_MAX_ENCODED`      | 523   | 520 + ⌈520/254⌉ COBS overhead |

Sessions negotiate a possibly smaller `max_payload` (§5.2); after
negotiation, frames larger than `4 + max_payload + 4` decoded MUST be treated
as invalid.

### 3.5 Parser state machine (normative)

Two states: **HUNT** and **FRAME**.

- **HUNT** (initial):
  - byte ≠ 0x00 → emit to *passthrough* (§3.6).
  - byte = 0x00 → enter FRAME with empty candidate buffer.
- **FRAME**:
  - byte = 0x00, candidate empty → stay (tolerate repeated delimiters).
  - byte = 0x00, candidate non-empty → attempt COBS decode + CRC check:
    - valid → deliver frame to link layer; clear candidate; stay in FRAME.
    - invalid → flush candidate to passthrough; clear; stay in FRAME
      (the just-consumed 0x00 acts as the next leading delimiter).
  - byte ≠ 0x00 → append to candidate; if candidate length exceeds
    `RQFT_MAX_ENCODED` → flush candidate to passthrough; enter HUNT.
- **Idle flush, session inactive only**: if the candidate is non-empty and no
  byte has arrived for `T_FLUSH` (50 ms) → flush candidate to passthrough;
  enter HUNT. This bounds the delivery latency of foreign text that happens to
  follow a 0x00. While a session is active, never idle-flush a candidate;
  retain it across arbitrary transport gaps until a delimiter or the encoded
  size bound resynchronizes the parser.

Transport integrations MUST feed all currently available RX bytes into the
parser before applying idle flush or other timer polls. Thus, a trailing
delimiter already buffered at `T_FLUSH` completes its frame before the idle
deadline is evaluated.

The parser MUST never allocate, MUST never raise/crash on arbitrary input,
and MUST always return to a state where a subsequent valid frame is
recognized (fuzz-tested invariants).

### 3.6 Passthrough

Foreign bytes — HUNT-state bytes and flushed candidates (content bytes only;
delimiters are dropped) — are:

- **session inactive**: delivered to the host in order via a passthrough
  callback/event, so a host text protocol on the same stream keeps working;
- **session active** (§4.2): dropped (counted). Hosts SHOULD also pause
  their own text-command transmission while `session_active()`.

Hosts sharing the stream with a text protocol MUST ensure the text side
never emits 0x00 bytes.

### 3.7 Diagnostics

Implementations MUST expose counters: `frames_ok`, `frames_crc_fail`,
`frames_oversize`, `frames_dropped` (bad type/sid), idle-flushed candidates
and bytes (including how many candidates passed COBS and CRC),
`bytes_passthrough`, and `bytes_dropped_in_session`. Frame CRC failures are
**not** errors — they are expected on dirty lines and handled by resync +
retransmission.

## 4. Link layer

### 4.1 Session id (`sid`)

A session is identified by a `sid` chosen by the initiator: uniformly random,
MUST be non-zero, SHOULD be unpredictable across reboots. All frames of a
session carry its `sid`. An endpoint with an active session MUST drop
(count) any non-HELLO frame whose `sid` differs from the active one — this
kills stale frames from previous sessions still buffered in the pipe.

An endpoint supports at most one active session. A HELLO received during an
active session with a **different** sid MUST be answered with
`ABORT(E_BUSY)` carrying the *offered* sid; the active session is unaffected.
A HELLO re-received with the **active** sid is a retransmission → re-answer
HELLO_OK (idempotent).

### 4.2 Handshake

**Initiator**: choose `sid`; send HELLO; retransmit every `T_HELLO` (500 ms)
up to `N_HELLO` (5) total attempts; session becomes active on receiving
HELLO_OK with matching sid. No HELLO_OK after all attempts → give up, report
`E_TIMEOUT` locally.

**Replier**: on receiving a valid HELLO with an acceptable version range:
adopt the sid, answer HELLO_OK, session becomes active immediately. On
version mismatch: answer `ABORT(E_VERSION)`.

**Version and parameter negotiation** (fields in §5.2):

- version = highest version in both sides' `[ver_min, ver_max]` ranges;
  none → `ABORT(E_VERSION)`.
- effective `max_payload` = min(HELLO.max_payload, HELLO_OK.max_payload).
- effective `window` = min(HELLO.window, HELLO_OK.window).
- `caps` are declarative, not negotiated: each side learns the peer's
  capabilities.

**Collision** (both endpoints send HELLO before seeing the other's): the
endpoint with the numerically **lower sid wins as initiator**. The
higher-sid endpoint MUST abandon its own HELLO and answer the peer's HELLO
with HELLO_OK. Equal sids: both abandon, re-randomize, and retry after
`T_HELLO`.

Session activity begins: initiator — at HELLO_OK receipt; replier — at HELLO
receipt. If the initiator goes silent after the replier activates, the idle
timeout (§4.5) clears the session.

### 4.3 DATA reliability — Go-Back-N

Each direction carries an independent sequenced stream of DATA frames.
`seq` starts at 0 for the first DATA frame of the session in that direction
and increments mod 256. ACK frames always refer to the stream flowing
**toward** their sender.

**Sender**: may have up to `window` (`W`, negotiated 1–8) unacknowledged DATA
frames in flight and MUST buffer them for retransmission.

**Receiver**: accepts a DATA frame only if `seq` equals the next expected
value → deliver payload to the session layer, increment expectation, send
`ACK(next_expected)`. Any other `seq` (duplicate or gap) → discard the frame
and send `ACK(next_expected)` with the **NAK flag** set.

**ACKs are cumulative**: `ACK(k)` acknowledges every in-flight frame with
`seq` in the modular interval `[oldest_unacked, k)`. ACK frames are not
sequenced, not acknowledged, and never retransmitted on their own.

**Sender on ACK**: slide the window. **On NAK**: retransmit all unacked
frames starting from `k` ("go-back"), rate-limited to at most one
NAK-triggered go-back per window flight (further NAKs with the same `k` are
ignored until the retransmission makes progress or RTO fires).

**Retransmission timer**: one timer for the oldest unacked frame. On expiry:
retransmit all unacked frames, double the RTO (exponential backoff, still
clamped to `RTO_MAX`), increment the retry counter. The counter resets on
any progress (new cumulative ACK). After `N_RETRY` (8) consecutive expiries:
send `ABORT(E_TIMEOUT)` best-effort and terminate the session locally.

Link diagnostics expose retransmitted DATA frames, ACK+NAKs sent, and DATA
frames rejected as duplicates or forward gaps. These are local endpoint
counters; they do not directly report retransmissions performed by the peer.

### 4.4 Adaptive RTO (simplified RFC 6298)

- RTT samples: time from a DATA frame's **first** transmission to the ACK
  covering it. Frames that were retransmitted give no sample (Karn's rule).
  The HELLO→HELLO_OK round trip MUST NOT seed the estimator: it is measured
  on an unloaded link, so it undershoots the RTT of a full in-flight window
  and primes spurious full-window retransmissions that Karn's rule then
  sustains.
- First sample: `srtt = rtt`, `rttvar = rtt / 2`.
- Then: `rttvar = (3·rttvar + |srtt − rtt|) / 4`, `srtt = (7·srtt + rtt) / 8`
  (integer ms arithmetic).
- `RTO = clamp(srtt + 4·rttvar, RTO_MIN=100, RTO_MAX=3000)`.
- Before any sample: `RTO = 1000`.

Rationale: RTT spans ~2 ms (USB CDC) to >200 ms (BT SPP with spikes); a fixed
timer is either sluggish or spuriously retransmits.

### 4.5 Keepalive and idle death

- If a session is active and the **controller** has sent nothing for
  `T_PING` (2000 ms), it sends a PING message (§5.3) on the reliable stream.
- The keepalive runs whether or not an operation is in flight, except
  while a file stream is open or may be opening, because a PING that
  reaches the peer inside a file stream is fatal (§5.3). The controller
  MUST NOT send PING from a GET_REQ until it has processed the FILE_END
  or ERR that ends that GET, nor from a PUT_REQ until it has sent the
  PUT's FILE_END or the PUT has ended without one. It MUST send it at
  every other point: between operations, while a LIST or DEL awaits its
  reply, while a PUT source is still being hashed before PUT_REQ, and
  after FILE_END while PUT_DONE is awaited. Hashing a large file for LIST
  `want_crc` or for PUT can take longer than `T_DEAD` with nothing else
  on the wire; the PING and its ACK and PONG keep both sides' idle
  timers fed through it.
- Any endpoint MUST terminate the session locally (best-effort
  `ABORT(E_TIMEOUT)`) after `T_DEAD` (10 000 ms) without receiving any valid
  in-session frame.

### 4.6 Session termination — ABORT

`ABORT` payload is one reason byte:

| Reason | Name        | Meaning |
|-------:|-------------|---------|
| 0x00   | CLOSE       | clean close (not an error) |
| 0x01   | E_VERSION   | no common protocol version |
| 0x02   | E_TIMEOUT   | retry/idle exhaustion |
| 0x03   | E_PROTO     | protocol violation |
| 0x04   | E_BUSY      | endpoint already in a session |
| 0x05   | E_INTERNAL  | implementation failure |
| 0x06   | E_USER      | user cancelled |

ABORT is unsequenced and best-effort. A clean CLOSE SHOULD be sent only
after the sender's outbound stream is fully acknowledged, and MAY be
repeated up to 3 times. On receiving any ABORT with the active sid, the
session ends immediately; no reply is sent. `T_DEAD` is the backstop for a
lost CLOSE.

## 5. Session layer

### 5.1 Roles

Every session has exactly one **controller** and one **responder**. The
controller drives all operations; the responder only answers and never
pushes unrequested data, with one exception: the informative NOTIFY
message (§5.3), which the responder MAY send unsolicited to prompt the
controller to start pulling files. *Initiation is decoupled from control*: a
responder-capable-only endpoint (e.g. an embedded device) initiates a
session as a **doorbell** — it sends HELLO declaring itself responder, and
the answering peer becomes controller. The steady state is identical
regardless of who initiated.

If both sides declare the same role, the replier MUST answer
`ABORT(E_PROTO)`.

### 5.2 HELLO / HELLO_OK bodies

HELLO (8 bytes):

| Field         | Type | Meaning |
|---------------|------|---------|
| `ver_min`     | u8   | lowest protocol version supported |
| `ver_max`     | u8   | highest protocol version supported |
| `role`        | u8   | sender's role: 0x00 controller, 0x01 responder |
| `max_payload` | u16  | largest frame payload sender accepts (≤512) |
| `window`      | u8   | largest send window sender can buffer (1–8) |
| `caps`        | u8   | capability bits, below |
| `reserved`    | u8   | MUST be 0 |

HELLO_OK (8 bytes):

| Field         | Type | Meaning |
|---------------|------|---------|
| `ver`         | u8   | chosen protocol version |
| `role`        | u8   | replier's role (complement of HELLO.role) |
| `max_payload` | u16  | replier's limit; effective = min of the two |
| `window`      | u8   | replier's limit; effective = min of the two |
| `caps`        | u8   | replier's capability bits |
| `reserved`    | u16  | MUST be 0 |

`caps` bits: **bit0 `ALLOW_DELETE`** — endpoint permits DEL_FILE/DEL_DIR
against its filesystem. Bits 1–7 reserved, MUST be 0.

This document specifies **version 1**.

### 5.3 Messages

A message is `u8 msg_type` + body, carried as the entire payload of one DATA
frame — **exactly one message per DATA frame; messages never span frames**.
Body length ≤ negotiated `max_payload` − 1. `C` = controller, `R` =
responder.

| Type | Name       | Dir  | Body |
|-----:|------------|------|------|
| 0x10 | LIST_REQ   | C→R  | `u8 flags` (bit0 = want_crc), `path root` (len 0 = whole tree) |
| 0x11 | LIST_ENTRY | R→C  | `u8 etype` (0 = file), `u8 eflags` (bit0 = crc_valid), `u32 size`, `u32 crc32`, `u32 mtime` (Unix s), `path` |
| 0x12 | LIST_END   | R→C  | `u16 count` (number of LIST_ENTRY sent) |
| 0x20 | GET_REQ    | C→R  | `u32 offset` (MUST be 0 in v1; reserved for resume), `path` |
| 0x21 | FILE_INFO  | R→C  | `u32 size` |
| 0x22 | FILE_DATA  | both | raw file bytes (chunk size = `max_payload` − 1) |
| 0x23 | FILE_END   | both | `u32 crc32` of the whole file |
| 0x24 | GET_DONE   | C→R  | `u8 status` (0 = committed, else ERR code) |
| 0x28 | PUT_REQ    | C→R  | `u32 size`, `u32 crc32`, `path` |
| 0x29 | PUT_OK     | R→C  | empty |
| 0x2A | PUT_DONE   | R→C  | `u8 status` (0 = committed, else ERR code) |
| 0x30 | DEL_FILE   | C→R  | `path` |
| 0x31 | DEL_DIR    | C→R  | `path` (recursive) |
| 0x32 | DEL_OK     | R→C  | empty |
| 0x40 | PLAN       | C→R  | `u16 nfiles`, `u32 nbytes` (informative; no reply) |
| 0x41 | NOTIFY     | R→C  | `u32 flags` (bit0 = sync_mode: 0 full / 1 incremental, bit1 = delete_after_sync; informative; no reply) |
| 0x50 | PING       | both | `u32 token` |
| 0x51 | PONG       | both | `u32 token` (echoed) |
| 0x7F | ERR        | both | `u8 code`, `u8 ref_msgtype`, `u16 detail` |

ERR codes:

| Code | Name          | Meaning |
|-----:|---------------|---------|
| 0x01 | E_FS_OPEN     | open failed |
| 0x02 | E_FS_READ     | read failed |
| 0x03 | E_FS_WRITE    | write failed |
| 0x04 | E_FS_REMOVE   | remove failed |
| 0x05 | E_PATH        | path validation failed (§1) |
| 0x06 | E_CRC_FILE    | file CRC mismatch after transfer |
| 0x07 | E_TOO_LARGE   | size/limit exceeded |
| 0x08 | E_DENIED      | operation not permitted (e.g. delete without ALLOW_DELETE) |
| 0x09 | E_BAD_STATE   | message not valid in current operation state |
| 0x0A | E_UNSUPPORTED | unknown msg_type / reserved feature (e.g. GET offset ≠ 0) |

ERR is **non-fatal**: it fails the referenced operation; the session
continues (the controller typically proceeds with the next file). Fatal
conditions use ABORT (§4.6).

Unknown `msg_type` received **between operations** → answer
`ERR(E_UNSUPPORTED, ref=that type)` and continue (forward compatibility).
Any unexpected message **during a file stream** (between FILE_INFO/PUT_OK
and FILE_END) → `ABORT(E_PROTO)`.

### 5.4 Operations

Operations are **strictly sequential**: the controller has at most one
operation in flight; the responder MUST NOT interleave responses of
different operations. (The link layer's ordered stream makes each operation
a simple sub-state machine.)

**LIST**: `LIST_REQ` → zero or more `LIST_ENTRY` → `LIST_END(count)`.
Which entries appear (filtering, recursion) is host policy via the listing
callback — not the library's business. If `want_crc` was set, the responder
SHOULD compute per-file CRC32 incrementally (bounded work per poll) and set
`eflags.crc_valid`; it MAY skip (crc_valid = 0). A responder MUST keep
receiving frames between hashing steps and answer PING with PONG while it
serves a LIST, so the controller's keepalive (§4.5) holds the session open
however long hashing takes. Files it cannot read are
skipped and SHOULD each be reported with an informational
`ERR(E_FS_READ, ref = LIST_REQ)` interleaved with the entries (best-effort:
the report MAY be dropped under transmit backpressure, and `LIST_END.count`
never includes skipped files). A controller MUST treat `ERR(E_FS_READ)`
received during a LIST as informational — it surfaces the skip to the host
and the listing continues; any other ERR code fails the operation as usual.

**GET**: `GET_REQ` → `FILE_INFO(size)` → ⌈size/chunk⌉ × `FILE_DATA` →
`FILE_END(crc32)`, or `ERR` instead of FILE_INFO. A zero-byte file is
`FILE_INFO(0)` → `FILE_END`. The controller verifies received byte count ==
size and streamed CRC == FILE_END.crc32; mismatch → discard temp file,
retry the file **once**, then record a per-file error and continue the
batch.

The controller sends exactly one `GET_DONE(status)` for every FILE_END it
processes — `GET_DONE(0)` on committed verify, else the ERR code
(`E_CRC_FILE` on a verify mismatch, including the attempt that triggers the
retry, in which case GET_DONE precedes the retry's GET_REQ; `E_FS_WRITE` on
a failed local write/commit). No GET_DONE is sent for a GET that never
reached FILE_END. Because the link stream is ordered and the controller is
strictly sequential (§5.4 opening), GET_DONE always arrives after the
responder's FILE_END and before any subsequent request; the responder
correlates it to its most recently served GET. GET_DONE is informational
for the responder: it MUST NOT block on or await it, and confirms only the
mirror image of PUT_DONE — whether the peer committed the file.

**PUT**: `PUT_REQ(size, crc32, path)` → `PUT_OK` (or `ERR`) → controller
streams `FILE_DATA` → `FILE_END(crc32)`; FILE_END.crc32 MUST equal
PUT_REQ.crc32 (mismatch = `ABORT(E_PROTO)` — same sender produced both).
Responder verifies count + CRC, then `PUT_DONE(0)` on committed rename, or
`PUT_DONE(err)` after discarding the temp file.

**DEL**: `DEL_FILE`/`DEL_DIR` → `DEL_OK` or `ERR(E_DENIED | E_FS_REMOVE |
E_PATH)`. Responders MUST double-gate deletes: advertise `ALLOW_DELETE` caps
*and* re-check the host callback per request. DEL_DIR is recursive.

**PLAN**: sent by the controller after diffing LIST against local state, so
the responder's UI can show accurate batch totals. No reply.

**NOTIFY**: sent by the responder at any between-message point (never
inside a FILE_DATA stream) to tell the controller it should pull files —
typically right after a doorbell establish, or mid-session when new files
appear. `flags` bits: **bit0 `SYNC_MODE`** — the kind of sync requested:
0 = **full sync** (complete mirror), 1 = **incremental sync** (pull only
files that are new since the controller's last sync);
**bit1 `DELETE_AFTER_SYNC`** — delete each file from the responder once
it has been fetched and verified; only actionable when the responder also
declares `ALLOW_DELETE`, since deletion happens through the ordinary
caps-gated DEL_FILE operation. Informative for the controller's sync
policy; no reply; occupies no operation slot. Senders MUST set undefined
flag bits to 0; receivers MUST mask off undefined bits and MUST NOT
reject them. Receivers MUST accept a body longer than 4 bytes and ignore
the extra bytes (future fields append there); a body shorter than 4 bytes
is malformed. A controller MUST accept NOTIFY wherever PING/PONG is
legal, including while awaiting an operation reply; a responder receiving
NOTIFY between operations answers `ERR(E_BAD_STATE, ref = 0x41)`; inside
a file stream the §5.3 stream rule applies (`ABORT(E_PROTO)`).

**PING** → `PONG` with the token echoed.

**Temp-and-commit rule** (any file receiver, both sides): write to a
temporary name (implementation-defined, e.g. `<path>.part`), commit
(rename) only after size and CRC verify. On abort/error/session death the
temp file MUST be discarded. The receiver MUST create any missing parent
directories of the destination path before committing, so the sender-side
folder structure is reproduced exactly.

**Resume** is file-granular by design: after a reconnect the controller
re-LISTs and diffs (size + CRC) against local storage, skipping files
already verified. `GET_REQ.offset` is reserved so offset resume can be
added in a future version without a wire break; in v1 a responder MUST
answer `ERR(E_UNSUPPORTED)` to a non-zero offset.

## 6. Constants

| Constant           | Value  | Section |
|--------------------|-------:|---------|
| protocol version   | 1      | §5.2 |
| `RQFT_MAX_PAYLOAD` | 512 B  | §3.4 |
| `RQFT_MAX_ENCODED` | 523 B  | §3.4 |
| `RQFT_MAX_PATH`    | 128 B  | §1 |
| `T_FLUSH`          | 50 ms  | §3.5 |
| `T_HELLO`          | 500 ms | §4.2 |
| `N_HELLO`          | 5      | §4.2 |
| `RTO_MIN`          | 100 ms | §4.4 |
| `RTO_MAX`          | 3000 ms| §4.4 |
| initial RTO        | 1000 ms| §4.4 |
| `N_RETRY`          | 8      | §4.3 |
| `T_PING`           | 2000 ms| §4.5 |
| `T_DEAD`           | 10 000 ms | §4.5 |
| window `W`         | 1–8, default 4 | §4.3 |
| chunk size         | `max_payload` − 1 | §5.3 |

Throughput sanity check (115 200 baud ≈ 11.5 KB/s): a 520 B frame ≈ 45 ms on
the wire; `W = 4` keeps ~180 ms in flight, saturating the link for RTT up to
~150 ms. The ACK window doubles as flow control on links that have none.

## 7. Coexistence with a host text protocol (informative)

A host that shares the stream with a newline-based text protocol (e.g.
`STATUS?`) should:

1. Feed **all** received bytes through the RQFT dispatcher first.
2. Feed passthrough bytes (§3.6) to its text-command parser.
3. Gate text-command parsing and transmission on `!session_active()`.
4. Never emit 0x00 from the text side.

Foreign text between frames costs nothing; foreign text spliced into a
frame corrupts only that frame — CRC rejects it, the parser resyncs at the
next 0x00, and the link layer retransmits.

## 8. Conformance

A conforming implementation passes:

1. the golden vectors in `testvectors/` (CRC32, COBS, frames, session
   traces), byte-exact;
2. the parser fuzz invariants (§3.5): no crash, no allocation, no invalid
   frame delivered, always recovers;
3. the cross-implementation fault-injection matrix in `interop/`.

A full clause-by-clause checklist is maintained in `CONFORMANCE.md`.

## License

Copyright © 2026
[Tapio Measurement Technologies Oy](https://tapiotechnologies.com).

Licensed under GNU General Public License v3.0 only. See [`LICENSE`](LICENSE). The copyright owner may use and license its own code separately.
