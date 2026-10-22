# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Sans-io session layer for SPEC.md sections 4.2 and 5.

A :class:`Session` owns one frame parser and, once the handshake
completes, one Go-Back-N link. Bytes from the transport go into
:meth:`Session.receive_bytes`; bytes for the transport come out of
:meth:`Session.data_to_send`; time is injected through explicit
``now_ms`` arguments, :meth:`Session.next_timeout`, and
:meth:`Session.handle_timeout`. The class performs no I/O and keeps no
clock.
"""

from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Final, Iterator, Optional, Protocol, Union

from rqft import MAX_PAYLOAD, PROTOCOL_VERSION, WINDOW_MAX
from rqft.crc32 import crc32_update
from rqft.events import (
    DelDone,
    Ended,
    EntryListed,
    EntrySkipped,
    Established,
    GetServed,
    ListDone,
    NotifyReceived,
    OpFailed,
    PlanReceived,
    SessionEvent,
)
from rqft.events import GetDone as GetDoneEvent
from rqft.events import PutDone as PutDoneEvent
from rqft.frame import (
    Frame,
    FrameType,
    Parser,
    ParserState,
    Passthrough,
    T_FLUSH_MS,
    build_frame,
)
from rqft.fs import FsEntry, FsProvider
from rqft.link import AbortReason, Aborted, Delivered, Link, LinkEvent, abort_reason_from_byte
from rqft.messages import (
    CAP_ALLOW_DELETE,
    _NOTIFY_DEFINED_MASK,
    DelDir,
    DelFile,
    DelOk,
    Err,
    ErrCode,
    FileData,
    FileEnd,
    FileInfo,
    GetDone,
    GetReq,
    Hello,
    HelloOk,
    ListEnd,
    ListEntry,
    ListReq,
    Message,
    MessageError,
    MsgType,
    Notify,
    Ping,
    Plan,
    Pong,
    PutDone,
    PutOk,
    PutReq,
    Role,
    Unknown,
    decode_message,
    msg_type_of,
    path_valid,
)

# Interval between HELLO attempts, from SPEC.md section 4.2.
T_HELLO_MS: Final = 500

# Total HELLO attempts before the initiator gives up, from SPEC.md
# section 4.2.
N_HELLO: Final = 5

# Controller keepalive interval, from SPEC.md section 4.5: after this
# much outbound silence the controller sends a PING.
T_PING_MS: Final = 2000

# Idle-death backstop, from SPEC.md section 4.5: an active session ends
# after this long without receiving any valid in-session frame.
T_DEAD_MS: Final = 10000

# Largest number of file bytes read per poll while serving LIST with
# want_crc or streaming a GET (SPEC.md section 5.4 bounded work).
CRC_BUDGET_PER_POLL: Final = 4096

# Largest single read handed to the filesystem provider while hashing.
_HASH_READ_MAX: Final = 512

# Upper bound on pump loop turns per poll, so a pathological listing
# cannot stall one poll indefinitely.
_PUMP_MAX_STEPS: Final = 32

# Control-queue depth; overflow means a broken peer and aborts the
# session with E_INTERNAL.
_CTRL_QUEUE_MAX: Final = 16

# Wire overhead of a LIST_ENTRY message before path bytes: msg_type,
# etype, eflags, size, crc32, mtime, and the path length prefix.
_LIST_ENTRY_OVERHEAD: Final = 16

# Wire overhead of a GET_REQ message before path bytes: msg_type,
# offset, and the path length prefix.
_GET_REQ_OVERHEAD: Final = 6

# Wire overhead of a PUT_REQ message before path bytes: msg_type, size,
# crc32, and the path length prefix.
_PUT_REQ_OVERHEAD: Final = 10

# Wire overhead of a DEL_FILE/DEL_DIR message before path bytes:
# msg_type and the path length prefix.
_DEL_OVERHEAD: Final = 2


class SessionError(ValueError):
    """Raised on session API misuse: bad configuration, starting twice, or
    driving an operation in the wrong state or role."""


class SessionState(Enum):
    """Life-cycle states of a session endpoint."""

    IDLE = "IDLE"
    HELLO_SENT = "HELLO_SENT"
    ACTIVE = "ACTIVE"
    ENDED = "ENDED"


class TransferPhase(Enum):
    """Phase of the in-flight file transfer reported by
    :meth:`Session.progress`."""

    # A controller PUT is hashing its source file before PUT_REQ.
    HASH = "HASH"
    # File bytes are moving (or about to move) on the wire.
    STREAM = "STREAM"


@dataclass(frozen=True)
class TransferProgress:
    """Point-in-time byte counters of the in-flight file transfer.

    Attributes:
        request: msg_type of the request driving the transfer:
            MsgType.GET_REQ or MsgType.PUT_REQ.
        phase: Current transfer phase.
        done: Bytes hashed (HASH) or streamed (STREAM) so far.
        total: Total bytes when known, else None. A controller GET
            learns it from FILE_INFO; a controller PUT hashing reports
            the source size from the filesystem provider.
    """

    request: MsgType
    phase: TransferPhase
    done: int
    total: Optional[int]


@dataclass(frozen=True)
class SessionDiagnostics:
    """Point-in-time frame and active-link diagnostic counters.

    Attributes:
        frames_ok: Valid frames accepted by the parser.
        frames_crc_fail: Candidates rejected by decode, length, or CRC.
        frames_oversize: Candidates exceeding the encoded-frame limit.
        frames_dropped: CRC-valid frames rejected for invalid shape.
        candidates_idle_flushed: Unterminated candidates discarded after T_FLUSH.
        valid_candidates_idle_flushed: Idle-flushed candidates passing COBS,
            minimum-length, and CRC checks despite missing a delimiter.
        bytes_idle_flushed: Encoded candidate bytes discarded after T_FLUSH.
        frames_wrong_sid: In-session frames rejected for another session id.
        frames_retransmitted: DATA frames resent after RTO expiry or NAK.
        naks_sent: ACK+NAK frames sent for unexpected DATA sequence numbers.
        duplicate_data_received: DATA frames received behind expected sequence.
        out_of_order_data_received: DATA frames received ahead of expected sequence.
        bytes_passthrough: Foreign bytes delivered while no session was active.
        bytes_dropped_in_session: Foreign bytes dropped during a live session.
        srtt_ms: Smoothed RTT, or None before a link sample exists.
        rttvar_ms: RTT variance, or None before a link sample exists.
        rto_ms: Current link retransmission timeout, or None without a link.
        in_flight: Unacknowledged outbound DATA frames, or None without a link.
    """

    frames_ok: int
    frames_crc_fail: int
    frames_oversize: int
    frames_dropped: int
    candidates_idle_flushed: int
    valid_candidates_idle_flushed: int
    bytes_idle_flushed: int
    frames_wrong_sid: int
    frames_retransmitted: int
    naks_sent: int
    duplicate_data_received: int
    out_of_order_data_received: int
    bytes_passthrough: int
    bytes_dropped_in_session: int
    srtt_ms: Optional[int]
    rttvar_ms: Optional[int]
    rto_ms: Optional[int]
    in_flight: Optional[int]


def _default_sid_source() -> int:
    """Draw an unpredictable non-zero session id."""

    return random.SystemRandom().randrange(1, 256)


@dataclass
class _CtrlList:
    """Controller-side LIST progress: entries received so far."""

    received: int = 0


@dataclass
class _RespList:
    """Responder-side LIST cursor and incremental-hash state."""

    entries: Iterator[FsEntry]
    want_crc: bool
    count: int = 0
    current: Optional[FsEntry] = None
    path_bytes: bytes = b""
    reading: bool = False
    hashed: int = 0
    crc: int = 0


@dataclass
class _CtrlGet:
    """Controller-side GET progress and temp-file staging state."""

    path: str
    path_bytes: bytes
    retried: bool = False
    streaming: bool = False
    size: int = 0
    received: int = 0
    crc: int = 0
    writing: bool = False
    failed: Optional[ErrCode] = None


@dataclass
class _RespGet:
    """Responder-side GET stream cursor and staged chunk."""

    path: str
    size: int
    sent: int = 0
    crc: int = 0
    chunk: bytes = b""


@dataclass(frozen=True)
class _ServedGet:
    """Most recently served responder GET, awaiting the GET_DONE verdict."""

    path: str
    size: int
    crc32: int


class _PutPhase(Enum):
    """Controller-side PUT progress through SPEC.md section 5.4."""

    HASH = "HASH"
    AWAIT_OK = "AWAIT_OK"
    STREAM = "STREAM"
    AWAIT_DONE = "AWAIT_DONE"


@dataclass
class _CtrlPut:
    """Controller-side PUT hash state and upload stream cursor."""

    path: str
    path_bytes: bytes
    phase: _PutPhase = _PutPhase.HASH
    reading: bool = False
    failed: Optional[ErrCode] = None
    size: int = 0
    size_hint: Optional[int] = None
    crc: int = 0
    hashed: int = 0
    sent: int = 0
    chunk: bytes = b""


@dataclass
class _RespPut:
    """Responder-side PUT verification and temp-file staging state."""

    size: int
    crc32: int
    received: int = 0
    crc: int = 0
    writing: bool = True
    failed: Optional[ErrCode] = None


@dataclass
class _CtrlDel:
    """Controller-side DEL progress: awaiting DEL_OK or ERR."""

    path: str
    path_bytes: bytes
    is_dir: bool


# Union of in-flight operation states; None when no operation runs.
_Op = Union[_CtrlList, _RespList, _CtrlGet, _RespGet, _CtrlPut, _RespPut, _CtrlDel]


class _Encodable(Protocol):
    """Any session message that can produce its wire payload."""

    def encode(self) -> bytes:
        """Encode msg_type and body into one DATA frame payload."""
        ...


class Session:
    """One endpoint of an RQFT session (SPEC.md section 5).

    Attributes:
        role: This endpoint's role, fixed at construction.
        state: Current life-cycle state.
    """

    def __init__(
        self,
        role: Role,
        *,
        sid_source: Optional[Callable[[], int]] = None,
        fs: Optional[FsProvider] = None,
        ver_min: int = 1,
        ver_max: int = PROTOCOL_VERSION,
        max_payload: int = MAX_PAYLOAD,
        window: int = 4,
        caps: int = 0,
    ) -> None:
        """Initialize an idle session endpoint.

        Args:
            role: Session role this endpoint plays once active.
            sid_source: Callable drawing a non-zero initiator session id;
                defaults to an unpredictable system source. Called again
                after an equal-sid HELLO collision.
            fs: Filesystem provider serving operations; a responder
                without one answers requests with ERR(E_UNSUPPORTED).
            ver_min: Lowest protocol version supported.
            ver_max: Highest protocol version supported.
            max_payload: Largest frame payload accepted, 1 to MAX_PAYLOAD.
            window: Largest send window buffered, 1 to WINDOW_MAX.
            caps: Declared capability bits.

        Raises:
            SessionError: If a limit or the version range is out of range.
        """

        if not 0 <= ver_min <= ver_max <= 255:
            raise SessionError("version range must satisfy 0 <= ver_min <= ver_max <= 255")
        if not 1 <= max_payload <= MAX_PAYLOAD:
            raise SessionError("max_payload must be in [1, MAX_PAYLOAD]")
        if not 1 <= window <= WINDOW_MAX:
            raise SessionError("window must be in [1, WINDOW_MAX]")

        self.role: Final = role
        self.state = SessionState.IDLE
        self._ver_min = ver_min
        self._ver_max = ver_max
        self._max_payload = max_payload
        self._window = window
        self._caps = caps
        self._fs = fs
        self._sid_source = sid_source if sid_source is not None else _default_sid_source
        self._parser = Parser(max_payload=max_payload)
        self._out = bytearray()
        self._link: Optional[Link] = None
        self._sid = 0
        self._hello_attempts = 0
        self._last_hello_tx_ms = 0
        self._hello_ok_wire = b""
        self._end_reason: Optional[AbortReason] = None
        self._eff_max_payload = max_payload
        self._peer_caps = 0
        self._ctrl: Deque[bytes] = deque()
        self._ctrl_overflow = False
        self._op: Optional[_Op] = None
        self._served_get: Optional[_ServedGet] = None
        self._now_ms = 0
        self._last_tx_ms = 0
        self._last_rx_ms = 0
        self._ping_token = 0

    @property
    def session_active(self) -> bool:
        """True while the handshake has completed and the session lives.

        Hosts sharing the stream with a text protocol gate their own text
        transmission on this (SPEC.md section 3.6).
        """

        return self.state is SessionState.ACTIVE

    def start(self, now_ms: int) -> None:
        """Initiate the handshake by sending HELLO.

        Either role may initiate; a responder-role HELLO is the doorbell
        pattern of SPEC.md section 5.1.

        Args:
            now_ms: Monotonic timestamp of the transmission.

        Raises:
            SessionError: If the session is not idle, or the sid source
                returns a value outside [1, 255].
        """

        if self.state is not SessionState.IDLE:
            raise SessionError("start() requires an idle session")
        self._now_ms = now_ms
        self._sid = self._draw_sid()
        self._hello_attempts = 0
        self._transmit_hello(now_ms)
        self.state = SessionState.HELLO_SENT

    def receive_bytes(self, data: bytes, now_ms: int) -> list[SessionEvent]:
        """Feed transport bytes through the parser into the session.

        Args:
            data: Raw bytes from the transport, in arrival order.
            now_ms: Monotonic timestamp of the arrival.

        Returns:
            Host events emitted by these bytes, in order.
        """

        self._now_ms = now_ms
        events: list[SessionEvent] = []
        for parsed in self._parser.feed(data, now_ms):
            if isinstance(parsed, Passthrough):
                events.append(parsed)
            else:
                self._on_frame(parsed, now_ms, events)
        self._pump(now_ms, events)
        return events

    def data_to_send(self) -> bytes:
        """Drain bytes queued for the transport.

        Returns:
            All pending outbound wire bytes; empty when there is nothing
            to write. The internal buffer is cleared.
        """

        data = bytes(self._out)
        self._out.clear()
        return data

    def next_timeout(self) -> Optional[int]:
        """Earliest monotonic deadline at which handle_timeout() will act.

        Returns:
            The deadline timestamp, or None when no timer is pending.
        """

        deadlines: list[int] = []
        if (
            not self._parser.session_active
            and self._parser.state is ParserState.FRAME
            and self._parser.candidate
        ):
            deadlines.append(self._parser.last_byte_ms + T_FLUSH_MS)
        if self.state is SessionState.HELLO_SENT:
            deadlines.append(self._last_hello_tx_ms + T_HELLO_MS)
        if self.state is SessionState.ACTIVE:
            deadlines.append(self._last_rx_ms + T_DEAD_MS)
            if self._keepalive_allowed():
                deadlines.append(self._last_tx_ms + T_PING_MS)
        if self._link is not None:
            link_deadline = self._link.next_timeout()
            if link_deadline is not None:
                deadlines.append(link_deadline)
        return min(deadlines) if deadlines else None

    def handle_timeout(self, now_ms: int) -> list[SessionEvent]:
        """Run all expired timers.

        Args:
            now_ms: Monotonic timestamp.

        Returns:
            Host events emitted by timer actions, in order.
        """

        self._now_ms = now_ms
        events: list[SessionEvent] = []
        for parsed in self._parser.flush_idle(now_ms):
            if isinstance(parsed, Passthrough):
                events.append(parsed)
        if self.state is SessionState.HELLO_SENT and now_ms - self._last_hello_tx_ms >= T_HELLO_MS:
            self._retry_hello(now_ms, events)
        if self.state is SessionState.ACTIVE and self._link is not None:
            self._map_link_events(self._link.poll(now_ms), now_ms, events)
        if self.state is SessionState.ACTIVE:
            self._run_keepalive(now_ms, events)
        self._pump(now_ms, events)
        return events

    def abort(self, reason: AbortReason, now_ms: int) -> list[SessionEvent]:
        """Terminate this endpoint with a best-effort ABORT frame.

        Args:
            reason: ABORT reason to place on the wire. Use
                AbortReason.CLOSE for a clean session close and
                AbortReason.E_USER for host cancellation.
            now_ms: Monotonic timestamp of the abort.

        Returns:
            The local Ended event when a live session was ended, or an
            empty list when the session was already idle or ended.
        """

        self._now_ms = now_ms
        events: list[SessionEvent] = []
        if self.state is SessionState.ACTIVE:
            self._abort_session(reason, events)
        elif self.state is SessionState.HELLO_SENT:
            self._send_abort(self._sid, reason)
            self._end(reason, from_peer=False, events=events)
        return events

    def _run_keepalive(self, now_ms: int, events: list[SessionEvent]) -> None:
        """Run the keepalive and idle-death timers (SPEC.md section 4.5).

        T_DEAD without any valid in-session frame ends the session with
        a best-effort ABORT(E_TIMEOUT). Otherwise the controller sends a
        PING after T_PING of outbound silence whenever
        _keepalive_allowed() says no file stream can be open.
        """

        if now_ms - self._last_rx_ms >= T_DEAD_MS:
            self._abort_session(AbortReason.E_TIMEOUT, events)
            return
        if self._keepalive_allowed() and now_ms - self._last_tx_ms >= T_PING_MS:
            self._ping_token += 1
            self._last_tx_ms = now_ms
            self._send_ctrl(Ping(self._ping_token), now_ms)

    def _keepalive_allowed(self) -> bool:
        """Whether the controller keepalive may send PING now (SPEC.md
        section 4.5).

        A PING that reaches the peer inside a file stream is an E_PROTO
        violation (SPEC.md section 5.3), so it is held back from GET_REQ
        until the GET ends, and from PUT_REQ until our FILE_END. At
        every other point it runs, including while a LIST or DEL awaits
        its reply and while a PUT source is hashed: those can outlast
        T_DEAD on a large file with nothing else on the wire.
        """

        if self.role is not Role.CONTROLLER:
            return False
        op = self._op
        if isinstance(op, _CtrlGet):
            return False
        if isinstance(op, _CtrlPut):
            return op.phase in (_PutPhase.HASH, _PutPhase.AWAIT_DONE)
        return True

    def _draw_sid(self) -> int:
        """Draw and validate a session id from the configured source."""

        sid = self._sid_source()
        if not 1 <= sid <= 255:
            raise SessionError("sid source must return a value in [1, 255]")
        return sid

    def _transmit_hello(self, now_ms: int) -> None:
        """Send one HELLO attempt and record its time."""

        body = Hello(
            self._ver_min, self._ver_max, self.role, self._max_payload, self._window, self._caps
        ).encode()
        self._out += build_frame(FrameType.HELLO, self._sid, 0, 0, body)
        self._last_hello_tx_ms = now_ms
        self._hello_attempts += 1

    def _retry_hello(self, now_ms: int, events: list[SessionEvent]) -> None:
        """Retransmit HELLO or give up after N_HELLO attempts."""

        if self._hello_attempts >= N_HELLO:
            self.state = SessionState.ENDED
            self._end_reason = AbortReason.E_TIMEOUT
            events.append(Ended(AbortReason.E_TIMEOUT, from_peer=False))
            return
        self._transmit_hello(now_ms)

    def _on_frame(self, frame: Frame, now_ms: int, events: list[SessionEvent]) -> None:
        """Dispatch one validated frame according to the session state."""

        if self.state is SessionState.IDLE:
            if frame.type is FrameType.HELLO:
                self._replier_on_hello(frame, events)
        elif self.state is SessionState.HELLO_SENT:
            self._handshake_on_frame(frame, now_ms, events)
        elif self.state is SessionState.ACTIVE:
            self._active_on_frame(frame, now_ms, events)

    def _handshake_on_frame(self, frame: Frame, now_ms: int, events: list[SessionEvent]) -> None:
        """Handle frames while our HELLO is outstanding."""

        if frame.type is FrameType.HELLO_OK and frame.sid == self._sid:
            self._initiator_on_hello_ok(frame, now_ms, events)
        elif frame.type is FrameType.HELLO:
            self._initiator_on_collision(frame, now_ms, events)
        elif frame.type is FrameType.ABORT and frame.sid == self._sid:
            self._end(abort_reason_from_byte(frame.payload[0]), from_peer=True, events=events)

    def _active_on_frame(self, frame: Frame, now_ms: int, events: list[SessionEvent]) -> None:
        """Handle frames while the session is active."""

        if frame.sid == self._sid:
            self._last_rx_ms = now_ms
        if frame.type is FrameType.HELLO:
            if frame.sid == self._sid:
                if self._hello_ok_wire:
                    self._last_tx_ms = now_ms
                    self._out += self._hello_ok_wire
            else:
                self._send_abort(frame.sid, AbortReason.E_BUSY)
        elif frame.type is FrameType.HELLO_OK:
            return
        elif self._link is not None:
            self._map_link_events(self._link.on_frame(frame, now_ms), now_ms, events)

    def _initiator_on_hello_ok(self, frame: Frame, now_ms: int, events: list[SessionEvent]) -> None:
        """Complete the handshake from a HELLO_OK answering our HELLO."""

        try:
            ok = HelloOk.decode(frame.payload)
        except MessageError:
            return
        if not self._ver_min <= ok.ver <= self._ver_max:
            self._send_abort(self._sid, AbortReason.E_VERSION)
            self._end(AbortReason.E_VERSION, from_peer=False, events=events)
            return
        if ok.role == self.role:
            self._send_abort(self._sid, AbortReason.E_PROTO)
            self._end(AbortReason.E_PROTO, from_peer=False, events=events)
            return

        # The handshake round trip does not seed the RTO estimator (SPEC 4.4).
        # It is measured on an unloaded link, so it undershoots the RTT of a
        # full in-flight window and primes spurious full-window
        # retransmissions that Karn's rule then sustains. Start from
        # RTO_INITIAL_MS and let data-frame ACKs train the estimator.
        self._activate(self._sid, ok.ver, ok.max_payload, ok.window, ok.caps, events)

    def _initiator_on_collision(self, frame: Frame, now_ms: int, events: list[SessionEvent]) -> None:
        """Resolve a HELLO crossing ours per SPEC.md section 4.2."""

        if frame.sid > self._sid:
            return
        if frame.sid == self._sid:
            self._sid = self._draw_sid()
            self._hello_attempts = 0
            self._last_hello_tx_ms = now_ms
            return
        try:
            hello = Hello.decode(frame.payload)
        except MessageError:
            return
        self.state = SessionState.IDLE
        rejection = self._answer_hello(frame.sid, hello, events)
        if rejection is not None:
            self._end(rejection, from_peer=False, events=events)

    def _replier_on_hello(self, frame: Frame, events: list[SessionEvent]) -> None:
        """Answer a HELLO received while idle."""

        try:
            hello = Hello.decode(frame.payload)
        except MessageError:
            return
        self._answer_hello(frame.sid, hello, events)

    def _answer_hello(
        self, sid: int, hello: Hello, events: list[SessionEvent]
    ) -> Optional[AbortReason]:
        """Negotiate and answer a decoded HELLO as the replier.

        Returns:
            None on success, or the ABORT reason sent back on rejection;
            a rejection leaves this endpoint idle.
        """

        version = min(self._ver_max, hello.ver_max)
        if version < max(self._ver_min, hello.ver_min):
            self._send_abort(sid, AbortReason.E_VERSION)
            return AbortReason.E_VERSION
        if hello.role == self.role:
            self._send_abort(sid, AbortReason.E_PROTO)
            return AbortReason.E_PROTO

        body = HelloOk(version, self.role, self._max_payload, self._window, self._caps).encode()
        self._hello_ok_wire = build_frame(FrameType.HELLO_OK, sid, 0, 0, body)
        self._out += self._hello_ok_wire
        self._activate(sid, version, hello.max_payload, hello.window, hello.caps, events)
        return None

    def _activate(
        self,
        sid: int,
        version: int,
        peer_max_payload: int,
        peer_window: int,
        peer_caps: int,
        events: list[SessionEvent],
    ) -> None:
        """Enter the active state with negotiated parameters."""

        max_payload = min(self._max_payload, peer_max_payload)
        window = min(self._window, peer_window)
        self._sid = sid
        self._link = Link(sid, window, transmit=self._out_append, max_payload=max_payload)
        self._parser.max_payload = max_payload
        self._parser.session_active = True
        self._eff_max_payload = max_payload
        self._peer_caps = peer_caps
        self._last_tx_ms = self._now_ms
        self._last_rx_ms = self._now_ms
        self.state = SessionState.ACTIVE
        events.append(Established(sid, version, self.role, max_payload, window, peer_caps))

    def _out_append(self, wire: bytes) -> None:
        """Transmit sink handed to the link; every link frame counts as
        keepalive traffic."""

        self._last_tx_ms = self._now_ms
        self._out += wire

    def _send_abort(self, sid: int, reason: AbortReason) -> None:
        """Queue a best-effort ABORT frame for the given sid."""

        self._out += build_frame(FrameType.ABORT, sid, 0, 0, bytes([reason]))

    def _end(self, reason: AbortReason, from_peer: bool, events: list[SessionEvent]) -> None:
        """Terminate the session and notify the host."""

        self._release_op()
        self.state = SessionState.ENDED
        self._end_reason = reason
        self._parser.session_active = False
        events.append(Ended(reason, from_peer))

    def _release_op(self) -> None:
        """Release filesystem resources held by an in-flight operation."""

        op = self._op
        self._op = None
        if self._fs is None:
            return
        if isinstance(op, _RespList) and op.reading:
            self._fs.close_read()
        elif isinstance(op, _RespGet):
            self._fs.close_read()
        elif isinstance(op, _CtrlGet) and op.writing:
            self._fs.discard()
        elif isinstance(op, _CtrlPut) and op.reading:
            self._fs.close_read()
        elif isinstance(op, _RespPut) and op.writing:
            self._fs.discard()

    def _map_link_events(
        self, link_events: list[LinkEvent], now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Translate link events into session behavior and host events."""

        for event in link_events:
            if isinstance(event, Aborted):
                self._end(event.reason, event.from_peer, events)
            elif isinstance(event, Delivered):
                self._on_message(event.payload, now_ms, events)

    def _abort_session(self, reason: AbortReason, events: list[SessionEvent]) -> None:
        """Send a best-effort ABORT for the active session and end it."""

        self._send_abort(self._sid, reason)
        self._end(reason, from_peer=False, events=events)

    def _on_message(self, payload: bytes, now_ms: int, events: list[SessionEvent]) -> None:
        """Dispatch one in-order session message (SPEC.md section 5.3)."""

        try:
            message = decode_message(payload)
        except MessageError:
            self._abort_session(AbortReason.E_PROTO, events)
            return
        if self.role is Role.RESPONDER:
            self._responder_on_message(message, now_ms, events)
        else:
            self._controller_on_message(message, now_ms, events)

    def _responder_on_message(
        self, message: Message, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Serve one message as the responder."""

        if isinstance(self._op, _RespGet):
            # No inbound message is valid while the file stream runs
            # (SPEC.md section 5.3), PING included.
            self._abort_session(AbortReason.E_PROTO, events)
            return
        if isinstance(self._op, _RespPut):
            self._resp_on_put_stream(self._op, message, now_ms, events)
            return
        if isinstance(message, Ping):
            self._send_ctrl(Pong(message.token), now_ms)
            return
        if isinstance(message, (Pong, Err)):
            return
        if isinstance(self._op, _RespList):
            self._send_ctrl(Err(ErrCode.E_BAD_STATE, msg_type_of(message)), now_ms)
            return

        if isinstance(message, (ListReq, GetReq, PutReq, DelFile, DelDir)):
            # A new request supersedes the served-GET record; a
            # conforming controller sends GET_DONE first (SPEC.md
            # section 5.4).
            self._served_get = None

        if isinstance(message, ListReq):
            self._responder_on_list_req(message, now_ms)
        elif isinstance(message, GetReq):
            self._responder_on_get_req(message, now_ms)
        elif isinstance(message, PutReq):
            self._responder_on_put_req(message, now_ms)
        elif isinstance(message, (DelFile, DelDir)):
            self._responder_on_del(message, now_ms)
        elif isinstance(message, GetDone):
            self._resp_on_get_done(message, now_ms, events)
        elif isinstance(message, Plan):
            events.append(PlanReceived(message.nfiles, message.nbytes))
        elif isinstance(message, Unknown):
            self._send_ctrl(Err(ErrCode.E_UNSUPPORTED, message.msg_type), now_ms)
        else:
            self._send_ctrl(Err(ErrCode.E_BAD_STATE, msg_type_of(message)), now_ms)

    def _responder_on_list_req(self, message: ListReq, now_ms: int) -> None:
        """Open the listing cursor or answer with the failure ERR."""

        if not path_valid(message.root, allow_empty=True):
            self._send_ctrl(Err(ErrCode.E_PATH, MsgType.LIST_REQ), now_ms)
            return
        if self._fs is None:
            self._send_ctrl(Err(ErrCode.E_UNSUPPORTED, MsgType.LIST_REQ), now_ms)
            return
        entries = self._fs.list_entries(message.root.decode("utf-8"))
        if entries is None:
            self._send_ctrl(Err(ErrCode.E_FS_OPEN, MsgType.LIST_REQ), now_ms)
            return
        self._op = _RespList(entries=entries, want_crc=message.want_crc)

    def _responder_on_get_req(self, message: GetReq, now_ms: int) -> None:
        """Open the download stream or answer with the failure ERR."""

        if not path_valid(message.path):
            self._send_ctrl(Err(ErrCode.E_PATH, MsgType.GET_REQ), now_ms)
            return
        if self._fs is None:
            self._send_ctrl(Err(ErrCode.E_UNSUPPORTED, MsgType.GET_REQ), now_ms)
            return
        if message.offset != 0:
            self._send_ctrl(Err(ErrCode.E_UNSUPPORTED, MsgType.GET_REQ), now_ms)
            return
        path = message.path.decode("utf-8")
        size = self._fs.open_read(path)
        if size is None:
            self._send_ctrl(Err(ErrCode.E_FS_OPEN, MsgType.GET_REQ), now_ms)
            return
        self._op = _RespGet(path=path, size=size)
        self._send_ctrl(FileInfo(size), now_ms)

    def _responder_on_put_req(self, message: PutReq, now_ms: int) -> None:
        """Open the upload temp file and accept, or answer the failure ERR."""

        if not path_valid(message.path):
            self._send_ctrl(Err(ErrCode.E_PATH, MsgType.PUT_REQ), now_ms)
            return
        if self._fs is None:
            self._send_ctrl(Err(ErrCode.E_UNSUPPORTED, MsgType.PUT_REQ), now_ms)
            return
        if not self._fs.open_write(message.path.decode("utf-8")):
            self._send_ctrl(Err(ErrCode.E_FS_OPEN, MsgType.PUT_REQ), now_ms)
            return
        self._op = _RespPut(size=message.size, crc32=message.crc32)
        self._send_ctrl(PutOk(), now_ms)

    def _responder_on_del(self, message: Union[DelFile, DelDir], now_ms: int) -> None:
        """Remove the file or tree and answer DEL_OK, or answer the
        failure ERR.

        Deletes are double-gated (SPEC.md section 5.4): this endpoint
        must have advertised ALLOW_DELETE *and* the host callback must
        permit the specific path, otherwise E_DENIED.
        """

        ref = MsgType.DEL_DIR if isinstance(message, DelDir) else MsgType.DEL_FILE
        if not path_valid(message.path):
            self._send_ctrl(Err(ErrCode.E_PATH, ref), now_ms)
            return
        if not self._caps & CAP_ALLOW_DELETE:
            self._send_ctrl(Err(ErrCode.E_DENIED, ref), now_ms)
            return
        if self._fs is None:
            self._send_ctrl(Err(ErrCode.E_UNSUPPORTED, ref), now_ms)
            return
        path = message.path.decode("utf-8")
        if not self._fs.allow_delete(path):
            self._send_ctrl(Err(ErrCode.E_DENIED, ref), now_ms)
            return
        removed = (
            self._fs.remove_dir(path)
            if isinstance(message, DelDir)
            else self._fs.remove_file(path)
        )
        if removed:
            self._send_ctrl(DelOk(), now_ms)
        else:
            self._send_ctrl(Err(ErrCode.E_FS_REMOVE, ref), now_ms)

    def _resp_on_get_done(
        self, message: GetDone, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Surface the controller's verdict on the last served GET.

        GET_DONE is informational (SPEC.md section 5.4): status 0
        confirms the peer committed the download; any other status
        surfaces as OpFailed. Without a served GET to correlate to,
        the message is out of place.
        """

        served = self._served_get
        if served is None:
            self._send_ctrl(Err(ErrCode.E_BAD_STATE, MsgType.GET_DONE), now_ms)
            return
        self._served_get = None
        if message.status == 0:
            events.append(GetServed(served.path, served.size, served.crc32))
        else:
            events.append(OpFailed(MsgType.GET_REQ, served.path, ErrCode(message.status), 0))

    def _resp_on_put_stream(
        self, op: _RespPut, message: Message, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Handle one message inside the PUT_OK..FILE_END stream.

        ERR from the uploader fails the operation quietly; anything
        that is not FILE_DATA, FILE_END, or ERR is fatal (SPEC.md
        section 5.3).
        """

        if isinstance(message, FileData):
            self._resp_on_put_data(op, message.data)
        elif isinstance(message, FileEnd):
            self._resp_on_put_end(op, message.crc32, now_ms, events)
        elif isinstance(message, Err):
            self._put_discard(op)
            self._op = None
        else:
            self._put_discard(op)
            self._abort_session(AbortReason.E_PROTO, events)

    def _resp_on_put_data(self, op: _RespPut, data: bytes) -> None:
        """Stage one chunk; a write error fails the file but keeps
        consuming the stream so the session survives."""

        if op.failed is not None:
            return
        op.received += len(data)
        op.crc = crc32_update(op.crc, data)
        assert self._fs is not None
        if data and not self._fs.write(data):
            self._fs.discard()
            op.writing = False
            op.failed = ErrCode.E_FS_WRITE

    def _resp_on_put_end(
        self, op: _RespPut, peer_crc: int, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Close the stream: enforce the PUT_REQ/FILE_END CRC agreement,
        then verify, commit, and answer PUT_DONE."""

        assert self._fs is not None
        if peer_crc != op.crc32:
            # The uploader produced both CRCs; disagreement is a
            # protocol violation, not a transfer error (SPEC.md
            # section 5.4).
            self._put_discard(op)
            self._abort_session(AbortReason.E_PROTO, events)
            return
        self._op = None
        if op.failed is not None:
            self._send_ctrl(PutDone(op.failed), now_ms)
            return
        if op.received == op.size and op.crc == peer_crc:
            op.writing = False
            if self._fs.commit():
                self._send_ctrl(PutDone(0), now_ms)
            else:
                self._send_ctrl(PutDone(ErrCode.E_FS_WRITE), now_ms)
            return
        self._put_discard(op)
        self._send_ctrl(PutDone(ErrCode.E_CRC_FILE), now_ms)

    def _put_discard(self, op: _RespPut) -> None:
        """Discard the staged temporary file if one is open."""

        if op.writing:
            assert self._fs is not None
            self._fs.discard()
            op.writing = False

    def _controller_on_message(
        self, message: Message, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Collect one message as the controller."""

        op = self._op
        if isinstance(op, _CtrlGet) and op.streaming:
            self._ctrl_on_get_stream(op, message, now_ms, events)
            return
        if isinstance(op, _CtrlPut) and op.phase is _PutPhase.STREAM:
            # No inbound message is valid while our upload stream runs
            # (SPEC.md section 5.3), PING included.
            self._abort_session(AbortReason.E_PROTO, events)
            return
        if isinstance(message, Ping):
            self._send_ctrl(Pong(message.token), now_ms)
            return
        if isinstance(message, Pong):
            return
        if isinstance(message, Notify):
            # Legal at any between-message point, like PONG (SPEC.md
            # section 5.4): the responder may queue it while our request
            # is in flight.
            events.append(NotifyReceived(message.flags))
            return
        if isinstance(op, _CtrlGet):
            self._ctrl_on_get_await_info(op, message, now_ms, events)
            return
        if isinstance(op, _CtrlPut):
            self._ctrl_on_put_reply(op, message, now_ms, events)
            return
        if isinstance(op, _CtrlDel):
            self._ctrl_on_del_reply(op, message, now_ms, events)
            return
        if isinstance(op, _CtrlList):
            if isinstance(message, ListEntry):
                self._ctrl_on_list_entry(op, message, events)
            elif isinstance(message, ListEnd):
                self._op = None
                if message.count != op.received:
                    self._abort_session(AbortReason.E_PROTO, events)
                    return
                events.append(ListDone(op.received))
            elif isinstance(message, Err):
                if message.code is ErrCode.E_FS_READ:
                    # Informational skip report (SPEC.md section 5.4):
                    # the responder could not read one file; the
                    # listing lives.
                    events.append(EntrySkipped(message.code, message.detail))
                else:
                    self._op = None
                    events.append(
                        OpFailed(MsgType.LIST_REQ, None, message.code, message.detail)
                    )
            else:
                self._send_ctrl(Err(ErrCode.E_BAD_STATE, msg_type_of(message)), now_ms)
            return

        if isinstance(message, Err):
            return
        if isinstance(message, Unknown):
            self._send_ctrl(Err(ErrCode.E_UNSUPPORTED, message.msg_type), now_ms)
        else:
            self._send_ctrl(Err(ErrCode.E_BAD_STATE, msg_type_of(message)), now_ms)

    def _ctrl_on_list_entry(
        self, op: _CtrlList, message: ListEntry, events: list[SessionEvent]
    ) -> None:
        """Surface one LIST_ENTRY, dropping entries with invalid paths."""

        op.received += 1
        if not path_valid(message.path):
            return
        events.append(
            EntryListed(
                etype=message.etype,
                path=message.path.decode("utf-8"),
                size=message.size,
                mtime=message.mtime,
                crc32=message.crc32 if message.crc_valid else None,
            )
        )

    def _ctrl_on_get_await_info(
        self, op: _CtrlGet, message: Message, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Handle one message while GET awaits FILE_INFO."""

        if isinstance(message, FileInfo):
            op.streaming = True
            op.size = message.size
            op.received = 0
            op.crc = 0
            assert self._fs is not None
            if self._fs.open_write(op.path):
                op.writing = True
            else:
                op.failed = ErrCode.E_FS_OPEN
        elif isinstance(message, Err):
            self._op = None
            events.append(OpFailed(MsgType.GET_REQ, op.path, message.code, message.detail))
        else:
            self._send_ctrl(Err(ErrCode.E_BAD_STATE, msg_type_of(message)), now_ms)

    def _ctrl_on_get_stream(
        self, op: _CtrlGet, message: Message, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Handle one message inside the FILE_INFO..FILE_END stream.

        ERR fails the file and ends the operation; anything that is not
        FILE_DATA, FILE_END, or ERR is fatal (SPEC.md section 5.3).
        """

        if isinstance(message, FileData):
            self._ctrl_on_file_data(op, message.data)
        elif isinstance(message, FileEnd):
            self._ctrl_on_file_end(op, message.crc32, now_ms, events)
        elif isinstance(message, Err):
            self._get_discard(op)
            self._op = None
            events.append(OpFailed(MsgType.GET_REQ, op.path, message.code, message.detail))
        else:
            self._get_discard(op)
            self._abort_session(AbortReason.E_PROTO, events)

    def _ctrl_on_file_data(self, op: _CtrlGet, data: bytes) -> None:
        """Stage one chunk; a write error fails the file but keeps
        consuming the stream so the session survives."""

        if op.failed is not None:
            return
        op.received += len(data)
        op.crc = crc32_update(op.crc, data)
        assert self._fs is not None
        if data and not self._fs.write(data):
            self._fs.discard()
            op.writing = False
            op.failed = ErrCode.E_FS_WRITE

    def _ctrl_on_file_end(
        self, op: _CtrlGet, peer_crc: int, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Verify the finished stream: commit, retry once, or fail."""

        assert self._fs is not None
        if op.failed is not None:
            self._op = None
            self._send_ctrl(GetDone(op.failed), now_ms)
            events.append(OpFailed(MsgType.GET_REQ, op.path, op.failed, 0))
            return
        if op.received == op.size and op.crc == peer_crc:
            op.writing = False
            self._op = None
            if self._fs.commit():
                self._send_ctrl(GetDone(0), now_ms)
                events.append(GetDoneEvent(op.path, op.size, op.crc))
            else:
                self._send_ctrl(GetDone(ErrCode.E_FS_WRITE), now_ms)
                events.append(OpFailed(MsgType.GET_REQ, op.path, ErrCode.E_FS_WRITE, 0))
            return
        self._get_discard(op)
        self._send_ctrl(GetDone(ErrCode.E_CRC_FILE), now_ms)
        if op.retried:
            self._op = None
            events.append(OpFailed(MsgType.GET_REQ, op.path, ErrCode.E_CRC_FILE, 0))
            return
        op.retried = True
        op.streaming = False
        op.size = 0
        op.received = 0
        op.crc = 0
        self._send_ctrl(GetReq(0, op.path_bytes), now_ms)

    def _get_discard(self, op: _CtrlGet) -> None:
        """Discard the staged temporary file if one is open."""

        if op.writing:
            assert self._fs is not None
            self._fs.discard()
            op.writing = False

    def _ctrl_on_put_reply(
        self, op: _CtrlPut, message: Message, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Handle one message while PUT hashes or awaits PUT_OK/PUT_DONE."""

        if isinstance(message, PutOk) and op.phase is _PutPhase.AWAIT_OK:
            assert self._fs is not None
            if self._fs.open_read(op.path) is None:
                self._op = None
                self._send_ctrl(Err(ErrCode.E_FS_OPEN, MsgType.PUT_REQ), now_ms)
                events.append(OpFailed(MsgType.PUT_REQ, op.path, ErrCode.E_FS_OPEN, 0))
                return
            op.reading = True
            op.phase = _PutPhase.STREAM
            return
        if isinstance(message, PutDone) and op.phase is _PutPhase.AWAIT_DONE:
            self._op = None
            if message.status == 0:
                events.append(PutDoneEvent(op.path, op.size, op.crc))
            else:
                events.append(
                    OpFailed(MsgType.PUT_REQ, op.path, ErrCode(message.status), 0)
                )
            return
        if isinstance(message, Err):
            if op.phase is _PutPhase.HASH:
                # Nothing has been requested yet; the ERR is stray.
                return
            self._op = None
            events.append(OpFailed(MsgType.PUT_REQ, op.path, message.code, message.detail))
            return
        self._send_ctrl(Err(ErrCode.E_BAD_STATE, msg_type_of(message)), now_ms)

    def _ctrl_on_del_reply(
        self, op: _CtrlDel, message: Message, now_ms: int, events: list[SessionEvent]
    ) -> None:
        """Handle one message while DEL awaits DEL_OK."""

        request = MsgType.DEL_DIR if op.is_dir else MsgType.DEL_FILE
        if isinstance(message, DelOk):
            self._op = None
            events.append(DelDone(op.path, op.is_dir))
        elif isinstance(message, Err):
            self._op = None
            events.append(OpFailed(request, op.path, message.code, message.detail))
        else:
            self._send_ctrl(Err(ErrCode.E_BAD_STATE, msg_type_of(message)), now_ms)

    def request_list(self, root: str, want_crc: bool, now_ms: int) -> None:
        """Start a LIST operation (controller only).

        Entries arrive as EntryListed events, closed by ListDone or
        OpFailed. Strictly sequential: only one operation may run.

        Args:
            root: Listing root; empty string lists the whole tree.
            want_crc: Ask the responder for per-file CRC32 values.
            now_ms: Monotonic timestamp of the transmission.

        Raises:
            SessionError: If the session is not active, this endpoint is
                not the controller, another operation is in flight, or
                root violates the path rules.
        """

        self._now_ms = now_ms
        root_bytes = self._require_request_path(root, allow_empty=True)
        self._op = _CtrlList()
        self._send_ctrl(ListReq(want_crc, root_bytes), now_ms)

    def request_get(self, path: str, now_ms: int) -> None:
        """Start a GET operation (controller only).

        The file streams into the provider's temporary file and commits
        only after size and CRC verify (SPEC.md section 5.4); a
        verification mismatch silently retries the file once. Closed by
        GetDone or OpFailed, and the session continues either way.

        Args:
            path: Relative path of the file to fetch.
            now_ms: Monotonic timestamp of the transmission.

        Raises:
            SessionError: If the session is not active, this endpoint is
                not the controller, another operation is in flight, no
                filesystem provider stages the file, path violates the
                path rules, or the request exceeds the negotiated
                payload.
        """

        self._now_ms = now_ms
        path_bytes = self._require_request_path(path)
        if self._fs is None:
            raise SessionError("GET requires a filesystem provider to stage the file")
        if _GET_REQ_OVERHEAD + len(path_bytes) > self._eff_max_payload:
            raise SessionError("path does not fit the negotiated payload")
        self._op = _CtrlGet(path=path, path_bytes=path_bytes)
        self._send_ctrl(GetReq(0, path_bytes), now_ms)

    def request_put(self, path: str, now_ms: int) -> None:
        """Start a PUT operation (controller only).

        The file is hashed under the bounded per-poll budget, offered
        with PUT_REQ, and streamed once the responder accepts; the
        responder commits only after size and CRC verify (SPEC.md
        section 5.4). PUT_REQ goes out only once handle_timeout()
        finishes the hash, so drive the operation with handle_timeout()
        while work_pending() is true; keepalive PINGs keep the peer's
        idle timer fed meanwhile (SPEC.md section 4.5). Closed by
        PutDone or OpFailed, and the session continues either way.

        Args:
            path: Relative path of the file to upload.
            now_ms: Monotonic timestamp of the request.

        Raises:
            SessionError: If the session is not active, this endpoint is
                not the controller, another operation is in flight, no
                filesystem provider sources the file, path violates the
                path rules, or the request exceeds the negotiated
                payload.
        """

        self._now_ms = now_ms
        path_bytes = self._require_request_path(path)
        if self._fs is None:
            raise SessionError("PUT requires a filesystem provider to source the file")
        if _PUT_REQ_OVERHEAD + len(path_bytes) > self._eff_max_payload:
            raise SessionError("path does not fit the negotiated payload")
        op = _CtrlPut(path=path, path_bytes=path_bytes)
        self._op = op
        size = self._fs.open_read(path)
        if size is None:
            op.failed = ErrCode.E_FS_OPEN
        else:
            op.reading = True
            op.size_hint = size

    def request_del(self, path: str, is_dir: bool, now_ms: int) -> None:
        """Start a DEL operation (controller only).

        Sends DEL_FILE, or recursive DEL_DIR when is_dir. The responder
        double-gates deletes (SPEC.md section 5.4): it must advertise
        ALLOW_DELETE and permit the specific path per request, otherwise
        the operation fails with E_DENIED. Closed by DelDone or
        OpFailed, and the session continues either way.

        Args:
            path: Relative path of the file or directory to remove.
            is_dir: Remove a directory tree recursively instead of one
                file.
            now_ms: Monotonic timestamp of the transmission.

        Raises:
            SessionError: If the session is not active, this endpoint is
                not the controller, another operation is in flight, path
                violates the path rules, or the request exceeds the
                negotiated payload.
        """

        self._now_ms = now_ms
        path_bytes = self._require_request_path(path)
        if _DEL_OVERHEAD + len(path_bytes) > self._eff_max_payload:
            raise SessionError("path does not fit the negotiated payload")
        self._op = _CtrlDel(path=path, path_bytes=path_bytes, is_dir=is_dir)
        self._send_ctrl(DelDir(path_bytes) if is_dir else DelFile(path_bytes), now_ms)

    def send_plan(self, nfiles: int, nbytes: int, now_ms: int) -> None:
        """Announce batch totals with PLAN (controller only).

        Informative for the responder's progress display (SPEC.md
        section 5.4); no reply is expected and no operation slot is
        held, so the next request may follow immediately.

        Args:
            nfiles: Number of files this batch intends to transfer.
            nbytes: Total bytes this batch intends to transfer.
            now_ms: Monotonic timestamp of the transmission.

        Raises:
            SessionError: If the session is not active, this endpoint is
                not the controller, another operation is in flight, or a
                total is out of its wire-field range.
        """

        self._now_ms = now_ms
        self._require_controller_idle()
        if not 0 <= nfiles <= 0xFFFF:
            raise SessionError("nfiles must fit u16")
        if not 0 <= nbytes <= 0xFFFFFFFF:
            raise SessionError("nbytes must fit u32")
        self._send_ctrl(Plan(nfiles, nbytes), now_ms)

    def send_notify(self, flags: int, now_ms: int) -> None:
        """Ask the controller to pull files with NOTIFY (responder only).

        Informative for the controller's sync policy (SPEC.md section
        5.4); no reply is expected and no operation slot is held. The
        idle-slot requirement keeps NOTIFY out of a FILE_DATA stream
        being served — retry after the operation completes.

        Args:
            flags: Combination of the rqft.messages NOTIFY_* bits. Bit 0
                is the sync mode: 0 = full sync, 1 = incremental sync.
            now_ms: Monotonic timestamp of the transmission.

        Raises:
            SessionError: If the session is not active, this endpoint is
                not the responder, an operation is in flight, or an
                undefined flag bit is set.
        """

        self._now_ms = now_ms
        if self.state is not SessionState.ACTIVE:
            raise SessionError("operation requires an active session")
        if self.role is not Role.RESPONDER:
            raise SessionError("NOTIFY is sent by the responder")
        if self._op is not None:
            raise SessionError("another operation is in flight")
        if flags & ~_NOTIFY_DEFINED_MASK:
            raise SessionError("undefined NOTIFY flag bits must be 0")
        self._send_ctrl(Notify(flags), now_ms)

    def _require_controller_idle(self) -> None:
        """Validate the shared controller-request preconditions.

        Raises:
            SessionError: On role, state, or in-flight violations.
        """

        if self.state is not SessionState.ACTIVE:
            raise SessionError("operation requires an active session")
        if self.role is not Role.CONTROLLER:
            raise SessionError("operations are driven by the controller")
        if self._op is not None:
            raise SessionError("another operation is in flight")

    def _require_request_path(self, path: str, allow_empty: bool = False) -> bytes:
        """Validate operation preconditions and encode the request path.

        Raises:
            SessionError: On role, state, in-flight, or path violations.
        """

        self._require_controller_idle()
        path_bytes = path.encode("utf-8")
        if not path_valid(path_bytes, allow_empty=allow_empty):
            raise SessionError("path violates SPEC.md section 1 rules")
        return path_bytes

    def progress(self) -> Optional[TransferProgress]:
        """Snapshot the byte counters of the in-flight file transfer.

        Works for both roles: a controller sees its own GET download or
        PUT hash/upload, a responder sees the GET it is serving or the
        PUT it is receiving. Poll between pump turns to drive a
        progress display; totals come from FILE_INFO, PUT_REQ, or the
        filesystem provider, so no extra wire traffic is involved.

        Returns:
            The current counters, or None while no file transfer is in
            flight (idle, LIST, DEL, or no active session).
        """

        if self.state is not SessionState.ACTIVE:
            return None
        op = self._op
        if isinstance(op, _CtrlGet):
            if not op.streaming:
                return TransferProgress(MsgType.GET_REQ, TransferPhase.STREAM, 0, None)
            return TransferProgress(MsgType.GET_REQ, TransferPhase.STREAM, op.received, op.size)
        if isinstance(op, _RespGet):
            return TransferProgress(MsgType.GET_REQ, TransferPhase.STREAM, op.sent, op.size)
        if isinstance(op, _CtrlPut):
            if op.phase is _PutPhase.HASH:
                return TransferProgress(
                    MsgType.PUT_REQ, TransferPhase.HASH, op.hashed, op.size_hint
                )
            return TransferProgress(MsgType.PUT_REQ, TransferPhase.STREAM, op.sent, op.size)
        if isinstance(op, _RespPut):
            return TransferProgress(MsgType.PUT_REQ, TransferPhase.STREAM, op.received, op.size)
        return None

    def diagnostics(self) -> SessionDiagnostics:
        """Snapshot frame counters and current reliable-link timing state.

        Returns:
            Immutable diagnostic values. Link-only fields are None before
            handshake creates a link; RTT fields remain None until sampled.
        """

        parser = self._parser.diag
        link = self._link
        if link is None:
            frames_wrong_sid = 0
            frames_retransmitted = 0
            naks_sent = 0
            duplicate_data_received = 0
            out_of_order_data_received = 0
            srtt_ms: Optional[int] = None
            rttvar_ms: Optional[int] = None
            rto_ms: Optional[int] = None
            in_flight: Optional[int] = None
        else:
            frames_wrong_sid = link.diag.frames_wrong_sid
            frames_retransmitted = link.diag.frames_retransmitted
            naks_sent = link.diag.naks_sent
            duplicate_data_received = link.diag.duplicate_data_received
            out_of_order_data_received = link.diag.out_of_order_data_received
            estimator = link._estimator
            sampled = estimator.srtt_ms >= 0
            srtt_ms = estimator.srtt_ms if sampled else None
            rttvar_ms = estimator.rttvar_ms if sampled else None
            rto_ms = link._rto_ms
            in_flight = link.in_flight
        return SessionDiagnostics(
            frames_ok=parser.frames_ok,
            frames_crc_fail=parser.frames_crc_fail,
            frames_oversize=parser.frames_oversize,
            frames_dropped=parser.frames_dropped,
            candidates_idle_flushed=parser.candidates_idle_flushed,
            valid_candidates_idle_flushed=parser.valid_candidates_idle_flushed,
            bytes_idle_flushed=parser.bytes_idle_flushed,
            frames_wrong_sid=frames_wrong_sid,
            frames_retransmitted=frames_retransmitted,
            naks_sent=naks_sent,
            duplicate_data_received=duplicate_data_received,
            out_of_order_data_received=out_of_order_data_received,
            bytes_passthrough=parser.bytes_passthrough,
            bytes_dropped_in_session=parser.bytes_dropped_in_session,
            srtt_ms=srtt_ms,
            rttvar_ms=rttvar_ms,
            rto_ms=rto_ms,
            in_flight=in_flight,
        )

    def work_pending(self) -> bool:
        """Whether handle_timeout() has queued or bounded work to run now.

        Hosts loop ``while session.work_pending(): session.handle_timeout(now)``
        between transport reads to drive queued replies and incremental
        listing, hashing, and file-streaming work to completion.
        """

        if self.state is not SessionState.ACTIVE:
            return False
        if bool(self._ctrl) or self._ctrl_overflow:
            return True
        if isinstance(self._op, _CtrlPut):
            return self._op.failed is not None or self._op.phase in (
                _PutPhase.HASH,
                _PutPhase.STREAM,
            )
        return isinstance(self._op, (_RespList, _RespGet))

    def _send_ctrl(self, message: _Encodable, now_ms: int) -> None:
        """Queue one small control message and drain the queue in order.

        Overflow marks the session for an E_INTERNAL abort at the next
        pump: a peer that provokes sixteen unanswered replies is broken.
        """

        if len(self._ctrl) >= _CTRL_QUEUE_MAX:
            self._ctrl_overflow = True
            return
        self._ctrl.append(message.encode())
        self._drain_ctrl(now_ms)

    def _send_info_err(self, code: ErrCode, ref: MsgType, now_ms: int) -> None:
        """Queue an informational ERR best-effort.

        A full control queue drops the report instead of marking
        overflow, since losing an informative message must never end
        the session.
        """

        if len(self._ctrl) >= _CTRL_QUEUE_MAX:
            return
        self._send_ctrl(Err(code, ref), now_ms)

    def _drain_ctrl(self, now_ms: int) -> None:
        """Send queued control messages until the window fills."""

        while self._ctrl and self.state is SessionState.ACTIVE and self._link is not None:
            if not self._link.send(self._ctrl[0], now_ms):
                return
            self._ctrl.popleft()

    def _try_send(self, encoded: bytes, now_ms: int) -> bool:
        """Send one operation message unless queued control traffic or a
        full window blocks it."""

        if self.state is not SessionState.ACTIVE or self._link is None:
            return False
        self._drain_ctrl(now_ms)
        if self._ctrl:
            return False
        return self._link.send(encoded, now_ms)

    def _pump(self, now_ms: int, events: list[SessionEvent]) -> None:
        """Run queued sends and one bounded slice of operation work."""

        if self.state is not SessionState.ACTIVE:
            return
        if self._ctrl_overflow:
            self._abort_session(AbortReason.E_INTERNAL, events)
            return
        self._drain_ctrl(now_ms)
        if isinstance(self._op, _RespList):
            self._pump_resp_list(self._op, now_ms, CRC_BUDGET_PER_POLL)
        elif isinstance(self._op, _RespGet):
            self._pump_resp_get(self._op, now_ms, CRC_BUDGET_PER_POLL)
        elif isinstance(self._op, _CtrlPut):
            self._pump_ctrl_put(self._op, now_ms, CRC_BUDGET_PER_POLL, events)

    def _pump_resp_list(self, op: _RespList, now_ms: int, budget: int) -> None:
        """Advance the responder listing: hash within budget, send entries
        while the window has room, and finish with LIST_END."""

        assert self._fs is not None
        for _ in range(_PUMP_MAX_STEPS):
            if op.current is None and not self._resp_list_advance(op, now_ms):
                return
            if op.reading:
                budget = self._resp_list_hash(op, now_ms, budget)
                if op.reading:
                    return
                if op.current is None:
                    continue
            entry = op.current
            assert entry is not None
            if op.want_crc and entry.etype == 0:
                message = ListEntry(entry.etype, True, op.hashed, op.crc, entry.mtime, op.path_bytes)
            else:
                message = ListEntry(entry.etype, False, entry.size, 0, entry.mtime, op.path_bytes)
            if not self._try_send(message.encode(), now_ms):
                return
            op.count += 1
            op.current = None

    def _resp_list_advance(self, op: _RespList, now_ms: int) -> bool:
        """Pull the next listable entry into op.current.

        Entries with unencodable, invalid, or over-long paths are
        skipped silently; files the provider cannot open while hashing
        are skipped with an informational ERR(E_FS_READ) (SPEC.md
        section 5.4).

        Returns:
            True when an entry is staged; False when the listing ended
            (LIST_END queued) or the current step should retry later.
        """

        assert self._fs is not None
        while True:
            entry = next(op.entries, None)
            if entry is None:
                self._op = None
                self._send_ctrl(ListEnd(op.count), now_ms)
                return False
            try:
                path_bytes = entry.path.encode("utf-8")
            except UnicodeEncodeError:
                continue
            if not path_valid(path_bytes):
                continue
            if _LIST_ENTRY_OVERHEAD + len(path_bytes) > self._eff_max_payload:
                continue
            op.current = entry
            op.path_bytes = path_bytes
            op.reading = False
            op.hashed = 0
            op.crc = 0
            if op.want_crc and entry.etype == 0:
                if self._fs.open_read(entry.path) is None:
                    self._send_info_err(ErrCode.E_FS_READ, MsgType.LIST_REQ, now_ms)
                    continue
                op.reading = True
            return True

    def _resp_list_hash(self, op: _RespList, now_ms: int, budget: int) -> int:
        """Hash the staged file within budget; returns the budget left.

        A read error skips the entry with an informational
        ERR(E_FS_READ) (SPEC.md section 5.4: files the responder
        cannot read are skipped); the hashed byte count replaces the
        listed size so size and CRC always agree.
        """

        assert self._fs is not None
        while budget > 0:
            chunk = self._fs.read(min(budget, _HASH_READ_MAX))
            if chunk is None:
                self._fs.close_read()
                op.reading = False
                op.current = None
                self._send_info_err(ErrCode.E_FS_READ, MsgType.LIST_REQ, now_ms)
                return budget
            if chunk == b"":
                self._fs.close_read()
                op.reading = False
                return budget
            op.crc = crc32_update(op.crc, chunk)
            op.hashed += len(chunk)
            budget -= len(chunk)
        return 0

    def _pump_resp_get(self, op: _RespGet, now_ms: int, budget: int) -> None:
        """Advance the download stream: read full chunks within budget,
        send them while the window has room, and finish with FILE_END.

        A read error or early end of file breaks the promised byte
        count, so the stream ends with ERR(E_FS_READ) instead.
        """

        assert self._fs is not None
        chunk_size = self._eff_max_payload - 1
        for _ in range(_PUMP_MAX_STEPS):
            target = min(chunk_size, op.size - op.sent)
            if target > 0 and len(op.chunk) == target:
                if not self._try_send(FileData(op.chunk).encode(), now_ms):
                    return
                op.sent += len(op.chunk)
                op.chunk = b""
                continue
            if op.sent == op.size:
                self._fs.close_read()
                self._op = None
                self._served_get = _ServedGet(op.path, op.size, op.crc)
                self._send_ctrl(FileEnd(op.crc), now_ms)
                return
            if budget <= 0:
                return
            data = self._fs.read(min(budget, target - len(op.chunk)))
            if not data:
                self._fs.close_read()
                self._op = None
                self._send_ctrl(Err(ErrCode.E_FS_READ, MsgType.GET_REQ), now_ms)
                return
            op.crc = crc32_update(op.crc, data)
            op.chunk += data
            budget -= len(data)

    def _pump_ctrl_put(
        self, op: _CtrlPut, now_ms: int, budget: int, events: list[SessionEvent]
    ) -> None:
        """Advance the upload: surface a staged open failure, hash within
        budget toward PUT_REQ, or stream chunks while the window has room."""

        if op.failed is not None:
            self._op = None
            events.append(OpFailed(MsgType.PUT_REQ, op.path, op.failed, 0))
            return
        if op.phase is _PutPhase.HASH:
            self._put_hash(op, now_ms, budget, events)
        elif op.phase is _PutPhase.STREAM:
            self._pump_put_stream(op, now_ms, budget, events)

    def _put_hash(
        self, op: _CtrlPut, now_ms: int, budget: int, events: list[SessionEvent]
    ) -> None:
        """Hash the staged upload within budget; the hashed byte count
        becomes PUT_REQ.size so size and CRC always agree.

        A read error fails the file before anything reaches the wire.
        """

        assert self._fs is not None
        while budget > 0:
            chunk = self._fs.read(min(budget, _HASH_READ_MAX))
            if chunk is None:
                self._fs.close_read()
                op.reading = False
                self._op = None
                events.append(OpFailed(MsgType.PUT_REQ, op.path, ErrCode.E_FS_READ, 0))
                return
            if chunk == b"":
                self._fs.close_read()
                op.reading = False
                op.size = op.hashed
                op.phase = _PutPhase.AWAIT_OK
                self._send_ctrl(PutReq(op.size, op.crc, op.path_bytes), now_ms)
                return
            op.crc = crc32_update(op.crc, chunk)
            op.hashed += len(chunk)
            budget -= len(chunk)

    def _pump_put_stream(
        self, op: _CtrlPut, now_ms: int, budget: int, events: list[SessionEvent]
    ) -> None:
        """Advance the upload stream: read full chunks within budget, send
        them while the window has room, and finish with FILE_END carrying
        the PUT_REQ CRC.

        A read error or early end of file breaks the promised byte
        count, so the stream ends with ERR(E_FS_READ) and the file
        fails locally.
        """

        assert self._fs is not None
        chunk_size = self._eff_max_payload - 1
        for _ in range(_PUMP_MAX_STEPS):
            target = min(chunk_size, op.size - op.sent)
            if target > 0 and len(op.chunk) == target:
                if not self._try_send(FileData(op.chunk).encode(), now_ms):
                    return
                op.sent += len(op.chunk)
                op.chunk = b""
                continue
            if op.sent == op.size:
                self._fs.close_read()
                op.reading = False
                op.phase = _PutPhase.AWAIT_DONE
                self._send_ctrl(FileEnd(op.crc), now_ms)
                return
            if budget <= 0:
                return
            data = self._fs.read(min(budget, target - len(op.chunk)))
            if not data:
                self._fs.close_read()
                op.reading = False
                self._op = None
                self._send_ctrl(Err(ErrCode.E_FS_READ, MsgType.PUT_REQ), now_ms)
                events.append(OpFailed(MsgType.PUT_REQ, op.path, ErrCode.E_FS_READ, 0))
                return
            op.chunk += data
            budget -= len(data)
