# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Go-Back-N link layer for SPEC.md section 4.

The link endpoint turns host payloads into sequenced DATA frames with a
bounded retransmission window, and turns validated inbound frames into
typed events. It is sans-io: wire bytes leave through an injected
transmit callable, timing comes from explicit ``now_ms`` arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Callable, Final, Union

from rqft import MAX_PAYLOAD, WINDOW_MAX
from rqft.frame import Frame, FrameType, build_frame
from rqft.rto import RTO_INITIAL_MS, RTO_MAX_MS, RtoEstimator

# Consecutive retransmission timeouts that kill a session, from SPEC.md
# section 4.3.
N_RETRY: Final = 8


class LinkError(ValueError):
    """Raised on link API misuse: bad configuration, bad payload size, or
    sending on a dead link."""


class AbortReason(IntEnum):
    """ABORT reason codes from SPEC.md section 4.6."""

    CLOSE = 0x00
    E_VERSION = 0x01
    E_TIMEOUT = 0x02
    E_PROTO = 0x03
    E_BUSY = 0x04
    E_INTERNAL = 0x05
    E_USER = 0x06


class LinkState(Enum):
    """Life-cycle states of a link endpoint."""

    ACTIVE = "ACTIVE"
    DEAD = "DEAD"


@dataclass(frozen=True)
class Delivered:
    """In-order payload received from the peer.

    Attributes:
        payload: DATA frame payload delivered exactly once, in order.
    """

    payload: bytes


@dataclass(frozen=True)
class Aborted:
    """Session termination event.

    Attributes:
        reason: ABORT reason code.
        from_peer: True when the peer sent the ABORT frame; False when the
            link terminated locally (for example retry exhaustion).
    """

    reason: AbortReason
    from_peer: bool


# Event type emitted by Link.on_frame() and Link.poll().
LinkEvent = Union[Delivered, Aborted]


@dataclass
class Diagnostics:
    """Link diagnostic counters from SPEC.md section 4.1.

    Attributes:
        frames_wrong_sid: Non-HELLO frames dropped because their sid was
            not the active one.
        frames_retransmitted: DATA frames resent after RTO expiry or NAK.
        naks_sent: ACK+NAK frames sent for unexpected DATA sequence numbers.
        duplicate_data_received: DATA frames received behind expected_seq.
        out_of_order_data_received: DATA frames received ahead of expected_seq.
    """

    frames_wrong_sid: int = 0
    frames_retransmitted: int = 0
    naks_sent: int = 0
    duplicate_data_received: int = 0
    out_of_order_data_received: int = 0


def abort_reason_from_byte(byte: int) -> AbortReason:
    """Map a received ABORT reason byte to a typed reason.

    Args:
        byte: Reason byte from the ABORT payload.

    Returns:
        The matching AbortReason, or E_PROTO for reason bytes this version
        does not define.
    """

    try:
        return AbortReason(byte)
    except ValueError:
        return AbortReason.E_PROTO


@dataclass
class _Slot:
    """One unacknowledged DATA frame buffered for retransmission."""

    seq: int
    payload: bytes
    first_tx_ms: int
    retransmitted: bool = False


class Link:
    """One endpoint of the SPEC.md section 4.3 Go-Back-N reliable stream.

    Attributes:
        sid: Non-zero session id carried by every frame.
        window: Maximum unacknowledged DATA frames in flight.
        max_payload: Largest DATA payload accepted by send().
        state: Current life-cycle state.
    """

    def __init__(
        self,
        sid: int,
        window: int,
        transmit: Callable[[bytes], None],
        max_payload: int = MAX_PAYLOAD,
    ) -> None:
        """Initialize an active link endpoint.

        Args:
            sid: Non-zero session id in [1, 255].
            window: Negotiated send window in [1, WINDOW_MAX].
            transmit: Called with complete wire frames to write to the
                transport, from within send(), on_frame(), and poll().
            max_payload: Negotiated payload limit in [1, MAX_PAYLOAD].

        Raises:
            LinkError: If sid, window, or max_payload is out of range.
        """

        if not 1 <= sid <= 255:
            raise LinkError("sid must be in [1, 255]")
        if not 1 <= window <= WINDOW_MAX:
            raise LinkError("window must be in [1, WINDOW_MAX]")
        if not 1 <= max_payload <= MAX_PAYLOAD:
            raise LinkError("max_payload must be in [1, MAX_PAYLOAD]")

        self.sid: Final = sid
        self.window: Final = window
        self.max_payload: Final = max_payload
        self.state = LinkState.ACTIVE
        self._transmit = transmit
        self.diag = Diagnostics()
        self._slots: list[_Slot] = []
        self._base_seq = 0
        self._next_seq = 0
        self._retries = 0
        self._estimator = RtoEstimator()
        self._rto_ms = RTO_INITIAL_MS
        self._timer_running = False
        self._timer_start_ms = 0
        self._nak_goback_used = False
        self._expected_seq = 0

    @property
    def in_flight(self) -> int:
        """Number of DATA frames sent but not yet acknowledged."""

        return len(self._slots)

    def next_timeout(self) -> int | None:
        """Monotonic deadline of the retransmission timer.

        Returns:
            The timestamp at which poll() will act, or None when no DATA
            frame is awaiting acknowledgement or the link is dead.
        """

        if self.state is LinkState.DEAD or not self._timer_running:
            return None
        return self._timer_start_ms + self._rto_ms

    def send(self, payload: bytes, now_ms: int) -> bool:
        """Queue and transmit one DATA frame.

        Args:
            payload: One session message, 1 to max_payload bytes.
            now_ms: Monotonic timestamp of the transmission.

        Returns:
            True when the frame was queued and transmitted; False when the
            send window is full and the caller must wait for progress.

        Raises:
            LinkError: If the link is dead or the payload size is invalid.
        """

        if self.state is LinkState.DEAD:
            raise LinkError("link is dead")
        if not 1 <= len(payload) <= self.max_payload:
            raise LinkError("payload must be 1 to max_payload bytes")
        if len(self._slots) >= self.window:
            return False

        slot = _Slot(seq=self._next_seq, payload=bytes(payload), first_tx_ms=now_ms)
        self._next_seq = (self._next_seq + 1) & 0xFF
        self._slots.append(slot)
        if not self._timer_running:
            self._timer_running = True
            self._timer_start_ms = now_ms
        self._transmit(build_frame(FrameType.DATA, self.sid, slot.seq, 0, slot.payload))
        return True

    def on_frame(self, frame: Frame, now_ms: int) -> list[LinkEvent]:
        """Process one validated frame from the frame parser.

        Args:
            frame: Decoded frame from the peer.
            now_ms: Monotonic timestamp of the frame's arrival.

        Returns:
            Events for the host. Frames for other sessions and frames not
            handled by the link layer are ignored.
        """

        events: list[LinkEvent] = []
        if self.state is LinkState.DEAD:
            return events
        if frame.type in (FrameType.HELLO, FrameType.HELLO_OK):
            return events
        if frame.sid != self.sid:
            self.diag.frames_wrong_sid += 1
            return events

        if frame.type is FrameType.ACK:
            self._on_ack(frame.seq, bool(frame.flags & 0x01), now_ms)
        elif frame.type is FrameType.DATA:
            self._on_data(frame, events)
        elif frame.type is FrameType.ABORT:
            self.state = LinkState.DEAD
            events.append(Aborted(abort_reason_from_byte(frame.payload[0]), from_peer=True))
        return events

    def poll(self, now_ms: int) -> list[LinkEvent]:
        """Run the retransmission timer.

        Args:
            now_ms: Monotonic timestamp.

        Returns:
            An Aborted event when consecutive timeouts exhaust N_RETRY,
            otherwise an empty list. On earlier expiries all unacknowledged
            frames are retransmitted byte-identically and the timeout doubles
            up to RTO_MAX_MS.
        """

        events: list[LinkEvent] = []
        if self.state is LinkState.DEAD or not self._timer_running:
            return events
        if now_ms - self._timer_start_ms < self._rto_ms:
            return events

        self._retries += 1
        if self._retries >= N_RETRY:
            self._abort_local(AbortReason.E_TIMEOUT, events)
            return events

        self._retransmit_all(now_ms)
        self._nak_goback_used = False
        self._rto_ms = min(self._rto_ms * 2, RTO_MAX_MS)
        return events

    def _retransmit_all(self, now_ms: int) -> None:
        """Retransmit every unacknowledged frame and restart the timer."""

        self.diag.frames_retransmitted += len(self._slots)
        for slot in self._slots:
            slot.retransmitted = True
            self._transmit(build_frame(FrameType.DATA, self.sid, slot.seq, 0, slot.payload))
        self._timer_start_ms = now_ms

    def _on_data(self, frame: Frame, events: list[LinkEvent]) -> None:
        """Deliver an in-order DATA frame or reject it with ACK+NAK."""

        if frame.seq == self._expected_seq:
            self._expected_seq = (self._expected_seq + 1) & 0xFF
            self._transmit(build_frame(FrameType.ACK, self.sid, self._expected_seq, 0x00))
            events.append(Delivered(frame.payload))
        else:
            distance = (frame.seq - self._expected_seq) & 0xFF
            self.diag.naks_sent += 1
            if distance < 0x80:
                self.diag.out_of_order_data_received += 1
            else:
                self.diag.duplicate_data_received += 1
            self._transmit(build_frame(FrameType.ACK, self.sid, self._expected_seq, 0x01))

    def _on_ack(self, ack_seq: int, nak: bool, now_ms: int) -> None:
        """Slide the send window and honor a rate-limited NAK go-back."""

        dist = (ack_seq - self._base_seq) & 0xFF
        if 0 < dist <= len(self._slots):
            newest = self._slots[dist - 1]
            if not newest.retransmitted:
                self._estimator.sample(now_ms - newest.first_tx_ms)
                self._rto_ms = self._estimator.rto_ms
            del self._slots[:dist]
            self._base_seq = ack_seq
            self._retries = 0
            self._nak_goback_used = False
            if self._slots:
                self._timer_start_ms = now_ms
            else:
                self._timer_running = False

        if nak and self._slots and not self._nak_goback_used:
            self._nak_goback_used = True
            self._retransmit_all(now_ms)

    def _abort_local(self, reason: AbortReason, events: list[LinkEvent]) -> None:
        """Terminate the session locally with a best-effort ABORT frame."""

        self._transmit(build_frame(FrameType.ABORT, self.sid, 0, 0, bytes([reason])))
        self.state = LinkState.DEAD
        events.append(Aborted(reason, from_peer=False))
