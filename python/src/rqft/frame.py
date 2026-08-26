# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Frame codec and resynchronizing parser for SPEC.md section 3."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Final, Optional, Union

from rqft import MAX_ENCODED, MAX_PAYLOAD
from rqft.cobs import CobsError, decode as cobs_decode, encode as cobs_encode
from rqft.crc32 import crc32

# Idle milliseconds before a partial candidate is emitted as passthrough.
T_FLUSH_MS: Final = 50


class FrameError(ValueError):
    """Raised when frame fields cannot be encoded."""


class FrameType(IntEnum):
    """Frame type values from SPEC.md section 3.3."""

    HELLO = 0x01
    HELLO_OK = 0x02
    DATA = 0x03
    ACK = 0x04
    ABORT = 0x05


class ParserState(Enum):
    """Parser states from SPEC.md section 3.5."""

    HUNT = "HUNT"
    FRAME = "FRAME"


@dataclass(frozen=True)
class Frame:
    """Decoded and validated RQFT frame.

    Attributes:
        type: Frame type.
        sid: Non-zero session id.
        seq: Sequence or acknowledgement byte.
        flags: Frame flags. Only ACK bit 0 is currently defined.
        payload: Frame payload bytes.
    """

    type: FrameType
    sid: int
    seq: int
    flags: int
    payload: bytes = b""


@dataclass(frozen=True)
class Passthrough:
    """Foreign bytes emitted while parser is outside a valid frame.

    Attributes:
        data: Bytes delivered to the host text protocol.
    """

    data: bytes


# Parser event type emitted by feed() and flush_idle().
Event = Union[Frame, Passthrough]


@dataclass
class Diagnostics:
    """Frame parser diagnostic counters.

    Attributes:
        frames_ok: Valid frames delivered to the caller.
        frames_crc_fail: Candidates rejected by COBS decode, length, or CRC.
        frames_oversize: Candidates flushed after exceeding MAX_ENCODED.
        frames_dropped: CRC-valid frames dropped for bad shape.
        candidates_idle_flushed: Unterminated candidates discarded after T_FLUSH.
        valid_candidates_idle_flushed: Idle-flushed candidates that passed
            COBS, minimum-length, and CRC checks despite missing a delimiter.
        bytes_idle_flushed: Encoded candidate bytes discarded after T_FLUSH.
        bytes_passthrough: Foreign bytes delivered while no session is active.
        bytes_dropped_in_session: Foreign bytes dropped during an active session.
    """

    frames_ok: int = 0
    frames_crc_fail: int = 0
    frames_oversize: int = 0
    frames_dropped: int = 0
    candidates_idle_flushed: int = 0
    valid_candidates_idle_flushed: int = 0
    bytes_idle_flushed: int = 0
    bytes_passthrough: int = 0
    bytes_dropped_in_session: int = 0


def _u32_le(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _valid_shape(ftype: int, sid: int, flags: int, payload_len: int) -> bool:
    if sid == 0:
        return False
    if ftype == FrameType.HELLO:
        return flags == 0 and payload_len == 8
    if ftype == FrameType.HELLO_OK:
        return flags == 0 and payload_len == 8
    if ftype == FrameType.DATA:
        return flags == 0 and payload_len >= 1
    if ftype == FrameType.ACK:
        return flags & ~0x01 == 0 and payload_len == 0
    if ftype == FrameType.ABORT:
        return flags == 0 and payload_len == 1
    return False


def build_frame(
    ftype: FrameType,
    sid: int,
    seq: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    """Build a complete 0x00-delimited wire frame.

    Args:
        ftype: Frame type.
        sid: Non-zero session id.
        seq: Sequence or acknowledgement byte.
        flags: Frame flags; reserved bits must be zero.
        payload: Frame payload bytes.

    Returns:
        Leading delimiter, COBS body, and trailing delimiter.

    Raises:
        FrameError: If type, sid, flags, or payload length violate the spec.
    """

    if len(payload) > MAX_PAYLOAD or not _valid_shape(ftype, sid, flags, len(payload)):
        raise FrameError("invalid frame shape")

    body = bytes([ftype, sid, seq, flags]) + payload
    decoded = body + _u32_le(crc32(body))
    encoded = cobs_encode(decoded)
    return b"\x00" + encoded + b"\x00"


@dataclass
class Parser:
    """Resynchronizing frame parser.

    Attributes:
        max_payload: Maximum decoded payload accepted.
        state: Current parser state.
        session_active: Whether passthrough bytes are dropped as session noise.
        candidate: Current encoded frame candidate.
        last_byte_ms: Monotonic timestamp of the last candidate byte.
        diag: Diagnostic counters.
    """

    max_payload: int = MAX_PAYLOAD
    state: ParserState = ParserState.HUNT
    session_active: bool = False
    candidate: bytearray = field(default_factory=bytearray)
    last_byte_ms: int = 0
    diag: Diagnostics = field(default_factory=Diagnostics)

    def feed(self, data: bytes, now_ms: int) -> list[Event]:
        """Feed bytes into the parser.

        Args:
            data: Input bytes from the transport.
            now_ms: Monotonic timestamp for idle-flush tracking.

        Returns:
            Frame and passthrough events emitted by this chunk.

        Malformed candidates are counted and resynchronized instead of raised.
        """

        events: list[Event] = []
        for byte in data:
            if self.state is ParserState.HUNT:
                if byte == 0:
                    self.state = ParserState.FRAME
                    self.candidate.clear()
                else:
                    self._passthrough(bytes([byte]), events)
                continue

            if byte == 0:
                if self.candidate:
                    self._process_candidate(events)
                continue

            self.candidate.append(byte)
            self.last_byte_ms = now_ms
            if len(self.candidate) > MAX_ENCODED:
                self.diag.frames_oversize += 1
                self._passthrough(bytes(self.candidate), events)
                self.candidate.clear()
                self.state = ParserState.HUNT

        return events

    def flush_idle(self, now_ms: int) -> list[Event]:
        """Flush an inactive-session partial candidate after the idle timeout.

        Active sessions retain candidates across transport gaps. Delimiters
        and the encoded-size bound provide framing resynchronization without
        mistaking a slow frame for passthrough bytes.

        Args:
            now_ms: Monotonic timestamp.

        Returns:
            A passthrough event when a partial candidate timed out, otherwise
            an empty list.
        """

        events: list[Event] = []
        if (
            self.state is ParserState.FRAME
            and self.candidate
            and not self.session_active
            and now_ms - self.last_byte_ms >= T_FLUSH_MS
        ):
            self.diag.candidates_idle_flushed += 1
            self.diag.bytes_idle_flushed += len(self.candidate)
            if self._decode_candidate() is not None:
                self.diag.valid_candidates_idle_flushed += 1
            self._passthrough(bytes(self.candidate), events)
            self.candidate.clear()
            self.state = ParserState.HUNT
        return events

    def _passthrough(self, data: bytes, events: list[Event]) -> None:
        if not data:
            return
        if self.session_active:
            self.diag.bytes_dropped_in_session += len(data)
            return
        self.diag.bytes_passthrough += len(data)
        events.append(Passthrough(data))

    def _process_candidate(self, events: list[Event]) -> None:
        decoded = self._decode_candidate()
        if decoded is None:
            self.diag.frames_crc_fail += 1
            self._passthrough(bytes(self.candidate), events)
            self.candidate.clear()
            return

        body = decoded[:-4]
        payload = body[4:]
        ftype = body[0]
        if len(payload) > self.max_payload or not _valid_shape(ftype, body[1], body[3], len(payload)):
            self.diag.frames_dropped += 1
            self.candidate.clear()
            return

        self.diag.frames_ok += 1
        events.append(Frame(FrameType(ftype), body[1], body[2], body[3], payload))
        self.candidate.clear()

    def _decode_candidate(self) -> Optional[bytes]:
        """Decode and CRC-check current candidate without changing state."""

        try:
            decoded = cobs_decode(bytes(self.candidate))
        except CobsError:
            return None

        if len(decoded) < 8:
            return None

        body = decoded[:-4]
        expected_crc = int.from_bytes(decoded[-4:], "little")
        if crc32(body) != expected_crc:
            return None
        return decoded
