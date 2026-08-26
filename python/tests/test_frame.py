# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Frame codec and parser tests for SPEC.md section 3."""

from __future__ import annotations

import json
from pathlib import Path

from rqft.cobs import encode as cobs_encode
from rqft.crc32 import crc32
from rqft.frame import Frame, FrameType, Parser, ParserState, Passthrough, build_frame


ROOT = Path(__file__).resolve().parents[2]


def _vectors() -> list[dict[str, object]]:
    vectors: list[dict[str, object]] = json.loads(
        (ROOT / "testvectors" / "frames.json").read_text()
    )
    return vectors


def _int(value: object) -> int:
    assert isinstance(value, int)
    return value


def _raw_wire(ftype: int, sid: int, seq: int, flags: int, payload: bytes) -> bytes:
    body = bytes([ftype, sid, seq, flags]) + payload
    decoded = body + crc32(body).to_bytes(4, "little")
    return b"\x00" + cobs_encode(decoded) + b"\x00"


def test_frame_vectors() -> None:
    for vector in _vectors():
        payload = bytes.fromhex(str(vector["payload_hex"]))
        encoded = bytes.fromhex(str(vector["encoded_hex"]))
        assert (
            build_frame(
                FrameType(_int(vector["ftype"])),
                _int(vector["sid"]),
                _int(vector["seq"]),
                _int(vector["flags"]),
                payload,
            )
            == encoded
        )

        parser = Parser()
        events = []
        for byte in encoded:
            events.extend(parser.feed(bytes([byte]), now_ms=1))
        assert events == [
            Frame(
                FrameType(_int(vector["ftype"])),
                _int(vector["sid"]),
                _int(vector["seq"]),
                _int(vector["flags"]),
                payload,
            )
        ]


def test_parser_passthrough_before_frame() -> None:
    frame = build_frame(FrameType.ACK, 0x42, 8, 0)
    parser = Parser()
    text = b"STATUS?\r\n"

    events = parser.feed(text + frame, now_ms=10)

    assert b"".join(event.data for event in events if isinstance(event, Passthrough)) == text
    assert [event for event in events if isinstance(event, Frame)] == [Frame(FrameType.ACK, 0x42, 8, 0)]
    assert parser.diag.bytes_passthrough == len(text)
    assert parser.diag.frames_ok == 1


def test_parser_resyncs_after_junk_inside_frame() -> None:
    good = build_frame(FrameType.ACK, 0x42, 8, 0)
    corrupted = good[:-1] + b"JUNK" + good[-1:]
    parser = Parser()

    events = parser.feed(corrupted + good, now_ms=20)

    assert parser.diag.frames_crc_fail == 1
    assert [event for event in events if isinstance(event, Frame)] == [Frame(FrameType.ACK, 0x42, 8, 0)]
    assert any(isinstance(event, Passthrough) and b"JUNK" in event.data for event in events)


def test_parser_repeated_delimiters() -> None:
    frame = build_frame(FrameType.ABORT, 0x42, 0, 0, b"\x02")
    parser = Parser()

    events = parser.feed(b"\x00\x00" + frame, now_ms=30)

    assert events == [Frame(FrameType.ABORT, 0x42, 0, 0, b"\x02")]
    assert parser.diag.bytes_passthrough == 0


def test_parser_oversize_flushes_to_hunt() -> None:
    parser = Parser()
    good = build_frame(FrameType.ACK, 0x42, 8, 0)

    events = parser.feed(b"\x00" + (b"\x11" * 524) + good, now_ms=40)

    assert parser.diag.frames_oversize == 1
    assert parser.state is ParserState.FRAME
    assert any(isinstance(event, Passthrough) and len(event.data) == 524 for event in events)
    assert [event for event in events if isinstance(event, Frame)] == [Frame(FrameType.ACK, 0x42, 8, 0)]


def test_parser_idle_flush() -> None:
    parser = Parser()
    assert parser.feed(b"\x00abc", now_ms=100) == []
    assert parser.flush_idle(149) == []

    events = parser.flush_idle(150)

    assert events == [Passthrough(b"abc")]
    assert parser.state is ParserState.HUNT
    assert parser.diag.candidates_idle_flushed == 1
    assert parser.diag.valid_candidates_idle_flushed == 0
    assert parser.diag.bytes_idle_flushed == 3


def test_parser_diagnoses_valid_candidate_missing_trailing_delimiter() -> None:
    wire = build_frame(FrameType.DATA, 0x42, 7, 0, b"\x22payload")
    parser = Parser()

    assert parser.feed(wire[:-1], now_ms=100) == []
    assert parser.flush_idle(150) == [Passthrough(wire[1:-1])]

    assert parser.diag.candidates_idle_flushed == 1
    assert parser.diag.valid_candidates_idle_flushed == 1
    assert parser.diag.bytes_idle_flushed == len(wire) - 2
    assert parser.diag.bytes_passthrough == len(wire) - 2


def test_active_parser_keeps_candidate_across_idle_gap() -> None:
    wire = build_frame(FrameType.DATA, 0x42, 7, 0, b"\x22payload")
    parser = Parser(session_active=True)

    assert parser.feed(wire[:-1], now_ms=100) == []
    assert parser.flush_idle(150) == []
    assert parser.feed(wire[-1:], now_ms=151) == [
        Frame(FrameType.DATA, 0x42, 7, 0, b"\x22payload")
    ]

    assert parser.diag.candidates_idle_flushed == 0
    assert parser.diag.bytes_idle_flushed == 0
    assert parser.diag.bytes_dropped_in_session == 0


def test_parser_wrong_crc_and_unknown_type_counters() -> None:
    parser = Parser()
    good = build_frame(FrameType.ACK, 0x42, 8, 0)
    bad_crc = good[:-3] + bytes([good[-3] ^ 0x55]) + good[-2:]
    unknown = _raw_wire(0x99, 0x42, 0, 0, b"")

    events = parser.feed(bad_crc + unknown, now_ms=200)

    assert not [event for event in events if isinstance(event, Frame)]
    assert parser.diag.frames_crc_fail == 1
    assert parser.diag.frames_dropped == 1


def test_session_active_drops_passthrough() -> None:
    parser = Parser(session_active=True)

    assert parser.feed(b"text", now_ms=1) == []

    assert parser.diag.bytes_passthrough == 0
    assert parser.diag.bytes_dropped_in_session == 4
