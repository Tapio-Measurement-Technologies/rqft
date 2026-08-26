# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Parser fuzz invariants for SPEC.md section 3.5."""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from rqft.frame import Frame, FrameType, Parser, build_frame


VALID_ACK = build_frame(FrameType.ACK, 0x42, 8, 0)


@settings(max_examples=150, deadline=None)
@given(st.lists(st.binary(min_size=0, max_size=64), min_size=0, max_size=64))
def test_parser_fuzz_invariants(chunks: list[bytes]) -> None:
    parser = Parser()
    ack = Frame(FrameType.ACK, 0x42, 8, 0, b"")
    ack_count = 0

    for now_ms, chunk in enumerate(chunks):
        for event in parser.feed(chunk, now_ms=now_ms):
            if isinstance(event, Frame):
                build_frame(event.type, event.sid, event.seq, event.flags, event.payload)
                if event == ack:
                    ack_count += 1
        parser.flush_idle(now_ms)

    before = ack_count
    for index, byte in enumerate(VALID_ACK):
        for event in parser.feed(bytes([byte]), now_ms=len(chunks) + index):
            if isinstance(event, Frame):
                build_frame(event.type, event.sid, event.seq, event.flags, event.payload)
                if event == ack:
                    ack_count += 1

    assert ack_count > before
