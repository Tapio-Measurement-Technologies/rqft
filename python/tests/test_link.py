# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Go-Back-N link layer tests for SPEC.md sections 4.1, 4.3, and 4.6."""

from __future__ import annotations

import pytest

from rqft.frame import Frame, FrameType, Parser
from rqft.link import (
    N_RETRY,
    Aborted,
    AbortReason,
    Delivered,
    Link,
    LinkError,
    LinkState,
)
from rqft.rto import RTO_INITIAL_MS, RTO_MAX_MS


class WireLog:
    """Transmit sink that records each wire frame and decodes it."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def __call__(self, data: bytes) -> None:
        self.chunks.append(data)

    def frames(self) -> list[Frame]:
        parser = Parser()
        events: list[object] = []
        for chunk in self.chunks:
            events.extend(parser.feed(chunk, now_ms=0))
        assert all(isinstance(event, Frame) for event in events)
        return [event for event in events if isinstance(event, Frame)]


def ack(sid: int, seq: int, nak: bool = False) -> Frame:
    return Frame(FrameType.ACK, sid, seq, 0x01 if nak else 0x00)


def test_config_validation() -> None:
    with pytest.raises(LinkError):
        Link(sid=0, window=4, transmit=WireLog())
    with pytest.raises(LinkError):
        Link(sid=0x42, window=0, transmit=WireLog())
    with pytest.raises(LinkError):
        Link(sid=0x42, window=9, transmit=WireLog())
    with pytest.raises(LinkError):
        Link(sid=0x42, window=4, transmit=WireLog(), max_payload=513)


def test_window_fills_to_w_then_refuses() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)

    for i in range(4):
        assert link.send(bytes([i]), now_ms=0) is True
    assert link.send(b"\x04", now_ms=0) is False

    assert link.in_flight == 4
    assert len(wire.chunks) == 4
    assert [frame.seq for frame in wire.frames()] == [0, 1, 2, 3]
    assert all(frame.type is FrameType.DATA and frame.sid == 0x42 for frame in wire.frames())


def test_cumulative_ack_slides_window() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    for i in range(4):
        link.send(bytes([i]), now_ms=0)

    assert link.on_frame(ack(0x42, 2), now_ms=10) == []
    assert link.in_flight == 2

    assert link.send(b"\x04", now_ms=10) is True
    assert link.send(b"\x05", now_ms=10) is True
    assert link.send(b"\x06", now_ms=10) is False

    link.on_frame(ack(0x42, 6), now_ms=20)
    assert link.in_flight == 0


def test_duplicate_and_stale_acks_ignored() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    for i in range(2):
        link.send(bytes([i]), now_ms=0)

    link.on_frame(ack(0x42, 2), now_ms=10)
    assert link.in_flight == 0

    # Duplicate cumulative ACK and an ACK beyond the window are no-ops.
    link.on_frame(ack(0x42, 2), now_ms=11)
    link.on_frame(ack(0x42, 7), now_ms=12)
    assert link.in_flight == 0
    assert link.state is LinkState.ACTIVE

    # The window still starts where the last progress left it.
    link.send(b"\x02", now_ms=20)
    assert wire.frames()[-1].seq == 2


def test_seq_wraps_255_to_0() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=8, transmit=wire)

    for i in range(300):
        assert link.send(bytes([i & 0xFF]), now_ms=i) is True
        link.on_frame(ack(0x42, (i + 1) & 0xFF), now_ms=i)

    seqs = [frame.seq for frame in wire.frames()]
    assert seqs[254:258] == [254, 255, 0, 1]
    assert seqs == [i & 0xFF for i in range(300)]


def test_wrap_ack_across_boundary() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)

    for i in range(254):
        link.send(b"x", now_ms=0)
        link.on_frame(ack(0x42, (i + 1) & 0xFF), now_ms=0)

    for _ in range(4):
        assert link.send(b"y", now_ms=1) is True
    assert link.in_flight == 4

    # Cumulative ACK 2 covers seq 254, 255, 0, 1 across the wrap.
    link.on_frame(ack(0x42, 2), now_ms=2)
    assert link.in_flight == 0


def test_send_payload_size_validation() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire, max_payload=16)

    with pytest.raises(LinkError):
        link.send(b"", now_ms=0)
    with pytest.raises(LinkError):
        link.send(b"x" * 17, now_ms=0)
    assert link.send(b"x" * 16, now_ms=0) is True


def test_rto_expiry_retransmits_all_unacked_byte_identical() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    for i in range(3):
        link.send(bytes([i]), now_ms=0)
    originals = list(wire.chunks)

    assert link.poll(RTO_INITIAL_MS - 1) == []
    assert wire.chunks == originals

    assert link.poll(RTO_INITIAL_MS) == []
    assert wire.chunks == originals * 2
    assert link.diag.frames_retransmitted == 3


def test_rto_backoff_doubles_then_clamps() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=1, transmit=wire)
    link.send(b"x", now_ms=0)

    # Expiries: 1000 (RTO doubles to 2000), 3000 (clamps to RTO_MAX),
    # then every RTO_MAX ms.
    for expiry in (1000, 3000, 6000, 9000):
        before = len(wire.chunks)
        assert link.poll(expiry - 1) == []
        assert len(wire.chunks) == before
        link.poll(expiry)
        assert len(wire.chunks) == before + 1

    assert RTO_MAX_MS == 3000


def test_retry_exhaustion_aborts() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"x", now_ms=0)

    events: list[object] = []
    now = 0
    while not events and now < 60_000:
        now += 100
        events.extend(link.poll(now))

    assert events == [Aborted(AbortReason.E_TIMEOUT, from_peer=False)]
    assert link.state is LinkState.DEAD
    # Original + (N_RETRY - 1) retransmissions + final ABORT frame.
    assert len(wire.chunks) == 1 + (N_RETRY - 1) + 1
    frames = wire.frames()
    assert frames[-1].type is FrameType.ABORT
    assert frames[-1].payload == bytes([AbortReason.E_TIMEOUT])
    assert all(frame.type is FrameType.DATA and frame.seq == 0 for frame in frames[:-1])
    # The abort fires at 1000 + 2000 + 6 * 3000 = 21000 ms.
    assert now == 21_000

    with pytest.raises(LinkError):
        link.send(b"y", now_ms=now)
    assert link.poll(now + 10_000) == []
    assert link.on_frame(ack(0x42, 1), now_ms=now) == []


def test_progress_resets_retry_counter() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)
    link.send(b"b", now_ms=0)

    link.poll(1000)
    link.poll(3000)
    link.poll(6000)

    # Progress on the first frame resets the counter: 8 further expiries
    # are needed before the link gives up.
    link.on_frame(ack(0x42, 1), now_ms=6100)

    events: list[object] = []
    expiries = 0
    now = 6100
    while not events and now < 60_000:
        now += 100
        before = len(wire.chunks)
        events.extend(link.poll(now))
        if len(wire.chunks) != before:
            expiries += 1

    assert events == [Aborted(AbortReason.E_TIMEOUT, from_peer=False)]
    assert expiries == N_RETRY  # N_RETRY - 1 retransmissions + the ABORT frame


def test_timer_restarts_on_progress() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)
    link.send(b"b", now_ms=200)

    # The ACK also samples RTT=500 (srtt=500, rttvar=250, RTO=1500).
    link.on_frame(ack(0x42, 1), now_ms=500)

    # Without a restart the timer would fire at 0+1500; restarted at 500 it
    # fires at 2000 with only the second frame outstanding.
    assert link.poll(1999) == []
    assert len(wire.chunks) == 2
    link.poll(2000)
    assert len(wire.chunks) == 3
    assert wire.frames()[-1].seq == 1


def test_timer_stops_when_window_empties() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)
    link.on_frame(ack(0x42, 1), now_ms=100)

    assert link.poll(50_000) == []
    assert len(wire.chunks) == 1
    assert link.state is LinkState.ACTIVE


def test_nak_triggers_goback_retransmit_byte_identical() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    for i in range(3):
        link.send(bytes([i]), now_ms=0)
    originals = list(wire.chunks)

    assert link.on_frame(ack(0x42, 0, nak=True), now_ms=100) == []

    assert wire.chunks == originals * 2
    assert link.in_flight == 3
    assert link.diag.frames_retransmitted == 3


def test_nak_goback_rate_limited_to_one_per_flight() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    for i in range(3):
        link.send(bytes([i]), now_ms=0)

    link.on_frame(ack(0x42, 0, nak=True), now_ms=100)
    sent_after_goback = len(wire.chunks)

    # Further NAKs with the same cumulative point are ignored.
    link.on_frame(ack(0x42, 0, nak=True), now_ms=110)
    link.on_frame(ack(0x42, 0, nak=True), now_ms=120)
    assert len(wire.chunks) == sent_after_goback


def test_progress_rearms_nak_goback() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    for i in range(3):
        link.send(bytes([i]), now_ms=0)

    link.on_frame(ack(0x42, 0, nak=True), now_ms=100)

    # A NAK that also acknowledges progress slides the window first and
    # then goes back on the remaining frames.
    link.on_frame(ack(0x42, 1, nak=True), now_ms=200)

    assert link.in_flight == 2
    assert [frame.seq for frame in wire.frames()] == [0, 1, 2, 0, 1, 2, 1, 2]


def test_rto_expiry_rearms_nak_goback() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)

    link.on_frame(ack(0x42, 0, nak=True), now_ms=100)  # go-back, now used
    link.on_frame(ack(0x42, 0, nak=True), now_ms=200)  # rate-limited
    assert len(wire.chunks) == 2

    link.poll(1100)  # RTO expiry retransmits and re-arms the go-back
    assert len(wire.chunks) == 3

    link.on_frame(ack(0x42, 0, nak=True), now_ms=1200)
    assert len(wire.chunks) == 4


def test_nak_goback_restarts_timer() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)

    link.on_frame(ack(0x42, 0, nak=True), now_ms=500)
    assert len(wire.chunks) == 2

    assert link.poll(1499) == []
    assert len(wire.chunks) == 2
    link.poll(1500)
    assert len(wire.chunks) == 3


def test_nak_with_empty_window_ignored() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)
    link.on_frame(ack(0x42, 1), now_ms=100)

    assert link.on_frame(ack(0x42, 1, nak=True), now_ms=200) == []
    assert len(wire.chunks) == 1
    assert link.state is LinkState.ACTIVE


def test_ack_rtt_sample_adapts_rto() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)
    link.send(b"b", now_ms=0)

    # ACK covering the first frame at t=500 gives a 500 ms sample:
    # srtt=500, rttvar=250, RTO=1500. The restarted timer fires at 2000.
    link.on_frame(ack(0x42, 1), now_ms=500)

    assert link.poll(1999) == []
    assert len(wire.chunks) == 2
    link.poll(2000)
    assert len(wire.chunks) == 3


def test_rtt_sample_taken_from_newest_covered_frame() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)
    link.send(b"b", now_ms=400)

    # The cumulative ACK is triggered by the newest frame it covers, so the
    # sample is 100 ms (frame b), not 500 ms: srtt=100, rttvar=50, RTO=300.
    link.on_frame(ack(0x42, 2), now_ms=500)

    link.send(b"c", now_ms=600)
    assert link.poll(899) == []
    assert len(wire.chunks) == 3
    link.poll(900)
    assert len(wire.chunks) == 4


def test_karn_no_sample_from_retransmitted_frame() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)
    link.poll(1000)  # retransmit; RTO backs off to 2000

    # The covering ACK arrives after a retransmission: ambiguous timing,
    # no sample, and the backed-off RTO stays until a clean sample.
    link.on_frame(ack(0x42, 1), now_ms=1500)

    link.send(b"b", now_ms=1600)
    assert link.poll(3599) == []
    assert len(wire.chunks) == 3
    link.poll(3600)
    assert len(wire.chunks) == 4


def test_clean_sample_reverts_backoff() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"a", now_ms=0)
    link.poll(1000)  # retransmit; RTO backs off to 2000
    link.on_frame(ack(0x42, 1), now_ms=1200)  # retransmitted: no sample

    # A never-retransmitted frame gives a clean 300 ms sample:
    # srtt=300, rttvar=150, RTO=900 replaces the backed-off 2000.
    link.send(b"b", now_ms=1300)
    link.on_frame(ack(0x42, 2), now_ms=1600)

    link.send(b"c", now_ms=1700)
    assert link.poll(2599) == []
    assert len(wire.chunks) == 4
    link.poll(2600)
    assert len(wire.chunks) == 5


def data(sid: int, seq: int, payload: bytes) -> Frame:
    return Frame(FrameType.DATA, sid, seq, 0, payload)


def test_in_order_delivery_and_ack() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)

    assert link.on_frame(data(0x42, 0, b"one"), now_ms=10) == [Delivered(b"one")]
    assert link.on_frame(data(0x42, 1, b"two"), now_ms=20) == [Delivered(b"two")]

    acks = wire.frames()
    assert [(frame.type, frame.seq, frame.flags) for frame in acks] == [
        (FrameType.ACK, 1, 0),
        (FrameType.ACK, 2, 0),
    ]


def test_duplicate_data_acked_with_nak_no_redelivery() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.on_frame(data(0x42, 0, b"one"), now_ms=10)

    assert link.on_frame(data(0x42, 0, b"one"), now_ms=20) == []

    acks = wire.frames()
    assert (acks[-1].type, acks[-1].seq, acks[-1].flags) == (FrameType.ACK, 1, 1)
    assert link.diag.naks_sent == 1
    assert link.diag.duplicate_data_received == 1
    assert link.diag.out_of_order_data_received == 0


def test_gap_acked_with_nak() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.on_frame(data(0x42, 0, b"one"), now_ms=10)

    assert link.on_frame(data(0x42, 2, b"three"), now_ms=20) == []

    acks = wire.frames()
    assert (acks[-1].type, acks[-1].seq, acks[-1].flags) == (FrameType.ACK, 1, 1)
    assert link.diag.naks_sent == 1
    assert link.diag.duplicate_data_received == 0
    assert link.diag.out_of_order_data_received == 1

    # The in-order frame is still accepted afterwards.
    assert link.on_frame(data(0x42, 1, b"two"), now_ms=30) == [Delivered(b"two")]


def test_wrong_sid_frames_dropped_and_counted() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"x", now_ms=0)

    assert link.on_frame(data(0x43, 0, b"stale"), now_ms=10) == []
    assert link.on_frame(ack(0x43, 1), now_ms=10) == []
    assert link.on_frame(Frame(FrameType.ABORT, 0x43, 0, 0, b"\x02"), now_ms=10) == []

    assert link.diag.frames_wrong_sid == 3
    assert link.in_flight == 1
    assert link.state is LinkState.ACTIVE
    assert len(wire.chunks) == 1  # no ACK replies to stale frames

    # HELLO frames belong to the session layer and are not counted here.
    assert link.on_frame(Frame(FrameType.HELLO, 0x99, 0, 0, bytes(8)), now_ms=10) == []
    assert link.diag.frames_wrong_sid == 3


def test_peer_abort_ends_session_immediately() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)
    link.send(b"x", now_ms=0)

    events = link.on_frame(
        Frame(FrameType.ABORT, 0x42, 0, 0, bytes([AbortReason.E_USER])), now_ms=10
    )

    assert events == [Aborted(AbortReason.E_USER, from_peer=True)]
    assert link.state is LinkState.DEAD
    assert len(wire.chunks) == 1  # no reply to an ABORT

    assert link.on_frame(data(0x42, 0, b"late"), now_ms=20) == []
    assert link.poll(50_000) == []
    with pytest.raises(LinkError):
        link.send(b"y", now_ms=20)


def test_unknown_abort_reason_maps_to_e_proto() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)

    events = link.on_frame(Frame(FrameType.ABORT, 0x42, 0, 0, b"\x77"), now_ms=10)

    assert events == [Aborted(AbortReason.E_PROTO, from_peer=True)]
    assert link.state is LinkState.DEAD


def test_receive_seq_wraps_255_to_0() -> None:
    wire = WireLog()
    link = Link(sid=0x42, window=4, transmit=wire)

    for i in range(300):
        events = link.on_frame(data(0x42, i & 0xFF, bytes([i & 0xFF])), now_ms=i)
        assert events == [Delivered(bytes([i & 0xFF]))]

    acks = wire.frames()
    assert [frame.seq for frame in acks[253:258]] == [254, 255, 0, 1, 2]
