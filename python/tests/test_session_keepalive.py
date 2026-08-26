# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Keepalive and idle-death tests for SPEC.md section 4.5."""

from __future__ import annotations

import pytest

from fakefs import FakeFs
from rqft.events import Ended
from rqft.frame import Frame, FrameType, Parser, build_frame
from rqft.link import AbortReason
from rqft.messages import FileData, Message, Ping, Pong, PutReq, Role, decode_message
from rqft.session import Session, SessionState, T_DEAD_MS, T_PING_MS

SID = 0x42


def pair() -> tuple[Session, Session]:
    """Establish a controller/responder pair over a perfect line."""

    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID)
    resp = Session(Role.RESPONDER)
    ctrl.start(now_ms=0)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=0)
    events = ctrl.receive_bytes(resp.data_to_send(), now_ms=0)
    assert events and ctrl.session_active and resp.session_active
    return ctrl, resp


def data_frame(seq: int, payload: bytes) -> bytes:
    return build_frame(FrameType.DATA, SID, seq, 0, payload)


def sent_messages(wire: bytes) -> list[Message]:
    """Decode every DATA frame payload in one wire capture."""

    parser = Parser()
    return [
        decode_message(event.payload)
        for event in parser.feed(wire, now_ms=0)
        if isinstance(event, Frame) and event.type is FrameType.DATA
    ]


def test_ping_pong_token_echo_both_roles() -> None:
    ctrl, resp = pair()

    resp.receive_bytes(data_frame(0, Ping(0xDEADBEEF).encode()), now_ms=10)
    assert sent_messages(resp.data_to_send()) == [Pong(0xDEADBEEF)]

    ctrl.receive_bytes(data_frame(0, Ping(41).encode()), now_ms=10)
    assert sent_messages(ctrl.data_to_send()) == [Pong(41)]

    assert ctrl.session_active and resp.session_active


def test_controller_pings_after_t_ping_of_silence() -> None:
    ctrl, resp = pair()

    assert ctrl.handle_timeout(now_ms=T_PING_MS - 1) == []
    assert ctrl.data_to_send() == b""

    ctrl.handle_timeout(now_ms=T_PING_MS)
    wire = ctrl.data_to_send()
    assert sent_messages(wire) == [Ping(1)]

    # The exchange makes both directions quiet again; the next silence
    # window ends with the next token.
    resp.receive_bytes(wire, now_ms=T_PING_MS)
    ctrl.receive_bytes(resp.data_to_send(), now_ms=T_PING_MS)
    ctrl.handle_timeout(now_ms=2 * T_PING_MS)
    assert sent_messages(ctrl.data_to_send()) == [Ping(2)]


def test_any_transmission_defers_the_ping() -> None:
    ctrl, resp = pair()

    # A PLAN at 1500 restarts the silence window: no ping at 2000. The
    # PLAN is ACKed so no retransmission timer interferes.
    ctrl.send_plan(nfiles=1, nbytes=1, now_ms=1500)
    ctrl.data_to_send()
    ctrl.receive_bytes(build_frame(FrameType.ACK, SID, 1, 0, b""), now_ms=1500)
    ctrl.handle_timeout(now_ms=T_PING_MS)
    assert sent_messages(ctrl.data_to_send()) == []

    ctrl.handle_timeout(now_ms=1500 + T_PING_MS)
    assert sent_messages(ctrl.data_to_send()) == [Ping(1)]


def test_responder_never_auto_pings() -> None:
    ctrl, resp = pair()

    assert resp.handle_timeout(now_ms=3 * T_PING_MS) == []
    assert resp.data_to_send() == b""


def test_no_auto_ping_while_operation_in_flight() -> None:
    ctrl, resp = pair()

    ctrl.request_del("a.data", is_dir=False, now_ms=0)
    ctrl.data_to_send()
    # ACK the request so no retransmission timer interferes; the DEL
    # reply itself never arrives, keeping the operation in flight.
    ctrl.receive_bytes(build_frame(FrameType.ACK, SID, 1, 0, b""), now_ms=5)

    assert ctrl.handle_timeout(now_ms=T_PING_MS) == []
    assert ctrl.data_to_send() == b""


def test_next_timeout_includes_ping_deadline() -> None:
    ctrl, resp = pair()
    assert ctrl.next_timeout() == T_PING_MS


def last_frame_is_abort(wire: bytes, reason: AbortReason) -> bool:
    """Whether the final frame of a wire capture is ABORT(reason)."""

    frames = [e for e in Parser().feed(wire, now_ms=0) if isinstance(e, Frame)]
    return (
        bool(frames)
        and frames[-1].type is FrameType.ABORT
        and frames[-1].payload == bytes([reason])
    )


@pytest.mark.parametrize("role", [Role.CONTROLLER, Role.RESPONDER])
def test_t_dead_kills_a_silent_session_in_both_roles(role: Role) -> None:
    ctrl, resp = pair()
    session = ctrl if role is Role.CONTROLLER else resp

    events = session.handle_timeout(now_ms=T_DEAD_MS)

    assert events == [Ended(AbortReason.E_TIMEOUT, from_peer=False)]
    assert session.state is SessionState.ENDED
    assert last_frame_is_abort(session.data_to_send(), AbortReason.E_TIMEOUT)


def test_valid_in_session_frame_resets_t_dead() -> None:
    ctrl, resp = pair()

    resp.receive_bytes(data_frame(0, Ping(1).encode()), now_ms=9000)
    resp.data_to_send()

    assert resp.handle_timeout(now_ms=T_DEAD_MS) == []
    assert resp.session_active

    events = resp.handle_timeout(now_ms=9000 + T_DEAD_MS)
    assert events == [Ended(AbortReason.E_TIMEOUT, from_peer=False)]


def test_wrong_sid_frames_do_not_reset_t_dead() -> None:
    ctrl, resp = pair()

    stale = build_frame(FrameType.DATA, SID + 1, 0, 0, Ping(1).encode())
    resp.receive_bytes(stale, now_ms=9000)

    events = resp.handle_timeout(now_ms=T_DEAD_MS)
    assert events == [Ended(AbortReason.E_TIMEOUT, from_peer=False)]


def test_keepalive_pings_hold_off_peer_t_dead() -> None:
    # An idle but healthy pair outlives T_DEAD: the controller's pings
    # and their PONG/ACK answers keep both receive clocks fresh.
    ctrl, resp = pair()

    for now_ms in range(T_PING_MS, 6 * T_PING_MS + 1, T_PING_MS):
        ctrl.handle_timeout(now_ms)
        resp.receive_bytes(ctrl.data_to_send(), now_ms)
        resp.handle_timeout(now_ms)
        ctrl.receive_bytes(resp.data_to_send(), now_ms)

    assert ctrl.session_active and resp.session_active


def test_t_dead_mid_put_discards_responder_temp() -> None:
    resp_fs = FakeFs()
    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID)
    resp = Session(Role.RESPONDER, fs=resp_fs)
    ctrl.start(now_ms=0)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=0)
    ctrl.receive_bytes(resp.data_to_send(), now_ms=0)

    resp.receive_bytes(data_frame(0, PutReq(9, 0, b"f.bin").encode()), now_ms=0)
    resp.receive_bytes(data_frame(1, FileData(b"abc").encode()), now_ms=0)
    assert resp_fs.writing

    events = resp.handle_timeout(now_ms=T_DEAD_MS)

    assert events == [Ended(AbortReason.E_TIMEOUT, from_peer=False)]
    assert not resp_fs.writing
    assert resp_fs.discarded == 1


def test_next_timeout_includes_t_dead_deadline() -> None:
    ctrl, resp = pair()
    assert resp.next_timeout() == T_DEAD_MS
