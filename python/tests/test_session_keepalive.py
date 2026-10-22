# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Keepalive and idle-death tests for SPEC.md section 4.5."""

from __future__ import annotations

from typing import Optional

import pytest

from fakefs import FakeFs
from rqft.crc32 import crc32
from rqft.events import Ended, EntryListed, ListDone, OpFailed, PutDone, SessionEvent
from rqft.frame import Frame, FrameType, Parser, build_frame
from rqft.link import AbortReason
from rqft.messages import (
    FileData,
    FileEnd,
    Message,
    Ping,
    Pong,
    PutOk,
    PutReq,
    Role,
    decode_message,
)
from rqft.session import CRC_BUDGET_PER_POLL, Session, SessionState, T_DEAD_MS, T_PING_MS

SID = 0x42


def pair(
    ctrl_fs: Optional[FakeFs] = None, resp_fs: Optional[FakeFs] = None
) -> tuple[Session, Session]:
    """Establish a controller/responder pair over a perfect line."""

    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID, fs=ctrl_fs)
    resp = Session(Role.RESPONDER, fs=resp_fs)
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


def start_request(ctrl: Session, request_kind: str) -> None:
    """Leave the controller awaiting the reply to one request.

    The request frame is ACKed at once so no retransmission timer
    interferes; the reply itself never arrives. For "put" the caller
    has already called request_put() on a file that hashes in one
    poll, so PUT_REQ goes out here and PUT_OK is awaited.
    """

    if request_kind == "list":
        ctrl.request_list("", want_crc=True, now_ms=0)
    elif request_kind == "del":
        ctrl.request_del("a.data", is_dir=False, now_ms=0)
    elif request_kind == "get":
        ctrl.request_get("a.data", now_ms=0)
    else:
        ctrl.handle_timeout(now_ms=0)
    ctrl.data_to_send()
    ctrl.receive_bytes(build_frame(FrameType.ACK, SID, 1, 0, b""), now_ms=0)


@pytest.mark.parametrize("request_kind", ["list", "del"])
def test_controller_pings_while_awaiting_list_or_del(request_kind: str) -> None:
    # A responder hashing a large file for LIST want_crc sends nothing
    # until the entry is ready; only the keepalive keeps both sides
    # short of T_DEAD (SPEC.md section 4.5).
    ctrl, resp = pair()
    start_request(ctrl, request_kind)

    assert ctrl.next_timeout() == T_PING_MS
    ctrl.handle_timeout(now_ms=T_PING_MS)
    assert sent_messages(ctrl.data_to_send()) == [Ping(1)]


@pytest.mark.parametrize("request_kind", ["get", "put"])
def test_no_ping_once_a_file_stream_may_be_open(request_kind: str) -> None:
    # After GET_REQ the responder may already be streaming FILE_DATA,
    # and after PUT_REQ it treats anything but FILE_DATA, FILE_END or
    # ERR as fatal (SPEC.md section 5.3).
    ctrl, resp = pair(ctrl_fs=FakeFs({"up.bin": b"x" * 100}))
    if request_kind == "put":
        ctrl.request_put("up.bin", now_ms=0)
    start_request(ctrl, request_kind)

    assert ctrl.next_timeout() == T_DEAD_MS
    assert ctrl.handle_timeout(now_ms=T_PING_MS) == []
    assert ctrl.data_to_send() == b""


def test_controller_pings_while_hashing_put_source() -> None:
    ctrl, resp = pair(ctrl_fs=FakeFs({"up.bin": b"x" * (4 * CRC_BUDGET_PER_POLL)}))
    ctrl.request_put("up.bin", now_ms=0)

    ctrl.handle_timeout(now_ms=T_PING_MS)

    # The PING goes out ahead of PUT_REQ, which waits for the hash.
    assert sent_messages(ctrl.data_to_send()) == [Ping(1)]
    assert ctrl.work_pending()


def test_controller_pings_while_awaiting_put_done() -> None:
    ctrl, resp = pair(ctrl_fs=FakeFs({"up.bin": b"hello"}))
    ctrl.request_put("up.bin", now_ms=0)
    ctrl.handle_timeout(now_ms=0)
    ctrl.receive_bytes(data_frame(0, PutOk().encode()), now_ms=0)
    ctrl.handle_timeout(now_ms=0)
    sent = sent_messages(ctrl.data_to_send())
    assert [type(message) for message in sent] == [PutReq, FileData, FileEnd]
    ctrl.receive_bytes(build_frame(FrameType.ACK, SID, 3, 0, b""), now_ms=0)

    # FILE_END closed our stream, so a slow commit before PUT_DONE no
    # longer holds the keepalive back.
    ctrl.handle_timeout(now_ms=T_PING_MS)
    assert sent_messages(ctrl.data_to_send()) == [Ping(1)]


def test_next_timeout_includes_ping_deadline() -> None:
    ctrl, resp = pair()
    assert ctrl.next_timeout() == T_PING_MS


def run_clocked(
    ctrl: Session, resp: Session, step_ms: int
) -> tuple[list[SessionEvent], list[Message]]:
    """Drive both endpoints like host superloops sharing one clock.

    Each step of step_ms simulated time gives each side one timer poll,
    which is one bounded work slice, plus delivery of whatever its peer
    sent. A large hash therefore spans many steps of simulated time.
    Stops when the controller's operation finishes or either side ends.

    Returns:
        The controller's events and the messages it sent.
    """

    ctrl_events: list[SessionEvent] = []
    ctrl_sent: list[Message] = []
    parser = Parser()
    now_ms = 0
    for _ in range(5000):
        ctrl_events += ctrl.handle_timeout(now_ms)
        wire = ctrl.data_to_send()
        if wire:
            ctrl_sent += [
                decode_message(event.payload)
                for event in parser.feed(wire, now_ms)
                if isinstance(event, Frame) and event.type is FrameType.DATA
            ]
            resp.receive_bytes(wire, now_ms)
        resp.handle_timeout(now_ms)
        wire = resp.data_to_send()
        if wire:
            ctrl_events += ctrl.receive_bytes(wire, now_ms)
        if not (ctrl.session_active and resp.session_active):
            break
        if any(isinstance(event, (ListDone, PutDone, OpFailed)) for event in ctrl_events):
            break
        now_ms += step_ms
    return ctrl_events, ctrl_sent


# A 1 MiB file at about one CRC budget per 200 ms host loop turn takes
# about 50 s of simulated time to hash, five times T_DEAD.
BIG = bytes(i * 31 % 251 for i in range(1 << 20))
SLOW_STEP_MS = 200


def test_list_want_crc_outlives_t_dead_on_slow_responder_hash() -> None:
    ctrl, resp = pair(resp_fs=FakeFs({"big.bin": BIG}))
    ctrl.request_list("", want_crc=True, now_ms=0)

    events, sent = run_clocked(ctrl, resp, SLOW_STEP_MS)

    assert ctrl.session_active and resp.session_active
    assert [event for event in events if isinstance(event, EntryListed)] == [
        EntryListed(etype=0, path="big.bin", size=len(BIG), mtime=0, crc32=crc32(BIG))
    ]
    assert events[-1] == ListDone(1)
    assert sum(isinstance(message, Ping) for message in sent) >= T_DEAD_MS // T_PING_MS


def test_put_outlives_t_dead_on_slow_controller_hash() -> None:
    resp_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs=FakeFs({"big.bin": BIG}), resp_fs=resp_fs)
    ctrl.request_put("big.bin", now_ms=0)

    events, sent = run_clocked(ctrl, resp, SLOW_STEP_MS)

    assert ctrl.session_active and resp.session_active
    assert events[-1] == PutDone("big.bin", len(BIG), crc32(BIG))
    assert resp_fs.files["big.bin"] == BIG
    put_req_at = next(i for i, message in enumerate(sent) if isinstance(message, PutReq))
    assert sum(isinstance(message, Ping) for message in sent[:put_req_at]) >= (
        T_DEAD_MS // T_PING_MS
    )


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
