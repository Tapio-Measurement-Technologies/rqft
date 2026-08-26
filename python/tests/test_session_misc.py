# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""PLAN, NOTIFY, and forward-compatibility tests for SPEC.md section 5.3-5.4."""

from __future__ import annotations

import pytest

from fakefs import FakeFs
from rqft.events import DelDone, NotifyReceived, PlanReceived, SessionEvent
from rqft.frame import Frame, FrameType, Parser, build_frame
from rqft.messages import (
    CAP_ALLOW_DELETE,
    NOTIFY_SYNC_INCREMENTAL,
    Err,
    ErrCode,
    Message,
    MsgType,
    Notify,
    Ping,
    Plan,
    Pong,
    Role,
    decode_message,
)
from rqft.session import Session, SessionError

SID = 0x42


def pair() -> tuple[Session, Session]:
    """Establish a controller/responder pair over a perfect line."""

    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID)
    resp = Session(Role.RESPONDER, caps=CAP_ALLOW_DELETE)
    ctrl.start(now_ms=0)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=0)
    events = ctrl.receive_bytes(resp.data_to_send(), now_ms=0)
    assert events and ctrl.session_active and resp.session_active
    return ctrl, resp


def run(
    ctrl: Session, resp: Session, now_ms: int
) -> tuple[list[SessionEvent], list[SessionEvent], bytes, bytes]:
    """Shuttle bytes and pending work until both endpoints go quiet.

    Returns both event streams plus both outbound wire captures.
    """

    ctrl_events: list[SessionEvent] = []
    resp_events: list[SessionEvent] = []
    ctrl_wire = bytearray()
    resp_wire = bytearray()
    for _ in range(400):
        progressed = False
        if ctrl.work_pending():
            ctrl_events += ctrl.handle_timeout(now_ms)
            progressed = True
        outbound = ctrl.data_to_send()
        if outbound:
            ctrl_wire += outbound
            resp_events += resp.receive_bytes(outbound, now_ms)
            progressed = True
        if resp.work_pending():
            resp_events += resp.handle_timeout(now_ms)
            progressed = True
        inbound = resp.data_to_send()
        if inbound:
            resp_wire += inbound
            ctrl_events += ctrl.receive_bytes(inbound, now_ms)
            progressed = True
        if not progressed:
            return ctrl_events, resp_events, bytes(ctrl_wire), bytes(resp_wire)
    raise AssertionError("endpoints never went quiet")


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


def test_plan_surfaces_totals_on_responder() -> None:
    ctrl, resp = pair()

    ctrl.send_plan(nfiles=3, nbytes=12345, now_ms=10)
    _, resp_events, _, resp_wire = run(ctrl, resp, now_ms=10)

    assert resp_events == [PlanReceived(3, 12345)]
    # PLAN is informative: the responder answers nothing.
    assert sent_messages(resp_wire) == []
    assert ctrl.session_active and resp.session_active


def test_plan_does_not_occupy_the_operation_slot() -> None:
    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID)
    resp = Session(Role.RESPONDER, fs=FakeFs({"a.data": b"alpha"}), caps=CAP_ALLOW_DELETE)
    ctrl.start(now_ms=0)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=0)
    ctrl.receive_bytes(resp.data_to_send(), now_ms=0)

    ctrl.send_plan(nfiles=1, nbytes=5, now_ms=10)
    ctrl.request_del("a.data", is_dir=False, now_ms=10)
    ctrl_events, resp_events, _, _ = run(ctrl, resp, now_ms=10)

    assert resp_events == [PlanReceived(1, 5)]
    assert ctrl_events == [DelDone("a.data", False)]


def test_plan_to_controller_answers_bad_state() -> None:
    ctrl, resp = pair()

    ctrl.receive_bytes(data_frame(0, Plan(1, 2).encode()), now_ms=10)

    replies = sent_messages(ctrl.data_to_send())
    assert replies == [Err(ErrCode.E_BAD_STATE, MsgType.PLAN, 0)]
    assert ctrl.session_active


def test_send_plan_validates_role_state_op_and_ranges() -> None:
    ctrl, resp = pair()

    with pytest.raises(SessionError):
        resp.send_plan(nfiles=1, nbytes=1, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.send_plan(nfiles=0x10000, nbytes=1, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.send_plan(nfiles=-1, nbytes=1, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.send_plan(nfiles=1, nbytes=1 << 32, now_ms=10)

    ctrl.request_del("a.data", is_dir=False, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.send_plan(nfiles=1, nbytes=1, now_ms=11)

    idle = Session(Role.CONTROLLER, sid_source=lambda: SID)
    with pytest.raises(SessionError):
        idle.send_plan(nfiles=1, nbytes=1, now_ms=0)


def test_notify_surfaces_flags_on_controller() -> None:
    ctrl, resp = pair()

    resp.send_notify(NOTIFY_SYNC_INCREMENTAL, now_ms=10)
    ctrl_events, _, ctrl_wire, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [NotifyReceived(NOTIFY_SYNC_INCREMENTAL)]
    # NOTIFY is informative: the controller answers nothing.
    assert sent_messages(ctrl_wire) == []
    assert ctrl.session_active and resp.session_active


def test_notify_while_awaiting_op_reply_is_accepted() -> None:
    ctrl, resp = pair()

    # The controller's LIST is in flight; NOTIFY must still surface
    # without an ERR and without disturbing the operation slot.
    ctrl.request_list("", want_crc=False, now_ms=10)
    ctrl.data_to_send()  # discard the outbound LIST_REQ
    ctrl_events = ctrl.receive_bytes(
        data_frame(0, Notify(NOTIFY_SYNC_INCREMENTAL).encode()), now_ms=11
    )

    assert ctrl_events == [NotifyReceived(NOTIFY_SYNC_INCREMENTAL)]
    assert sent_messages(ctrl.data_to_send()) == []
    # The operation slot is still held by the LIST.
    with pytest.raises(SessionError):
        ctrl.request_list("", want_crc=False, now_ms=12)
    assert ctrl.session_active


def test_notify_to_responder_answers_bad_state() -> None:
    ctrl, resp = pair()

    resp_events = resp.receive_bytes(
        data_frame(0, Notify(NOTIFY_SYNC_INCREMENTAL).encode()), now_ms=10
    )

    assert resp_events == []
    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_BAD_STATE, MsgType.NOTIFY, 0)]
    assert resp.session_active


def test_send_notify_requires_idle_operation_slot() -> None:
    # A file larger than the send window can buffer keeps the responder's
    # GET stream (and so its operation slot) in flight without ACKs.
    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID, fs=FakeFs())
    resp = Session(Role.RESPONDER, fs=FakeFs({"a.data": b"x" * 8192}))
    ctrl.start(now_ms=0)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=0)
    ctrl.receive_bytes(resp.data_to_send(), now_ms=0)

    # Park a GET on the responder so its operation slot is held.
    ctrl.request_get("a.data", now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)

    with pytest.raises(SessionError):
        resp.send_notify(0, now_ms=11)


def test_unknown_msg_type_between_ops_answers_unsupported() -> None:
    ctrl, resp = pair()

    # Responder side: unknown type 0x60 with an arbitrary body.
    resp.receive_bytes(data_frame(0, bytes([0x60, 1, 2, 3])), now_ms=10)
    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_UNSUPPORTED, 0x60, 0)]
    assert resp.session_active

    # Controller side: unknown type 0x61 with an empty body.
    ctrl.receive_bytes(data_frame(0, bytes([0x61])), now_ms=10)
    replies = sent_messages(ctrl.data_to_send())
    assert replies == [Err(ErrCode.E_UNSUPPORTED, 0x61, 0)]
    assert ctrl.session_active


def test_session_lives_after_unknown_msg_and_keeps_serving() -> None:
    ctrl, resp = pair()

    resp.receive_bytes(data_frame(0, bytes([0x60])), now_ms=10)
    resp.data_to_send()

    # The next message on the stream is still served: PING echoes PONG.
    resp.receive_bytes(data_frame(1, Ping(7).encode()), now_ms=11)
    replies = sent_messages(resp.data_to_send())
    assert replies == [Pong(7)]
    assert resp.session_active
