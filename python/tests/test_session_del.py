# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""DEL operation tests for SPEC.md section 5.4."""

from __future__ import annotations

from typing import Optional

import pytest

from fakefs import FakeFs
from rqft.events import DelDone, OpFailed, SessionEvent
from rqft.frame import Frame, FrameType, Parser, build_frame
from rqft.messages import (
    CAP_ALLOW_DELETE,
    DelFile,
    DelOk,
    Err,
    ErrCode,
    ListEnd,
    Message,
    MsgType,
    Role,
    decode_message,
)
from rqft.session import Session, SessionError

SID = 0x42


def pair(
    resp_fs: Optional[FakeFs], resp_caps: int = CAP_ALLOW_DELETE
) -> tuple[Session, Session]:
    """Establish a controller/responder pair over a perfect line."""

    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID)
    resp = Session(Role.RESPONDER, fs=resp_fs, caps=resp_caps)
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


FILES = {
    "a.data": b"alpha",
    "logs/2025/run1.data": b"first run",
    "logs/2025/run2.data": b"second run",
}


def test_del_file_removes_file_and_reports_del_done() -> None:
    resp_fs = FakeFs(FILES)
    ctrl, resp = pair(resp_fs)

    ctrl.request_del("a.data", is_dir=False, now_ms=10)
    ctrl_events, _, _, resp_wire = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [DelDone("a.data", False)]
    assert "a.data" not in resp_fs.files
    assert resp_fs.files["logs/2025/run1.data"] == b"first run"
    assert sent_messages(resp_wire) == [DelOk()]
    assert ctrl.session_active and resp.session_active


def test_del_dir_removes_tree_recursively() -> None:
    resp_fs = FakeFs(FILES)
    ctrl, resp = pair(resp_fs)

    ctrl.request_del("logs", is_dir=True, now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [DelDone("logs", True)]
    assert resp_fs.files == {"a.data": b"alpha"}
    assert ctrl.session_active and resp.session_active


def test_del_denied_without_caps_bit() -> None:
    # First gate: the responder never advertised ALLOW_DELETE, so even a
    # permissive per-request callback must not be consulted.
    resp_fs = FakeFs(FILES)
    ctrl, resp = pair(resp_fs, resp_caps=0)

    ctrl.request_del("a.data", is_dir=False, now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.DEL_FILE, "a.data", ErrCode.E_DENIED, 0)]
    assert resp_fs.files["a.data"] == b"alpha"
    assert ctrl.session_active and resp.session_active


def test_del_denied_by_per_request_callback() -> None:
    # Second gate: caps advertised, but the host refuses this path.
    resp_fs = FakeFs(FILES)
    resp_fs.deny_delete.add("logs")
    ctrl, resp = pair(resp_fs)

    ctrl.request_del("logs", is_dir=True, now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.DEL_DIR, "logs", ErrCode.E_DENIED, 0)]
    assert resp_fs.files == dict(FILES)
    assert ctrl.session_active and resp.session_active


@pytest.mark.parametrize(
    "path,is_dir",
    [("a.data", False), ("nosuch.bin", False), ("nosuch", True)],
    ids=["scripted_failure", "missing_file", "missing_tree"],
)
def test_del_remove_failure_answers_fs_remove(path: str, is_dir: bool) -> None:
    resp_fs = FakeFs(FILES)
    resp_fs.fail_remove.add("a.data")
    ctrl, resp = pair(resp_fs)

    ctrl.request_del(path, is_dir=is_dir, now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)

    request = MsgType.DEL_DIR if is_dir else MsgType.DEL_FILE
    assert ctrl_events == [OpFailed(request, path, ErrCode.E_FS_REMOVE, 0)]
    assert resp_fs.files == dict(FILES)
    assert ctrl.session_active and resp.session_active


def test_failed_del_releases_slot_and_batch_continues() -> None:
    resp_fs = FakeFs(FILES)
    resp_fs.deny_delete.add("a.data")
    ctrl, resp = pair(resp_fs)

    ctrl.request_del("a.data", is_dir=False, now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)
    assert ctrl_events == [OpFailed(MsgType.DEL_FILE, "a.data", ErrCode.E_DENIED, 0)]

    ctrl.request_del("logs", is_dir=True, now_ms=20)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=20)
    assert ctrl_events == [DelDone("logs", True)]
    assert resp_fs.files == {"a.data": b"alpha"}


def test_responder_rejects_invalid_del_path_with_e_path() -> None:
    ctrl, resp = pair(FakeFs(FILES))

    resp.receive_bytes(data_frame(0, DelFile(b"../up").encode()), now_ms=10)

    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_PATH, MsgType.DEL_FILE, 0)]
    assert resp.session_active


def test_responder_without_fs_answers_unsupported() -> None:
    ctrl, resp = pair(None)

    resp.receive_bytes(data_frame(0, DelFile(b"a.data").encode()), now_ms=10)

    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_UNSUPPORTED, MsgType.DEL_FILE, 0)]
    assert resp.session_active


def test_wrong_message_while_awaiting_del_ok_answers_bad_state() -> None:
    ctrl, resp = pair(FakeFs(FILES))

    ctrl.request_del("a.data", is_dir=False, now_ms=10)
    ctrl.data_to_send()
    ctrl.receive_bytes(data_frame(0, ListEnd(0).encode()), now_ms=10)

    replies = sent_messages(ctrl.data_to_send())
    assert Err(ErrCode.E_BAD_STATE, MsgType.LIST_END, 0) in replies
    # The operation is still in flight.
    with pytest.raises(SessionError):
        ctrl.request_del("logs", is_dir=True, now_ms=11)


def test_request_del_validates_role_state_and_path() -> None:
    ctrl, resp = pair(FakeFs(FILES))

    with pytest.raises(SessionError):
        resp.request_del("a.data", is_dir=False, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_del("../up", is_dir=False, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_del("", is_dir=True, now_ms=10)

    ctrl.request_del("a.data", is_dir=False, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_del("a.data", is_dir=False, now_ms=11)

    idle = Session(Role.CONTROLLER, sid_source=lambda: SID)
    with pytest.raises(SessionError):
        idle.request_del("a.data", is_dir=False, now_ms=0)
