# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""LIST operation tests for SPEC.md section 5.4."""

from __future__ import annotations

from typing import Optional

import pytest

from fakefs import FakeFs
from rqft.crc32 import crc32
from rqft.events import Ended, EntryListed, EntrySkipped, ListDone, OpFailed, SessionEvent
from rqft.frame import Frame, FrameType, Parser, build_frame
from rqft.fs import FsEntry
from rqft.link import AbortReason
from rqft.messages import (
    Err,
    ErrCode,
    ListEnd,
    ListEntry,
    ListReq,
    Message,
    MsgType,
    decode_message,
)
from rqft.session import CRC_BUDGET_PER_POLL, Session, SessionError, SessionState
from rqft.messages import Role

SID = 0x42


def pair(
    fs: Optional[FakeFs], window: int = 4, resp_caps: int = 0
) -> tuple[Session, Session]:
    """Establish a controller/responder pair over a perfect line."""

    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID)
    resp = Session(Role.RESPONDER, fs=fs, window=window, caps=resp_caps)
    ctrl.start(now_ms=0)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=0)
    events = ctrl.receive_bytes(resp.data_to_send(), now_ms=0)
    assert events and ctrl.session_active and resp.session_active
    return ctrl, resp


def run(
    ctrl: Session, resp: Session, now_ms: int
) -> tuple[list[SessionEvent], list[SessionEvent]]:
    """Shuttle bytes and pending work until both endpoints go quiet."""

    ctrl_events: list[SessionEvent] = []
    resp_events: list[SessionEvent] = []
    for _ in range(400):
        progressed = False
        outbound = ctrl.data_to_send()
        if outbound:
            resp_events += resp.receive_bytes(outbound, now_ms)
            progressed = True
        if resp.work_pending():
            resp_events += resp.handle_timeout(now_ms)
            progressed = True
        inbound = resp.data_to_send()
        if inbound:
            ctrl_events += ctrl.receive_bytes(inbound, now_ms)
            progressed = True
        if ctrl.work_pending():
            ctrl_events += ctrl.handle_timeout(now_ms)
            progressed = True
        if not progressed:
            return ctrl_events, resp_events
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
    "logs/2025/run2.data": b"second run data",
}


def test_list_streams_entries_and_end() -> None:
    fs = FakeFs(FILES, mtimes={"a.data": 1735689600})
    ctrl, resp = pair(fs)

    ctrl.request_list("", want_crc=False, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [
        EntryListed(0, "a.data", 5, 1735689600, None),
        EntryListed(0, "logs/2025/run1.data", 9, 0, None),
        EntryListed(0, "logs/2025/run2.data", 15, 0, None),
        ListDone(3),
    ]


def test_list_subtree_root_filters() -> None:
    ctrl, resp = pair(FakeFs(FILES))

    ctrl.request_list("logs", want_crc=False, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert [e.path for e in ctrl_events if isinstance(e, EntryListed)] == [
        "logs/2025/run1.data",
        "logs/2025/run2.data",
    ]
    assert ctrl_events[-1] == ListDone(2)


def test_list_want_crc_computes_values() -> None:
    ctrl, resp = pair(FakeFs(FILES))

    ctrl.request_list("", want_crc=True, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    listed = [e for e in ctrl_events if isinstance(e, EntryListed)]
    assert [e.crc32 for e in listed] == [
        crc32(FILES["a.data"]),
        crc32(FILES["logs/2025/run1.data"]),
        crc32(FILES["logs/2025/run2.data"]),
    ]
    assert ctrl_events[-1] == ListDone(3)


def test_list_crc_work_bounded_per_poll() -> None:
    fs = FakeFs({"big.bin": bytes(range(256)) * 40})  # 10240 bytes
    ctrl, resp = pair(fs)

    ctrl.request_list("", want_crc=True, now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)

    polls = 0
    while resp.work_pending() and polls < 50:
        before = sum(length for _, length in fs.read_log)
        resp.handle_timeout(now_ms=10)
        hashed = sum(length for _, length in fs.read_log) - before
        assert hashed <= CRC_BUDGET_PER_POLL
        polls += 1

    # 10240 bytes at 4096 per poll: the receive pass hashes one budget,
    # then at least two more polls are needed.
    assert polls >= 2
    ctrl_events = ctrl.receive_bytes(resp.data_to_send(), now_ms=20)
    assert ctrl_events == [
        EntryListed(0, "big.bin", 10240, 0, crc32(fs.files["big.bin"])),
        ListDone(1),
    ]


def test_list_dir_entry_crc_skipped() -> None:
    fs = FakeFs()
    fs.list_override = [FsEntry("logs", 0, 7, etype=1), FsEntry("a.bin", 3, 0, etype=0)]
    fs.files["a.bin"] = b"abc"
    ctrl, resp = pair(fs)

    ctrl.request_list("", want_crc=True, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [
        EntryListed(1, "logs", 0, 7, None),
        EntryListed(0, "a.bin", 3, 0, crc32(b"abc")),
        ListDone(2),
    ]


def test_list_unreadable_file_skipped() -> None:
    fs = FakeFs(FILES)
    fs.fail_open_read.add("logs/2025/run1.data")
    ctrl, resp = pair(fs)

    ctrl.request_list("", want_crc=True, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [
        EntryListed(0, "a.data", 5, 0, crc32(FILES["a.data"])),
        EntrySkipped(ErrCode.E_FS_READ, 0),
        EntryListed(0, "logs/2025/run2.data", 15, 0, crc32(FILES["logs/2025/run2.data"])),
        ListDone(2),
    ]


def test_list_skip_reported_as_informational_err_on_wire() -> None:
    fs = FakeFs(FILES)
    fs.fail_open_read.add("logs/2025/run1.data")
    ctrl, resp = pair(fs)
    ctrl.request_list("", want_crc=True, now_ms=10)

    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    for _ in range(20):
        if resp.work_pending():
            resp.handle_timeout(now_ms=10)

    replies = sent_messages(resp.data_to_send())
    assert isinstance(replies[0], ListEntry) and replies[0].path == b"a.data"
    assert replies[1] == Err(ErrCode.E_FS_READ, MsgType.LIST_REQ, 0)
    assert isinstance(replies[2], ListEntry)
    assert replies[3] == ListEnd(2)


def test_controller_keeps_list_open_across_informational_err() -> None:
    ctrl, resp = pair(FakeFs(FILES))
    ctrl.request_list("", want_crc=True, now_ms=10)
    ctrl.data_to_send()

    skip = Err(ErrCode.E_FS_READ, MsgType.LIST_REQ, 0).encode()
    events = ctrl.receive_bytes(data_frame(0, skip), now_ms=10)
    events += ctrl.receive_bytes(data_frame(1, ListEnd(0).encode()), now_ms=10)

    assert events == [EntrySkipped(ErrCode.E_FS_READ, 0), ListDone(0)]
    assert ctrl.session_active


def test_list_read_error_mid_hash_skips_entry() -> None:
    fs = FakeFs(FILES)
    fs.fail_read_at["logs/2025/run2.data"] = 4
    ctrl, resp = pair(fs)

    ctrl.request_list("", want_crc=True, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert [e.path for e in ctrl_events if isinstance(e, EntryListed)] == [
        "a.data",
        "logs/2025/run1.data",
    ]
    assert EntrySkipped(ErrCode.E_FS_READ, 0) in ctrl_events
    assert ctrl_events[-1] == ListDone(2)


def test_responder_invalid_entry_paths_skipped() -> None:
    fs = FakeFs()
    fs.list_override = [
        FsEntry("../evil", 1, 0),
        FsEntry("ok.bin", 2, 0),
        FsEntry("x" * 500, 3, 0),
    ]
    fs.files["ok.bin"] = b"ok"
    ctrl, resp = pair(fs)

    ctrl.request_list("", want_crc=False, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [EntryListed(0, "ok.bin", 2, 0, None), ListDone(1)]


def test_list_entries_trickle_through_window_of_one() -> None:
    ctrl, resp = pair(FakeFs(FILES), window=1)

    ctrl.request_list("", want_crc=False, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert len([e for e in ctrl_events if isinstance(e, EntryListed)]) == 3
    assert ctrl_events[-1] == ListDone(3)


def test_responder_rejects_invalid_root_with_e_path() -> None:
    ctrl, resp = pair(FakeFs(FILES))
    ctrl.request_list("", want_crc=False, now_ms=10)  # occupies ctrl seq 0

    raw = ListReq(False, b"../up").encode()
    resp.receive_bytes(data_frame(0, raw), now_ms=10)

    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_PATH, MsgType.LIST_REQ, 0)]
    assert resp.session_active


def test_responder_missing_root_answers_fs_open() -> None:
    ctrl, resp = pair(FakeFs(FILES))
    ctrl.request_list("nosuch", want_crc=False, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.LIST_REQ, None, ErrCode.E_FS_OPEN, 0)]
    assert ctrl.session_active

    # The failed operation releases the slot for the next request.
    ctrl.request_list("", want_crc=False, now_ms=20)
    ctrl_events, _ = run(ctrl, resp, now_ms=20)
    assert ctrl_events[-1] == ListDone(3)


def test_responder_without_fs_answers_unsupported() -> None:
    ctrl, resp = pair(None)
    ctrl.request_list("", want_crc=False, now_ms=10)
    ctrl_events, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.LIST_REQ, None, ErrCode.E_UNSUPPORTED, 0)]


def test_controller_drops_invalid_entry_paths_but_counts_them() -> None:
    ctrl, resp = pair(FakeFs(FILES))
    ctrl.request_list("", want_crc=False, now_ms=10)
    ctrl.data_to_send()

    bad_entry = ListEntry(0, False, 1, 0, 0, b"../evil").encode()
    events = ctrl.receive_bytes(data_frame(0, bad_entry), now_ms=10)
    events += ctrl.receive_bytes(data_frame(1, ListEnd(1).encode()), now_ms=10)

    assert events == [ListDone(1)]
    assert ctrl.session_active


def test_list_end_count_mismatch_aborts_e_proto() -> None:
    ctrl, resp = pair(FakeFs(FILES))
    ctrl.request_list("", want_crc=False, now_ms=10)
    ctrl.data_to_send()

    events = ctrl.receive_bytes(data_frame(0, ListEnd(5).encode()), now_ms=10)

    assert events == [Ended(AbortReason.E_PROTO, from_peer=False)]
    assert ctrl.state is SessionState.ENDED
    frames = [
        e
        for e in Parser().feed(ctrl.data_to_send(), now_ms=0)
        if isinstance(e, Frame) and e.type is FrameType.ABORT
    ]
    assert len(frames) == 1
    assert frames[0].payload == bytes([AbortReason.E_PROTO])


def test_request_list_validates_role_state_and_path() -> None:
    ctrl, resp = pair(FakeFs(FILES))

    with pytest.raises(SessionError):
        resp.request_list("", want_crc=False, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_list("../up", want_crc=False, now_ms=10)

    ctrl.request_list("", want_crc=False, now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_list("", want_crc=False, now_ms=11)

    idle = Session(Role.CONTROLLER, sid_source=lambda: SID)
    with pytest.raises(SessionError):
        idle.request_list("", want_crc=False, now_ms=0)


def test_session_end_mid_list_closes_read_cursor() -> None:
    # A slow want_crc listing holds the fs read cursor across polls.
    fs = FakeFs({"big.bin": bytes(10240)})
    ctrl, resp = pair(fs)
    ctrl.request_list("", want_crc=True, now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    assert resp.work_pending() and fs.reading

    abort = build_frame(FrameType.ABORT, SID, 0, 0, bytes([AbortReason.E_USER]))
    events = resp.receive_bytes(abort, now_ms=11)

    assert events == [Ended(AbortReason.E_USER, from_peer=True)]
    assert not fs.reading
    assert not resp.work_pending()


def test_message_during_list_stream_answered_bad_state() -> None:
    # A slow want_crc listing keeps the operation open across polls.
    fs = FakeFs({"big.bin": bytes(10240)})
    ctrl, resp = pair(fs)
    ctrl.request_list("", want_crc=True, now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    assert resp.work_pending()

    # A second LIST_REQ while the listing streams is a state violation;
    # the responder answers ERR and the listing continues unharmed.
    resp.receive_bytes(data_frame(1, ListReq(False, b"").encode()), now_ms=11)
    for _ in range(10):
        if resp.work_pending():
            resp.handle_timeout(now_ms=12)

    replies = sent_messages(resp.data_to_send())
    assert replies[0] == Err(ErrCode.E_BAD_STATE, MsgType.LIST_REQ, 0)
    assert isinstance(replies[1], ListEntry)
    assert replies[2] == ListEnd(1)
    assert resp.session_active


def test_progress_is_none_during_list() -> None:
    fs = FakeFs({"big.bin": bytes(range(256)) * 24})  # hash spans several polls
    ctrl, resp = pair(fs)

    ctrl.request_list("", want_crc=True, now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)

    assert resp.work_pending()  # mid-hash: LIST work is not file-transfer progress
    assert ctrl.progress() is None and resp.progress() is None
