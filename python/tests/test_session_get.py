# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""GET operation tests for SPEC.md section 5.4."""

from __future__ import annotations

from typing import Optional

import pytest

from fakefs import FakeFs
from rqft.crc32 import crc32
from rqft.events import Ended, GetDone, GetServed, OpFailed, SessionEvent
from rqft.frame import Frame, FrameType, Parser, build_frame
from rqft.link import AbortReason
from rqft.messages import (
    Err,
    ErrCode,
    FileData,
    FileEnd,
    FileInfo,
    GetReq,
    ListEntry,
    ListReq,
    Message,
    MsgType,
    Ping,
    Role,
    decode_message,
)
from rqft.messages import GetDone as GetDoneMsg
from rqft.session import Session, SessionError, SessionState, TransferPhase, TransferProgress

SID = 0x42


def pair(
    ctrl_fs: Optional[FakeFs], resp_fs: Optional[FakeFs], window: int = 4
) -> tuple[Session, Session]:
    """Establish a controller/responder pair over a perfect line."""

    ctrl = Session(Role.CONTROLLER, sid_source=lambda: SID, fs=ctrl_fs)
    resp = Session(Role.RESPONDER, fs=resp_fs, window=window)
    ctrl.start(now_ms=0)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=0)
    events = ctrl.receive_bytes(resp.data_to_send(), now_ms=0)
    assert events and ctrl.session_active and resp.session_active
    return ctrl, resp


def run(
    ctrl: Session, resp: Session, now_ms: int
) -> tuple[list[SessionEvent], list[SessionEvent], bytes]:
    """Shuttle bytes and pending work until both endpoints go quiet.

    Returns both event streams plus the responder's outbound wire bytes.
    """

    ctrl_events: list[SessionEvent] = []
    resp_events: list[SessionEvent] = []
    resp_wire = bytearray()
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
            resp_wire += inbound
            ctrl_events += ctrl.receive_bytes(inbound, now_ms)
            progressed = True
        if ctrl.work_pending():
            ctrl_events += ctrl.handle_timeout(now_ms)
            progressed = True
        if not progressed:
            return ctrl_events, resp_events, bytes(resp_wire)
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
}


def test_get_transfers_whole_file() -> None:
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))

    ctrl.request_get("logs/2025/run1.data", now_ms=10)
    ctrl_events, resp_events, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [GetDone("logs/2025/run1.data", 9, crc32(b"first run"))]
    assert resp_events == [GetServed("logs/2025/run1.data", 9, crc32(b"first run"))]
    assert ctrl_fs.files["logs/2025/run1.data"] == b"first run"
    assert not ctrl_fs.writing
    assert ctrl.session_active and resp.session_active


def test_get_streams_full_chunks_with_streaming_crc() -> None:
    content = bytes(range(256)) * 6  # 1536 bytes -> chunks 511, 511, 511, 3
    resp_fs = FakeFs({"big.bin": content})
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, resp_fs)

    ctrl.request_get("big.bin", now_ms=10)
    ctrl_events, _, resp_wire = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [GetDone("big.bin", 1536, crc32(content))]
    assert ctrl_fs.files["big.bin"] == content
    streamed = sent_messages(resp_wire)
    assert streamed[0] == FileInfo(1536)
    assert [len(m.data) for m in streamed[1:-1] if isinstance(m, FileData)] == [
        511,
        511,
        511,
        3,
    ]
    assert streamed[-1] == FileEnd(crc32(content))
    # The responder hashed while reading: no single read spans the file.
    assert all(length <= 511 for _, length in resp_fs.read_log)


def test_get_zero_byte_file() -> None:
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs({"empty.bin": b""}))

    ctrl.request_get("empty.bin", now_ms=10)
    ctrl_events, resp_events, resp_wire = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [GetDone("empty.bin", 0, 0)]
    assert resp_events == [GetServed("empty.bin", 0, 0)]
    assert ctrl_fs.files["empty.bin"] == b""
    assert sent_messages(resp_wire) == [FileInfo(0), FileEnd(0)]


def test_get_writes_temp_then_commits_on_file_end() -> None:
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))
    ctrl.request_get("f.bin", now_ms=10)
    ctrl.data_to_send()

    ctrl.receive_bytes(data_frame(0, FileInfo(3).encode()), now_ms=10)
    ctrl.receive_bytes(data_frame(1, FileData(b"ab").encode()), now_ms=10)
    assert ctrl_fs.writing
    assert "f.bin" not in ctrl_fs.files

    ctrl.receive_bytes(data_frame(2, FileData(b"c").encode()), now_ms=10)
    events = ctrl.receive_bytes(data_frame(3, FileEnd(crc32(b"abc")).encode()), now_ms=10)

    assert events == [GetDone("f.bin", 3, crc32(b"abc"))]
    assert ctrl_fs.files["f.bin"] == b"abc"
    assert not ctrl_fs.writing
    assert sent_messages(ctrl.data_to_send()) == [GetDoneMsg(0)]


def test_get_crc_mismatch_retries_once_then_fails_batch_continues() -> None:
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))
    ctrl.request_get("f.bin", now_ms=10)
    ctrl.data_to_send()

    # First stream ends with a lying CRC: silent discard + one retry.
    events = ctrl.receive_bytes(data_frame(0, FileInfo(3).encode()), now_ms=10)
    events += ctrl.receive_bytes(data_frame(1, FileData(b"abc").encode()), now_ms=10)
    events += ctrl.receive_bytes(data_frame(2, FileEnd(0xDEADBEEF).encode()), now_ms=10)
    assert events == []
    assert ctrl_fs.discarded == 1
    retry = sent_messages(ctrl.data_to_send())
    assert retry == [GetDoneMsg(ErrCode.E_CRC_FILE), GetReq(0, b"f.bin")]

    # Second mismatch surfaces the per-file error; the session lives.
    ctrl.receive_bytes(data_frame(3, FileInfo(3).encode()), now_ms=20)
    ctrl.receive_bytes(data_frame(4, FileData(b"abc").encode()), now_ms=20)
    events = ctrl.receive_bytes(data_frame(5, FileEnd(0xDEADBEEF).encode()), now_ms=20)

    assert events == [OpFailed(MsgType.GET_REQ, "f.bin", ErrCode.E_CRC_FILE, 0)]
    assert ctrl_fs.discarded == 2
    assert "f.bin" not in ctrl_fs.files
    assert ctrl.session_active

    # The failed operation releases the slot; the next GET commits.
    ctrl.request_get("a.data", now_ms=30)
    ctrl.receive_bytes(data_frame(6, FileInfo(5).encode()), now_ms=30)
    ctrl.receive_bytes(data_frame(7, FileData(b"alpha").encode()), now_ms=30)
    events = ctrl.receive_bytes(data_frame(8, FileEnd(crc32(b"alpha")).encode()), now_ms=30)
    assert events == [GetDone("a.data", 5, crc32(b"alpha"))]
    assert ctrl_fs.files["a.data"] == b"alpha"


def test_get_size_mismatch_counts_as_verification_failure() -> None:
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))
    ctrl.request_get("f.bin", now_ms=10)
    ctrl.data_to_send()

    ctrl.receive_bytes(data_frame(0, FileInfo(5).encode()), now_ms=10)
    ctrl.receive_bytes(data_frame(1, FileData(b"ab").encode()), now_ms=10)
    events = ctrl.receive_bytes(data_frame(2, FileEnd(crc32(b"ab")).encode()), now_ms=10)

    assert events == []
    assert ctrl_fs.discarded == 1
    assert sent_messages(ctrl.data_to_send()) == [
        GetDoneMsg(ErrCode.E_CRC_FILE),
        GetReq(0, b"f.bin"),
    ]


def test_get_err_on_open_fails_op_and_batch_continues() -> None:
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))

    ctrl.request_get("nosuch.bin", now_ms=10)
    ctrl_events, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.GET_REQ, "nosuch.bin", ErrCode.E_FS_OPEN, 0)]
    assert ctrl.session_active and resp.session_active

    ctrl.request_get("a.data", now_ms=20)
    ctrl_events, _, _ = run(ctrl, resp, now_ms=20)
    assert ctrl_events == [GetDone("a.data", 5, crc32(b"alpha"))]


def test_get_responder_read_error_mid_stream_answers_err() -> None:
    content = bytes(1536)
    resp_fs = FakeFs({"big.bin": content})
    resp_fs.fail_read_at["big.bin"] = 600  # first chunk fine, second read fails
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, resp_fs)

    ctrl.request_get("big.bin", now_ms=10)
    ctrl_events, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.GET_REQ, "big.bin", ErrCode.E_FS_READ, 0)]
    assert ctrl_fs.discarded == 1
    assert not resp_fs.reading
    assert ctrl.session_active and resp.session_active


def test_get_write_failure_drains_stream_and_fails_file() -> None:
    ctrl_fs = FakeFs()
    ctrl_fs.fail_write = True
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))

    ctrl.request_get("a.data", now_ms=10)
    ctrl_events, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.GET_REQ, "a.data", ErrCode.E_FS_WRITE, 0)]
    assert ctrl_fs.discarded == 1
    assert ctrl.session_active and resp.session_active

    ctrl_fs.fail_write = False
    ctrl.request_get("a.data", now_ms=20)
    ctrl_events, _, _ = run(ctrl, resp, now_ms=20)
    assert ctrl_events == [GetDone("a.data", 5, crc32(b"alpha"))]


def test_get_open_write_failure_drains_stream_and_fails_file() -> None:
    ctrl_fs = FakeFs()
    ctrl_fs.fail_open_write.add("a.data")
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))

    ctrl.request_get("a.data", now_ms=10)
    ctrl_events, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.GET_REQ, "a.data", ErrCode.E_FS_OPEN, 0)]
    assert ctrl_fs.discarded == 0
    assert ctrl.session_active and resp.session_active


def test_get_commit_failure_sends_get_done_write_error() -> None:
    ctrl_fs = FakeFs()
    ctrl_fs.fail_commit = True
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))

    ctrl.request_get("a.data", now_ms=10)
    ctrl_events, resp_events, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.GET_REQ, "a.data", ErrCode.E_FS_WRITE, 0)]
    assert resp_events == [OpFailed(MsgType.GET_REQ, "a.data", ErrCode.E_FS_WRITE, 0)]
    assert "a.data" not in ctrl_fs.files
    assert ctrl.session_active and resp.session_active


def serve_get(resp: Session, seq: int, path: bytes, now_ms: int) -> None:
    """Feed one GET_REQ and pump the responder through FILE_END."""

    resp.receive_bytes(data_frame(seq, GetReq(0, path).encode()), now_ms=now_ms)
    for _ in range(100):
        resp.data_to_send()
        if not resp.work_pending():
            return
        resp.handle_timeout(now_ms)
    raise AssertionError("responder never finished serving")


def test_responder_surfaces_nonzero_get_done_as_op_failed() -> None:
    _, resp = pair(FakeFs(), FakeFs(FILES))
    serve_get(resp, 0, b"a.data", now_ms=10)

    events = resp.receive_bytes(
        data_frame(1, GetDoneMsg(ErrCode.E_CRC_FILE).encode()), now_ms=11
    )

    assert events == [OpFailed(MsgType.GET_REQ, "a.data", ErrCode.E_CRC_FILE, 0)]
    assert resp.session_active


def test_responder_answers_stray_get_done_with_bad_state() -> None:
    _, resp = pair(FakeFs(), FakeFs(FILES))

    events = resp.receive_bytes(data_frame(0, GetDoneMsg(0).encode()), now_ms=10)

    assert events == []
    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_BAD_STATE, MsgType.GET_DONE, 0)]
    assert resp.session_active


def test_responder_consumes_get_done_verdict_only_once() -> None:
    _, resp = pair(FakeFs(), FakeFs(FILES))
    serve_get(resp, 0, b"a.data", now_ms=10)

    events = resp.receive_bytes(data_frame(1, GetDoneMsg(0).encode()), now_ms=11)
    assert events == [GetServed("a.data", 5, crc32(b"alpha"))]

    events = resp.receive_bytes(data_frame(2, GetDoneMsg(0).encode()), now_ms=12)
    assert events == []
    assert Err(ErrCode.E_BAD_STATE, MsgType.GET_DONE, 0) in sent_messages(resp.data_to_send())


def test_new_request_supersedes_served_get_record() -> None:
    _, resp = pair(FakeFs(), FakeFs(FILES))
    serve_get(resp, 0, b"a.data", now_ms=10)
    # Ack the served frames so the send window can carry the ERR later.
    resp.receive_bytes(build_frame(FrameType.ACK, SID, 3, 0), now_ms=10)

    # A non-conforming controller skips GET_DONE and lists instead: the
    # served-GET record dies with the new request.
    resp.receive_bytes(data_frame(1, ListReq(False, b"").encode()), now_ms=11)
    for _ in range(100):
        resp.data_to_send()
        if not resp.work_pending():
            break
        resp.handle_timeout(11)
    resp.receive_bytes(build_frame(FrameType.ACK, SID, 6, 0), now_ms=11)

    events = resp.receive_bytes(data_frame(2, GetDoneMsg(0).encode()), now_ms=12)
    assert events == []
    assert Err(ErrCode.E_BAD_STATE, MsgType.GET_DONE, 0) in sent_messages(resp.data_to_send())


def test_get_done_mid_get_stream_aborts_responder() -> None:
    # window=1 wedges the responder mid-stream: FILE_INFO stays unacked.
    resp_fs = FakeFs({"big.bin": bytes(1536)})
    ctrl, resp = pair(FakeFs(), resp_fs, window=1)
    ctrl.request_get("big.bin", now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    assert resp.work_pending()

    events = resp.receive_bytes(data_frame(1, GetDoneMsg(0).encode()), now_ms=11)

    assert events == [Ended(AbortReason.E_PROTO, from_peer=False)]
    assert resp.state is SessionState.ENDED
    assert not resp_fs.reading


def test_responder_rejects_nonzero_offset_with_unsupported() -> None:
    ctrl, resp = pair(FakeFs(), FakeFs(FILES))

    resp.receive_bytes(data_frame(0, GetReq(5, b"a.data").encode()), now_ms=10)

    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_UNSUPPORTED, MsgType.GET_REQ, 0)]
    assert resp.session_active


def test_responder_rejects_invalid_get_path_with_e_path() -> None:
    ctrl, resp = pair(FakeFs(), FakeFs(FILES))

    resp.receive_bytes(data_frame(0, GetReq(0, b"../up").encode()), now_ms=10)

    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_PATH, MsgType.GET_REQ, 0)]
    assert resp.session_active


@pytest.mark.parametrize(
    "payload", [ListEntry(0, False, 1, 0, 0, b"x").encode(), Ping(7).encode()]
)
def test_unexpected_message_mid_stream_aborts_controller(payload: bytes) -> None:
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))
    ctrl.request_get("f.bin", now_ms=10)
    ctrl.data_to_send()

    ctrl.receive_bytes(data_frame(0, FileInfo(10).encode()), now_ms=10)
    events = ctrl.receive_bytes(data_frame(1, payload), now_ms=10)

    assert events == [Ended(AbortReason.E_PROTO, from_peer=False)]
    assert ctrl.state is SessionState.ENDED
    assert ctrl_fs.discarded == 1
    aborts = [
        e
        for e in Parser().feed(ctrl.data_to_send(), now_ms=0)
        if isinstance(e, Frame) and e.type is FrameType.ABORT
    ]
    assert len(aborts) == 1
    assert aborts[0].payload == bytes([AbortReason.E_PROTO])


def test_message_mid_get_stream_aborts_responder() -> None:
    # window=1 wedges the responder mid-stream: FILE_INFO stays unacked.
    resp_fs = FakeFs({"big.bin": bytes(1536)})
    ctrl, resp = pair(FakeFs(), resp_fs, window=1)
    ctrl.request_get("big.bin", now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    assert resp.work_pending()

    events = resp.receive_bytes(data_frame(1, ListReq(False, b"").encode()), now_ms=11)

    assert events == [Ended(AbortReason.E_PROTO, from_peer=False)]
    assert resp.state is SessionState.ENDED
    assert not resp_fs.reading


def test_session_end_mid_get_discards_temp() -> None:
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs(FILES))
    ctrl.request_get("f.bin", now_ms=10)
    ctrl.data_to_send()
    ctrl.receive_bytes(data_frame(0, FileInfo(9).encode()), now_ms=10)
    ctrl.receive_bytes(data_frame(1, FileData(b"abc").encode()), now_ms=10)
    assert ctrl_fs.writing

    abort = build_frame(FrameType.ABORT, SID, 0, 0, bytes([AbortReason.E_USER]))
    events = ctrl.receive_bytes(abort, now_ms=11)

    assert events == [Ended(AbortReason.E_USER, from_peer=True)]
    assert not ctrl_fs.writing
    assert ctrl_fs.discarded == 1


def test_request_get_validates_role_state_path_and_fs() -> None:
    ctrl, resp = pair(FakeFs(), FakeFs(FILES))

    with pytest.raises(SessionError):
        resp.request_get("a.data", now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_get("../up", now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_get("", now_ms=10)

    ctrl.request_get("a.data", now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_get("a.data", now_ms=11)

    fsless, _ = pair(None, FakeFs(FILES))
    with pytest.raises(SessionError):
        fsless.request_get("a.data", now_ms=10)

    idle = Session(Role.CONTROLLER, sid_source=lambda: SID, fs=FakeFs())
    with pytest.raises(SessionError):
        idle.request_get("a.data", now_ms=0)


def test_progress_reports_get_byte_counters_on_both_sides() -> None:
    content = bytes(range(256)) * 24  # 6144 bytes -> several window flights
    ctrl_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, FakeFs({"big.bin": content}))
    assert Session(Role.CONTROLLER, sid_source=lambda: SID).progress() is None
    assert ctrl.progress() is None and resp.progress() is None

    ctrl.request_get("big.bin", now_ms=10)
    assert ctrl.progress() == TransferProgress(MsgType.GET_REQ, TransferPhase.STREAM, 0, None)

    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    serving = resp.progress()
    assert serving is not None
    assert serving.request is MsgType.GET_REQ
    assert serving.phase is TransferPhase.STREAM
    assert 0 < serving.done < len(content)
    assert serving.total == len(content)

    ctrl.receive_bytes(resp.data_to_send(), now_ms=10)
    fetching = ctrl.progress()
    assert fetching is not None
    assert fetching.request is MsgType.GET_REQ
    assert 0 < fetching.done < len(content)
    assert fetching.total == len(content)

    ctrl_events, _, _ = run(ctrl, resp, now_ms=10)
    assert GetDone("big.bin", len(content), crc32(content)) in ctrl_events
    assert ctrl.progress() is None and resp.progress() is None
