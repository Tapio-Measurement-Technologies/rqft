# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""PUT operation tests for SPEC.md section 5.4."""

from __future__ import annotations

from typing import Optional

import pytest

from fakefs import FakeFs
from rqft.crc32 import crc32
from rqft.events import Ended, OpFailed, PutDone, SessionEvent
from rqft.frame import Frame, FrameType, Parser, build_frame
from rqft.link import AbortReason
from rqft.messages import (
    Err,
    ErrCode,
    FileData,
    FileEnd,
    ListReq,
    Message,
    MsgType,
    Ping,
    PutOk,
    PutReq,
    Role,
    decode_message,
)
from rqft.messages import PutDone as PutDoneMsg
from rqft.session import (
    CRC_BUDGET_PER_POLL,
    Session,
    SessionError,
    SessionState,
    TransferPhase,
    TransferProgress,
)

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
}


def test_put_transfers_whole_file() -> None:
    resp_fs = FakeFs()
    ctrl, resp = pair(FakeFs(FILES), resp_fs)

    ctrl.request_put("logs/2025/run1.data", now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [PutDone("logs/2025/run1.data", 9, crc32(b"first run"))]
    assert resp_fs.files["logs/2025/run1.data"] == b"first run"
    assert not resp_fs.writing
    assert ctrl.session_active and resp.session_active


def test_put_streams_full_chunks_after_hashing() -> None:
    content = bytes(range(256)) * 6  # 1536 bytes -> chunks 511, 511, 511, 3
    ctrl_fs = FakeFs({"big.bin": content})
    resp_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, resp_fs)

    ctrl.request_put("big.bin", now_ms=10)
    ctrl_events, _, ctrl_wire, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [PutDone("big.bin", 1536, crc32(content))]
    assert resp_fs.files["big.bin"] == content
    streamed = sent_messages(ctrl_wire)
    assert streamed[0] == PutReq(1536, crc32(content), b"big.bin")
    assert [len(m.data) for m in streamed[1:-1] if isinstance(m, FileData)] == [
        511,
        511,
        511,
        3,
    ]
    assert streamed[-1] == FileEnd(crc32(content))
    # The controller hashed and streamed in bounded reads.
    assert all(length <= 512 for _, length in ctrl_fs.read_log)


def test_put_hash_work_bounded_per_poll() -> None:
    fs = FakeFs({"big.bin": bytes(range(256)) * 40})  # 10240 bytes
    ctrl, resp = pair(fs, FakeFs())

    ctrl.request_put("big.bin", now_ms=10)

    polls = 0
    while ctrl.work_pending() and polls < 50:
        before = sum(length for _, length in fs.read_log)
        ctrl.handle_timeout(now_ms=10)
        hashed = sum(length for _, length in fs.read_log) - before
        assert hashed <= CRC_BUDGET_PER_POLL
        polls += 1

    # 10240 bytes at 4096 per poll: three polls to finish the hash.
    assert polls >= 3
    assert sent_messages(ctrl.data_to_send()) == [
        PutReq(10240, crc32(fs.files["big.bin"]), b"big.bin")
    ]


def test_put_zero_byte_file() -> None:
    resp_fs = FakeFs()
    ctrl, resp = pair(FakeFs({"empty.bin": b""}), resp_fs)

    ctrl.request_put("empty.bin", now_ms=10)
    ctrl_events, _, ctrl_wire, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [PutDone("empty.bin", 0, 0)]
    assert resp_fs.files["empty.bin"] == b""
    assert sent_messages(ctrl_wire) == [PutReq(0, 0, b"empty.bin"), FileEnd(0)]


def test_put_writes_temp_then_commits_on_file_end() -> None:
    resp_fs = FakeFs()
    ctrl, resp = pair(None, resp_fs)

    resp.receive_bytes(data_frame(0, PutReq(3, crc32(b"abc"), b"f.bin").encode()), now_ms=10)
    resp.receive_bytes(data_frame(1, FileData(b"ab").encode()), now_ms=10)
    assert resp_fs.writing
    assert "f.bin" not in resp_fs.files

    resp.receive_bytes(data_frame(2, FileData(b"c").encode()), now_ms=10)
    resp.receive_bytes(data_frame(3, FileEnd(crc32(b"abc")).encode()), now_ms=10)

    assert resp_fs.files["f.bin"] == b"abc"
    assert not resp_fs.writing
    replies = sent_messages(resp.data_to_send())
    assert replies == [PutOk(), PutDoneMsg(0)]
    assert resp.session_active


@pytest.mark.parametrize(
    "size,body", [(3, b"abX"), (5, b"abc")], ids=["crc_mismatch", "count_mismatch"]
)
def test_put_verification_mismatch_answers_put_done_crc_err(size: int, body: bytes) -> None:
    resp_fs = FakeFs()
    ctrl, resp = pair(None, resp_fs)

    crc = crc32(b"abc")
    resp.receive_bytes(data_frame(0, PutReq(size, crc, b"f.bin").encode()), now_ms=10)
    resp.receive_bytes(data_frame(1, FileData(body).encode()), now_ms=10)
    resp.receive_bytes(data_frame(2, FileEnd(crc).encode()), now_ms=10)

    assert sent_messages(resp.data_to_send()) == [
        PutOk(),
        PutDoneMsg(ErrCode.E_CRC_FILE),
    ]
    assert resp_fs.discarded == 1
    assert "f.bin" not in resp_fs.files
    assert resp.session_active


def test_file_end_crc_mismatching_put_req_aborts() -> None:
    resp_fs = FakeFs()
    ctrl, resp = pair(None, resp_fs)

    resp.receive_bytes(data_frame(0, PutReq(3, crc32(b"abc"), b"f.bin").encode()), now_ms=10)
    resp.receive_bytes(data_frame(1, FileData(b"abc").encode()), now_ms=10)
    events = resp.receive_bytes(data_frame(2, FileEnd(0xDEADBEEF).encode()), now_ms=10)

    assert events == [Ended(AbortReason.E_PROTO, from_peer=False)]
    assert resp.state is SessionState.ENDED
    assert resp_fs.discarded == 1
    aborts = [
        e
        for e in Parser().feed(resp.data_to_send(), now_ms=0)
        if isinstance(e, Frame) and e.type is FrameType.ABORT
    ]
    assert len(aborts) == 1
    assert aborts[0].payload == bytes([AbortReason.E_PROTO])


def test_put_write_failure_discards_temp_and_answers_put_done_err() -> None:
    resp_fs = FakeFs()
    resp_fs.fail_write = True
    ctrl, resp = pair(FakeFs(FILES), resp_fs)

    ctrl.request_put("a.data", now_ms=10)
    ctrl_events, _, _, resp_wire = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.PUT_REQ, "a.data", ErrCode.E_FS_WRITE, 0)]
    assert resp_fs.discarded == 1
    assert sent_messages(resp_wire) == [PutOk(), PutDoneMsg(ErrCode.E_FS_WRITE)]
    assert ctrl.session_active and resp.session_active

    # The failed operation releases the slot; the next PUT commits.
    resp_fs.fail_write = False
    ctrl.request_put("a.data", now_ms=20)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=20)
    assert ctrl_events == [PutDone("a.data", 5, crc32(b"alpha"))]
    assert resp_fs.files["a.data"] == b"alpha"


def test_put_commit_failure_answers_put_done_err() -> None:
    resp_fs = FakeFs()
    resp_fs.fail_commit = True
    ctrl, resp = pair(FakeFs(FILES), resp_fs)

    ctrl.request_put("a.data", now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.PUT_REQ, "a.data", ErrCode.E_FS_WRITE, 0)]
    assert resp_fs.discarded == 1
    assert ctrl.session_active and resp.session_active


def test_put_err_on_open_write_fails_op_and_batch_continues() -> None:
    resp_fs = FakeFs()
    resp_fs.fail_open_write.add("a.data")
    ctrl, resp = pair(FakeFs(FILES), resp_fs)

    ctrl.request_put("a.data", now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.PUT_REQ, "a.data", ErrCode.E_FS_OPEN, 0)]
    assert resp_fs.discarded == 0
    assert ctrl.session_active and resp.session_active

    ctrl.request_put("logs/2025/run1.data", now_ms=20)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=20)
    assert ctrl_events == [PutDone("logs/2025/run1.data", 9, crc32(b"first run"))]


def test_responder_rejects_invalid_put_path_with_e_path() -> None:
    ctrl, resp = pair(None, FakeFs())

    resp.receive_bytes(data_frame(0, PutReq(3, 0, b"../up").encode()), now_ms=10)

    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_PATH, MsgType.PUT_REQ, 0)]
    assert resp.session_active


def test_responder_without_fs_answers_unsupported() -> None:
    ctrl, resp = pair(None, None)

    resp.receive_bytes(data_frame(0, PutReq(3, 0, b"f.bin").encode()), now_ms=10)

    replies = sent_messages(resp.data_to_send())
    assert replies == [Err(ErrCode.E_UNSUPPORTED, MsgType.PUT_REQ, 0)]
    assert resp.session_active


@pytest.mark.parametrize(
    "payload", [ListReq(False, b"").encode(), Ping(7).encode()]
)
def test_unexpected_message_mid_stream_aborts_responder(payload: bytes) -> None:
    resp_fs = FakeFs()
    ctrl, resp = pair(None, resp_fs)

    resp.receive_bytes(data_frame(0, PutReq(9, 0, b"f.bin").encode()), now_ms=10)
    resp.receive_bytes(data_frame(1, FileData(b"abc").encode()), now_ms=10)
    events = resp.receive_bytes(data_frame(2, payload), now_ms=10)

    assert events == [Ended(AbortReason.E_PROTO, from_peer=False)]
    assert resp.state is SessionState.ENDED
    assert resp_fs.discarded == 1
    aborts = [
        e
        for e in Parser().feed(resp.data_to_send(), now_ms=0)
        if isinstance(e, Frame) and e.type is FrameType.ABORT
    ]
    assert len(aborts) == 1
    assert aborts[0].payload == bytes([AbortReason.E_PROTO])


def test_message_mid_put_stream_aborts_controller() -> None:
    # window=1 wedges the controller mid-stream: FILE_DATA stays unacked.
    ctrl_fs = FakeFs({"big.bin": bytes(1536)})
    ctrl, resp = pair(ctrl_fs, FakeFs(), window=1)

    ctrl.request_put("big.bin", now_ms=10)
    while ctrl.work_pending():
        ctrl.handle_timeout(now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    ctrl.receive_bytes(resp.data_to_send(), now_ms=10)
    assert ctrl_fs.reading

    events = ctrl.receive_bytes(data_frame(1, Ping(7).encode()), now_ms=11)

    assert events == [Ended(AbortReason.E_PROTO, from_peer=False)]
    assert ctrl.state is SessionState.ENDED
    assert not ctrl_fs.reading


def test_put_open_read_failure_fails_op_without_wire_traffic() -> None:
    ctrl_fs = FakeFs(FILES)
    ctrl, resp = pair(ctrl_fs, FakeFs())

    ctrl.request_put("nosuch.bin", now_ms=10)
    ctrl_events, _, ctrl_wire, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.PUT_REQ, "nosuch.bin", ErrCode.E_FS_OPEN, 0)]
    assert sent_messages(ctrl_wire) == []
    assert ctrl.session_active and resp.session_active

    ctrl.request_put("a.data", now_ms=20)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=20)
    assert ctrl_events == [PutDone("a.data", 5, crc32(b"alpha"))]


def test_put_read_error_during_hash_fails_op_without_wire_traffic() -> None:
    ctrl_fs = FakeFs(FILES)
    ctrl_fs.fail_read_at["a.data"] = 2
    ctrl, resp = pair(ctrl_fs, FakeFs())

    ctrl.request_put("a.data", now_ms=10)
    ctrl_events, _, ctrl_wire, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.PUT_REQ, "a.data", ErrCode.E_FS_READ, 0)]
    assert sent_messages(ctrl_wire) == []
    assert not ctrl_fs.reading
    assert ctrl.session_active and resp.session_active


def test_put_read_error_mid_stream_sends_err_and_fails_file() -> None:
    content = bytes(1536)
    ctrl_fs = FakeFs({"big.bin": content})
    ctrl_fs.fail_read_total = 1536 + 600  # hash pass fine, stream read fails
    resp_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, resp_fs)

    ctrl.request_put("big.bin", now_ms=10)
    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.PUT_REQ, "big.bin", ErrCode.E_FS_READ, 0)]
    assert resp_fs.discarded == 1
    assert "big.bin" not in resp_fs.files
    assert not ctrl_fs.reading
    assert ctrl.session_active and resp.session_active


def test_put_reopen_failure_after_put_ok_sends_err() -> None:
    ctrl_fs = FakeFs(FILES)
    resp_fs = FakeFs()
    ctrl, resp = pair(ctrl_fs, resp_fs)

    ctrl.request_put("a.data", now_ms=10)
    while ctrl.work_pending():
        ctrl.handle_timeout(now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    ctrl_fs.fail_open_read.add("a.data")

    ctrl_events = ctrl.receive_bytes(resp.data_to_send(), now_ms=10)
    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)

    assert ctrl_events == [OpFailed(MsgType.PUT_REQ, "a.data", ErrCode.E_FS_OPEN, 0)]
    assert resp_fs.discarded == 1
    assert ctrl.session_active and resp.session_active


def test_session_end_mid_put_discards_responder_temp() -> None:
    resp_fs = FakeFs()
    ctrl, resp = pair(None, resp_fs)
    resp.receive_bytes(data_frame(0, PutReq(9, 0, b"f.bin").encode()), now_ms=10)
    resp.receive_bytes(data_frame(1, FileData(b"abc").encode()), now_ms=10)
    assert resp_fs.writing

    abort = build_frame(FrameType.ABORT, SID, 0, 0, bytes([AbortReason.E_USER]))
    events = resp.receive_bytes(abort, now_ms=11)

    assert events == [Ended(AbortReason.E_USER, from_peer=True)]
    assert not resp_fs.writing
    assert resp_fs.discarded == 1


def test_session_end_mid_hash_releases_read_cursor() -> None:
    ctrl_fs = FakeFs({"big.bin": bytes(1536)})
    ctrl, resp = pair(ctrl_fs, FakeFs())
    ctrl.request_put("big.bin", now_ms=10)
    assert ctrl_fs.reading

    abort = build_frame(FrameType.ABORT, SID, 0, 0, bytes([AbortReason.E_USER]))
    events = ctrl.receive_bytes(abort, now_ms=11)

    assert events == [Ended(AbortReason.E_USER, from_peer=True)]
    assert not ctrl_fs.reading


def test_request_put_validates_role_state_path_and_fs() -> None:
    ctrl, resp = pair(FakeFs(FILES), FakeFs())

    with pytest.raises(SessionError):
        resp.request_put("a.data", now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_put("../up", now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_put("", now_ms=10)

    ctrl.request_put("a.data", now_ms=10)
    with pytest.raises(SessionError):
        ctrl.request_put("a.data", now_ms=11)

    fsless, _ = pair(None, FakeFs())
    with pytest.raises(SessionError):
        fsless.request_put("a.data", now_ms=10)

    idle = Session(Role.CONTROLLER, sid_source=lambda: SID, fs=FakeFs(FILES))
    with pytest.raises(SessionError):
        idle.request_put("a.data", now_ms=0)


def test_progress_reports_put_hash_then_stream_on_both_sides() -> None:
    content = bytes(range(256)) * 24  # 6144 bytes: more than one hash budget
    ctrl_fs = FakeFs({"up.bin": content})
    ctrl, resp = pair(ctrl_fs, FakeFs())
    assert ctrl.progress() is None and resp.progress() is None

    ctrl.request_put("up.bin", now_ms=10)
    assert ctrl.progress() == TransferProgress(
        MsgType.PUT_REQ, TransferPhase.HASH, 0, len(content)
    )

    ctrl.handle_timeout(now_ms=10)  # one bounded hash slice
    assert ctrl.progress() == TransferProgress(
        MsgType.PUT_REQ, TransferPhase.HASH, CRC_BUDGET_PER_POLL, len(content)
    )

    ctrl.handle_timeout(now_ms=10)  # hash finishes; PUT_REQ goes out
    assert ctrl.progress() == TransferProgress(
        MsgType.PUT_REQ, TransferPhase.STREAM, 0, len(content)
    )

    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)  # PUT_REQ -> PUT_OK
    assert resp.progress() == TransferProgress(
        MsgType.PUT_REQ, TransferPhase.STREAM, 0, len(content)
    )

    ctrl.receive_bytes(resp.data_to_send(), now_ms=10)  # PUT_OK opens the stream
    uploading = ctrl.progress()
    assert uploading is not None
    assert uploading.request is MsgType.PUT_REQ
    assert uploading.phase is TransferPhase.STREAM
    assert 0 < uploading.done < len(content)
    assert uploading.total == len(content)

    resp.receive_bytes(ctrl.data_to_send(), now_ms=10)
    receiving = resp.progress()
    assert receiving is not None
    assert 0 < receiving.done < len(content)
    assert receiving.total == len(content)

    ctrl_events, _, _, _ = run(ctrl, resp, now_ms=10)
    assert PutDone("up.bin", len(content), crc32(content)) in ctrl_events
    assert ctrl.progress() is None and resp.progress() is None


def test_progress_put_open_failure_reports_no_total() -> None:
    ctrl_fs = FakeFs(FILES)
    ctrl_fs.fail_open_read.add("a.data")
    ctrl, resp = pair(ctrl_fs, FakeFs())

    ctrl.request_put("a.data", now_ms=10)
    assert ctrl.progress() == TransferProgress(MsgType.PUT_REQ, TransferPhase.HASH, 0, None)

    events = ctrl.handle_timeout(now_ms=10)
    assert events == [OpFailed(MsgType.PUT_REQ, "a.data", ErrCode.E_FS_OPEN, 0)]
    assert ctrl.progress() is None
