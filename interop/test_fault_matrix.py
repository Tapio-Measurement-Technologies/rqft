# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Fault-injected C/Python interop coverage."""

from __future__ import annotations

import random
from typing import Any, Callable, Optional

from harness import CPeer, InteropHarness, MemoryFs, has_py_event
from fault_shim import FaultProfile, FaultShim
from rqft.crc32 import crc32
from rqft.events import (
    Ended,
    EntryListed,
    Established,
    GetDone,
    GetServed,
    ListDone,
    Passthrough,
)
from rqft.events import PutDone as PutDoneEvent
from rqft.frame import FrameType, build_frame
from rqft.link import AbortReason
from rqft.messages import Role
from rqft.session import Session


BATCH_COUNT = 50
BATCH_SIZE = 4096


def _got_get_done(path: str) -> Callable[[list[object], list[dict[str, Any]]], bool]:
    """Predicate observing a GetDone event for one specific path."""

    def predicate(py: list[object], _c: list[dict[str, Any]]) -> bool:
        return any(
            isinstance(event, GetDone) and event.path == path for event in py
        )

    return predicate


def _blob(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(size))


def _batch_files(count: int = BATCH_COUNT, size: int = BATCH_SIZE) -> dict[str, bytes]:
    return {
        f"batch/{index:02}.bin": _blob(0xD17000 + index, size)
        for index in range(count)
    }


def _file_args(files: dict[str, bytes]) -> list[str]:
    args: list[str] = []
    for path, data in sorted(files.items()):
        args += ["--file", f"{path}=hex:{data.hex()}"]
    return args


def _shim(seed: int, profile: Optional[FaultProfile]) -> FaultShim:
    return FaultShim(seed=seed, profile=profile)


def _make_harness(
    peer: CPeer,
    session: Session,
    *,
    py_to_c: Optional[FaultProfile] = None,
    c_to_py: Optional[FaultProfile] = None,
) -> InteropHarness:
    return InteropHarness(
        peer,
        session,
        py_to_c=_shim(0xD170 + len(peer.events), py_to_c),
        c_to_py=_shim(0xD171 + len(peer.events), c_to_py),
    )


def _established_sid(events: list[object]) -> int:
    for event in events:
        if isinstance(event, Established):
            return event.sid
    raise AssertionError("session not established")


def _run_py_controller_c_responder(
    *,
    py_to_c: Optional[FaultProfile] = None,
    c_to_py: Optional[FaultProfile] = None,
    batch_count: int = BATCH_COUNT,
) -> Session:
    remote = _batch_files(batch_count)
    upload = _blob(0xD17F00, BATCH_SIZE)
    py_fs = MemoryFs({"upload.bin": upload})
    peer = CPeer(
        ["--role", "responder", "--seed", "0xD170C"] + _file_args(remote)
    )
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x42, fs=py_fs)
        harness = _make_harness(peer, session, py_to_c=py_to_c, c_to_py=c_to_py)

        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established), max_steps=80000)

        session.request_list("", want_crc=True, now_ms=harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, ListDone), max_steps=120000)
        listed = {
            event.path: event
            for event in harness.py_events
            if isinstance(event, EntryListed)
        }
        assert set(listed) == set(remote)
        for path, data in remote.items():
            assert listed[path].size == len(data), path
            assert listed[path].crc32 == crc32(data), path

        for path, data in sorted(remote.items()):
            session.request_get(path, now_ms=harness.now_ms)
            harness.drive_until(_got_get_done(path), max_steps=220000)
            assert py_fs.files[path] == data, path

        session.request_put("upload.bin", now_ms=harness.now_ms)
        harness.drive_until(
            lambda py, _c: any(
                isinstance(event, PutDoneEvent) and event.path == "upload.bin"
                for event in py
            ),
            max_steps=180000,
        )

        peer.close_stdin()
        harness.drive_peer_exit()
        assert peer.file_hex("upload.bin") == upload.hex()
        # The responder learned every committed GET exactly once, even
        # under line faults (GET_DONE rides the retransmitting link).
        served_paths = [event["path"] for event in peer.events_named("get_served")]
        assert sorted(served_paths) == sorted(remote)
        return session
    finally:
        peer.kill()


def _run_c_controller_py_responder(
    *,
    py_to_c: Optional[FaultProfile] = None,
    c_to_py: Optional[FaultProfile] = None,
    batch_count: int = BATCH_COUNT,
) -> Session:
    served = _batch_files(batch_count)
    upload = _blob(0xD17F01, BATCH_SIZE)
    py_fs = MemoryFs(served)
    actions: list[str] = ["--list", ""]
    for path in sorted(served):
        actions += ["--get", path]
    actions += ["--put", "upload.bin"]
    peer = CPeer(
        [
            "--role",
            "controller",
            "--seed",
            "0xD171C",
            "--file",
            f"upload.bin=hex:{upload.hex()}",
        ]
        + actions
    )
    try:
        session = Session(Role.RESPONDER, fs=py_fs)
        harness = _make_harness(peer, session, py_to_c=py_to_c, c_to_py=c_to_py)

        harness.drive_until(
            lambda _py, c: any(event.get("event") == "complete" for event in c),
            max_steps=500000,
        )
        harness.drive_peer_exit()

        assert py_fs.files["upload.bin"] == upload
        assert peer.events_named("list_done")[-1]["count"] == len(served)
        for path, data in sorted(served.items()):
            assert peer.file_hex(path) == data.hex(), path
        assert peer.events_named("put_done")[-1] == {
            "event": "put_done",
            "path": "upload.bin",
            "size": len(upload),
            "crc32": crc32(upload),
        }
        served_get_paths = sorted(
            event.path for event in harness.py_events if isinstance(event, GetServed)
        )
        assert served_get_paths == sorted(served)
        return session
    finally:
        peer.kill()


def _run_both_directions(
    *,
    py_to_c: Optional[FaultProfile] = None,
    c_to_py: Optional[FaultProfile] = None,
    batch_count: int = BATCH_COUNT,
) -> tuple[Session, Session]:
    controller = _run_py_controller_c_responder(
        py_to_c=py_to_c, c_to_py=c_to_py, batch_count=batch_count
    )
    responder = _run_c_controller_py_responder(
        py_to_c=py_to_c, c_to_py=c_to_py, batch_count=batch_count
    )
    return controller, responder


def _frames_crc_fail(session: Session) -> int:
    """Frame-parser CRC reject count (private introspection, as in demo.py)."""

    return session._parser.diag.frames_crc_fail


def _idle_python_passthrough(data: bytes) -> bytes:
    session = Session(Role.CONTROLLER)
    events = session.receive_bytes(data, 0)
    return b"".join(
        event.data for event in events if isinstance(event, Passthrough)
    )


def _idle_c_passthrough(data: bytes) -> bytes:
    peer = CPeer(["--role", "responder", "--seed", "0xD17AA"])
    try:
        peer.send(data)
        for _ in range(200):
            peer.read_available(0.001)
            got = b"".join(
                bytes.fromhex(event["hex"])
                for event in peer.events_named("passthrough")
            )
            if got == data:
                return got
        raise AssertionError(f"c_peer passthrough mismatch: {peer.events!r}")
    finally:
        peer.close_stdin()
        peer.kill()


def test_chatter_between_frames() -> None:
    chatter = b"STATUS?\r\nLOG: boot ready\r\n"
    assert _idle_python_passthrough(chatter) == chatter
    assert _idle_c_passthrough(chatter) == chatter

    profile = FaultProfile(inject_ascii=chatter, inject_at=1400)
    _run_both_directions(py_to_c=profile, c_to_py=profile)


def test_chatter_inside_frame() -> None:
    profile = FaultProfile(inject_ascii=b"DBG:tick=12345\r\n", inject_at=96)
    _run_both_directions(py_to_c=profile, c_to_py=profile)


def test_binary_garbage_flood() -> None:
    garbage = bytes([0, 255, 0x7E, 0x11]) + _blob(0xD17BAD, 4092)
    assert 0 in garbage
    profile = FaultProfile(inject_ascii=garbage, inject_at=1536)
    _run_both_directions(py_to_c=profile, c_to_py=profile)


def test_bt_overrun_burst_loss() -> None:
    for burst_len in (64, 256):
        profile = FaultProfile(burst_len=burst_len, burst_at=2200)
        _run_both_directions(py_to_c=profile, c_to_py=profile)
    profile = FaultProfile(burst_len=600, burst_at=2200)
    _run_py_controller_c_responder(c_to_py=profile)
    _run_c_controller_py_responder(py_to_c=profile)


def test_random_byte_corruption() -> None:
    """1-permille random byte flips in both directions kill roughly 40% of
    data frames; every file must still arrive byte-exact."""

    profile = FaultProfile(corrupt_permille=1)
    controller, responder = _run_both_directions(
        py_to_c=profile, c_to_py=profile, batch_count=10
    )
    assert _frames_crc_fail(controller) > 0
    assert _frames_crc_fail(responder) > 0


def test_random_byte_drops() -> None:
    """1-permille random single-byte loss shifts the stream mid-frame,
    unlike burst loss which removes whole frames."""

    profile = FaultProfile(drop_permille=1)
    controller, responder = _run_both_directions(
        py_to_c=profile, c_to_py=profile, batch_count=10
    )
    assert _frames_crc_fail(controller) > 0
    assert _frames_crc_fail(responder) > 0


def test_noisy_line_combined() -> None:
    """Bit flips toward one peer, byte loss toward the other, everything in
    odd 17-byte chunks. Per-direction damage stays near 1 permille: beyond
    roughly 2 permille the N_RETRY backstop kills the session by design
    (covered by test_hostile_line_dies_clean)."""

    flips = FaultProfile(corrupt_permille=1, rechunk=17)
    drops = FaultProfile(drop_permille=1, rechunk=17)
    controller, responder = _run_both_directions(
        py_to_c=flips, c_to_py=drops, batch_count=10
    )
    assert _frames_crc_fail(controller) > 0
    assert _frames_crc_fail(responder) > 0


def test_hostile_line_dies_clean() -> None:
    """A line damaged beyond the retry budget (4-permille flips both ways
    kills ~90% of data frames) must end in ABORT(E_TIMEOUT) with the
    partial download discarded, never a committed file."""

    remote = {"doomed.bin": _blob(0xD17DEAD, 32 * 1024)}
    profile = FaultProfile(corrupt_permille=4)
    py_fs = MemoryFs()
    peer = CPeer(["--role", "responder", "--seed", "0xD17DE"] + _file_args(remote))
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x51, fs=py_fs)
        harness = _make_harness(peer, session, py_to_c=profile, c_to_py=profile)

        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established), max_steps=80000)

        session.request_get("doomed.bin", now_ms=harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Ended), max_steps=80000)

        ended = [event for event in harness.py_events if isinstance(event, Ended)]
        assert ended[-1].reason is AbortReason.E_TIMEOUT
        assert py_fs.files == {}
        assert not py_fs.writing
    finally:
        peer.close_stdin()
        peer.kill()


def test_hello_collision() -> None:
    remote = {"hello.bin": b"collision-ok"}
    peer = CPeer(
        ["--role", "responder", "--start", "--seed", "0xD17"]
        + _file_args(remote)
    )
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x42, fs=MemoryFs())
        harness = _make_harness(peer, session)

        session.start(harness.now_ms)
        harness.drive_until(
            lambda py, c: has_py_event(py, Established)
            and bool(peer.events_named("established")),
            max_steps=80000,
        )

        session.request_get("hello.bin", now_ms=harness.now_ms)
        harness.drive_until(
            lambda py, _c: any(
                isinstance(event, GetDone) and event.path == "hello.bin"
                for event in py
            ),
            max_steps=120000,
        )
    finally:
        peer.close_stdin()
        peer.kill()


def test_stale_session_frames() -> None:
    remote = {"fresh.bin": _blob(0xD1751D, BATCH_SIZE)}
    peer = CPeer(
        ["--role", "responder", "--seed", "0xD1751"] + _file_args(remote)
    )
    py_fs = MemoryFs()
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x33, fs=py_fs)
        harness = _make_harness(peer, session)

        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established), max_steps=80000)
        sid = _established_sid(harness.py_events)
        stale_sid = sid ^ 0x55
        if stale_sid == 0 or stale_sid == sid:
            stale_sid = 0x7E
        stale_data = build_frame(FrameType.DATA, stale_sid, 0, 0, b"\x50\x00\x00\x00\x00")
        stale_ack = build_frame(FrameType.ACK, stale_sid, 1, 0)

        harness.py_events += session.receive_bytes(stale_data + stale_ack, harness.now_ms)
        peer.send(stale_data + stale_ack)

        session.request_get("fresh.bin", now_ms=harness.now_ms)
        harness.drive_until(
            lambda py, _c: any(
                isinstance(event, GetDone) and event.path == "fresh.bin"
                for event in py
            ),
            max_steps=160000,
        )
        assert py_fs.files["fresh.bin"] == remote["fresh.bin"]
    finally:
        peer.close_stdin()
        peer.kill()


def test_slow_1byte_delivery() -> None:
    profile = FaultProfile(rechunk=1)
    _run_both_directions(py_to_c=profile, c_to_py=profile)


def test_duplicate_acks() -> None:
    profile = FaultProfile(duplicate_ack_permille=1000)
    _run_both_directions(py_to_c=profile, c_to_py=profile)


def test_abort_mid_file_cleanup() -> None:
    remote = {"large.bin": _blob(0xD17A80, 32 * 1024)}
    py_fs = MemoryFs()
    peer = CPeer(
        ["--role", "responder", "--seed", "0xD17AB"] + _file_args(remote)
    )
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x61, fs=py_fs)
        harness = _make_harness(peer, session)
        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established), max_steps=80000)
        sid = _established_sid(harness.py_events)

        session.request_get("large.bin", now_ms=harness.now_ms)
        for _ in range(1000):
            harness.step()
            if py_fs.writing:
                break
        assert py_fs.writing
        abort = build_frame(FrameType.ABORT, sid, 0, 0, bytes([AbortReason.E_USER]))
        harness.py_events += session.receive_bytes(abort, harness.now_ms)

        assert any(
            isinstance(event, Ended)
            and event.reason is AbortReason.E_USER
            and event.from_peer
            for event in harness.py_events
        )
        assert "large.bin" not in py_fs.files
        assert not py_fs.writing
    finally:
        peer.close_stdin()
        peer.kill()

    upload = _blob(0xD17A81, 32 * 1024)
    py_fs = MemoryFs({"upload.bin": upload})
    peer = CPeer(["--role", "responder", "--seed", "0xD17AC"])
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x62, fs=py_fs)
        harness = _make_harness(peer, session)
        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established), max_steps=80000)
        sid = _established_sid(harness.py_events)

        session.request_put("upload.bin", now_ms=harness.now_ms)
        for _ in range(1000):
            harness.step()
            if peer.events_named("fs_write_started"):
                break
        write_started = peer.events_named("fs_write_started")[-1]
        assert write_started["path"] == "upload.bin"
        assert 0 < write_started["bytes"] < len(upload)
        abort = build_frame(FrameType.ABORT, sid, 0, 0, bytes([AbortReason.E_USER]))
        peer.send(abort)
        for _ in range(1000):
            harness.step()
            if peer.events_named("ended"):
                break
        assert peer.events_named("ended")
        harness.py_events += session.receive_bytes(abort, harness.now_ms)
        peer.close_stdin()
        harness.drive_peer_exit()
        assert peer.file_hex("upload.bin") is None
    finally:
        peer.kill()


def test_reconnect_resume() -> None:
    remote = {
        "resume/a.bin": _blob(0xD17E00, BATCH_SIZE),
        "resume/b.bin": _blob(0xD17E01, BATCH_SIZE),
        "resume/c.bin": _blob(0xD17E02, BATCH_SIZE),
    }
    py_fs = MemoryFs()

    peer = CPeer(["--role", "responder", "--seed", "0xD17E1"] + _file_args(remote))
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x71, fs=py_fs)
        harness = _make_harness(peer, session)
        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established), max_steps=80000)
        sid = _established_sid(harness.py_events)

        session.request_get("resume/a.bin", now_ms=harness.now_ms)
        harness.drive_until(
            lambda py, _c: any(
                isinstance(event, GetDone) and event.path == "resume/a.bin"
                for event in py
            ),
            max_steps=120000,
        )
        session.request_get("resume/b.bin", now_ms=harness.now_ms)
        for _ in range(1000):
            harness.step()
            if py_fs.writing:
                break
        assert py_fs.writing
        harness.py_events += session.receive_bytes(
            build_frame(FrameType.ABORT, sid, 0, 0, bytes([AbortReason.E_USER])),
            harness.now_ms,
        )
    finally:
        peer.close_stdin()
        peer.kill()

    assert py_fs.files == {"resume/a.bin": remote["resume/a.bin"]}
    peer = CPeer(["--role", "responder", "--seed", "0xD17E2"] + _file_args(remote))
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x72, fs=py_fs)
        harness = _make_harness(peer, session)
        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established), max_steps=80000)

        session.request_list("resume", want_crc=True, now_ms=harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, ListDone), max_steps=120000)
        for path, data in sorted(remote.items()):
            if py_fs.files.get(path) == data:
                continue
            session.request_get(path, now_ms=harness.now_ms)
            harness.drive_until(_got_get_done(path), max_steps=120000)
        assert py_fs.files == remote
    finally:
        peer.close_stdin()
        peer.kill()

    served = {
        "resume/a.bin": remote["resume/a.bin"],
        "resume/b.bin": remote["resume/b.bin"],
    }
    peer = CPeer(
        ["--role", "controller", "--seed", "0xD17E3", "--get", "resume/a.bin", "--get", "resume/b.bin"]
    )
    try:
        session = Session(Role.RESPONDER, fs=MemoryFs(served))
        harness = _make_harness(peer, session)
        for _ in range(160000):
            harness.step()
            if any(
                event.get("event") == "action_started"
                and event.get("kind") == "get"
                and event.get("path") == "resume/b.bin"
                for event in peer.events
            ):
                break
        assert any(
            event.get("event") == "get_done" and event.get("path") == "resume/a.bin"
            for event in peer.events
        )
        assert any(
            event.get("event") == "action_started"
            and event.get("kind") == "get"
            and event.get("path") == "resume/b.bin"
            for event in peer.events
        )
        sid = int(peer.events_named("established")[-1]["sid"])
        peer.send(build_frame(FrameType.ABORT, sid, 0, 0, bytes([AbortReason.E_USER])))
        peer.close_stdin()
        harness.drive_peer_exit()
        assert peer.file_hex("resume/a.bin") == served["resume/a.bin"].hex()
        assert peer.file_hex("resume/b.bin") is None
    finally:
        peer.kill()

    peer = CPeer(
        [
            "--role",
            "controller",
            "--seed",
            "0xD17E4",
            "--file",
            f"resume/a.bin=hex:{served['resume/a.bin'].hex()}",
            "--list",
            "resume",
            "--get",
            "resume/b.bin",
        ]
    )
    try:
        session = Session(Role.RESPONDER, fs=MemoryFs(served))
        harness = _make_harness(peer, session)
        harness.drive_until(
            lambda _py, c: any(event.get("event") == "complete" for event in c),
            max_steps=200000,
        )
        harness.drive_peer_exit()
        assert peer.file_hex("resume/a.bin") == served["resume/a.bin"].hex()
        assert peer.file_hex("resume/b.bin") == served["resume/b.bin"].hex()
    finally:
        peer.kill()
