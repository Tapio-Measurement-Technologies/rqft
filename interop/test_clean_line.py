# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Clean-line C/Python session interop tests."""

from __future__ import annotations

from rqft.crc32 import crc32
from rqft.events import Ended, EntryListed, Established, GetDone, GetServed, ListDone
from rqft.events import PutDone as PutDoneEvent
from rqft.link import AbortReason
from rqft.messages import Role
from rqft.session import Session

from harness import CPeer, InteropHarness, MemoryFs, has_py_event


def test_python_controller_to_c_responder_list_get_put() -> None:
    """Python controller drives LIST, GET, and PUT against c_peer responder."""

    py_fs = MemoryFs({"upload.bin": b"bravo-data"})
    peer = CPeer(
        [
            "--role",
            "responder",
            "--seed",
            "0xC016",
            "--file",
            "a.data=text:alpha",
            "--file",
            "logs/run1.data=text:first run",
        ]
    )
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x42, fs=py_fs)
        harness = InteropHarness(peer, session)

        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established))

        session.request_list("", want_crc=True, now_ms=harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, ListDone))
        listed = {
            event.path: event
            for event in harness.py_events
            if isinstance(event, EntryListed)
        }
        assert set(listed) == {"a.data", "logs/run1.data"}
        assert listed["a.data"].size == 5
        assert listed["a.data"].crc32 == crc32(b"alpha")

        session.request_get("a.data", now_ms=harness.now_ms)
        harness.drive_until(
            lambda py, _c: any(
                isinstance(event, GetDone) and event.path == "a.data" for event in py
            )
        )
        assert py_fs.files["a.data"] == b"alpha"

        session.request_put("upload.bin", now_ms=harness.now_ms)
        harness.drive_until(
            lambda py, _c: any(
                isinstance(event, PutDoneEvent) and event.path == "upload.bin"
                for event in py
            )
        )

        peer.close_stdin()
        harness.drive_peer_exit()
        assert peer.file_hex("upload.bin") == b"bravo-data".hex()
        assert peer.events_named("get_served")[-1] == {
            "event": "get_served",
            "path": "a.data",
            "size": 5,
            "crc32": crc32(b"alpha"),
        }
    finally:
        peer.kill()


def test_c_responder_cancels_mid_get() -> None:
    """c_peer responder cancels an in-flight GET via rqft_session_abort."""

    big = bytes(range(256)) * 32
    py_fs = MemoryFs()
    peer = CPeer(
        [
            "--role",
            "responder",
            "--seed",
            "0xCA9CE1",
            "--file",
            "big.bin=hex:" + big.hex(),
            "--cancel-after-bytes",
            "2048",
        ]
    )
    try:
        session = Session(Role.CONTROLLER, sid_source=lambda: 0x42, fs=py_fs)
        harness = InteropHarness(peer, session)

        session.start(harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Established))

        session.request_get("big.bin", now_ms=harness.now_ms)
        harness.drive_until(lambda py, _c: has_py_event(py, Ended))

        ended = [event for event in harness.py_events if isinstance(event, Ended)]
        assert ended == [Ended(AbortReason.E_USER, from_peer=True)]
        assert not has_py_event(harness.py_events, GetDone)
        assert "big.bin" not in py_fs.files
        assert not py_fs.writing

        assert peer.events_named("cancelled")
        assert not peer.events_named("get_served")
        harness.drive_peer_exit()
        assert peer.events_named("ended")[-1] == {
            "event": "ended",
            "reason": int(AbortReason.E_USER),
            "from_peer": False,
        }
    finally:
        peer.kill()


def test_c_controller_to_python_responder_list_get_put() -> None:
    """c_peer controller drives LIST, GET, and PUT against Python responder."""

    py_fs = MemoryFs(
        {
            "a.data": b"alpha",
            "logs/run1.data": b"first run",
        }
    )
    peer = CPeer(
        [
            "--role",
            "controller",
            "--seed",
            "0xD016",
            "--file",
            "upload.bin=text:from-c",
            "--list",
            "",
            "--get",
            "a.data",
            "--put",
            "upload.bin",
        ]
    )
    try:
        session = Session(Role.RESPONDER, fs=py_fs)
        harness = InteropHarness(peer, session)
        harness.drive_until(
            lambda _py, c: any(event.get("event") == "complete" for event in c),
            max_steps=30000,
        )
        harness.drive_peer_exit()

        assert py_fs.files["upload.bin"] == b"from-c"
        assert GetServed("a.data", 5, crc32(b"alpha")) in harness.py_events
        assert peer.events_named("list_done")[-1]["count"] == 2
        assert {
            event["path"] for event in peer.events_named("list_entry")
        } == {"a.data", "logs/run1.data"}
        assert peer.events_named("get_done")[-1] == {
            "event": "get_done",
            "path": "a.data",
            "size": 5,
            "crc32": crc32(b"alpha"),
        }
        assert peer.events_named("put_done")[-1] == {
            "event": "put_done",
            "path": "upload.bin",
            "size": 6,
            "crc32": crc32(b"from-c"),
        }
        assert peer.file_hex("a.data") == b"alpha".hex()
    finally:
        peer.kill()
