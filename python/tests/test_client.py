# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""SyncClient integration tests."""

from __future__ import annotations

import sys
import threading
from collections import deque
from pathlib import Path
from typing import Callable, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
INTEROP = ROOT / "interop"
if str(INTEROP) not in sys.path:
    sys.path.insert(0, str(INTEROP))

from harness import CPeer, CPeerTransport
from rqft.client import (
    BlockingSessionDriver,
    LocalDirFs,
    LocalFile,
    ProgressPhase,
    SyncCancelled,
    SyncClient,
    SyncProgress,
)
from rqft.events import Ended, Established, ListDone, SessionEvent
from rqft.frame import T_FLUSH_MS, FrameType, build_frame
from rqft.link import AbortReason
from rqft.messages import Hello, HelloOk, Role
from rqft.session import Session


class _CancelAfterTempWriteTransport:
    """Transport wrapper that requests cancellation after a temp file receives bytes."""

    def __init__(
        self,
        inner: CPeerTransport,
        root: Path,
        path: str,
        cancel: threading.Event,
    ) -> None:
        self._inner = inner
        self._temp = root / f"{path}.rqft-part"
        self._cancel = cancel

    def write(self, data: bytes) -> None:
        self._inner.write(data)

    def read(self, max_len: int, timeout: float) -> bytes:
        data = self._inner.read(max_len, timeout)
        if data and self._temp.exists():
            self._cancel.set()
        return data

    def close(self) -> None:
        self._inner.close()


class _FailingTransport:
    """Tiny transport double for surfacing host I/O failures."""

    def __init__(
        self,
        *,
        read_error: Optional[OSError] = None,
        write_error: Optional[OSError] = None,
    ) -> None:
        self._read_error = read_error
        self._write_error = write_error
        self.closed = False

    def write(self, data: bytes) -> None:
        if self._write_error is not None:
            raise self._write_error

    def read(self, max_len: int, timeout: float) -> bytes:
        if self._read_error is not None:
            raise self._read_error
        return b""

    def close(self) -> None:
        self.closed = True


class _ScriptedTransport:
    """Transport double with queued reads and captured writes."""

    def __init__(self, reads: list[bytes]) -> None:
        self._reads = deque(reads)
        self.writes: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def read(self, max_len: int, timeout: float) -> bytes:
        return self._reads.popleft() if self._reads else b""

    def close(self) -> None:
        self.closed = True


def _file_args(files: dict[str, bytes]) -> list[str]:
    args: list[str] = []
    for path, data in sorted(files.items()):
        args += ["--file", f"{path}=hex:{data.hex()}"]
    return args


def _write(root: Path, path: str, data: bytes) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _read(root: Path, path: str) -> bytes:
    return (root / path).read_bytes()


def test_local_dir_fs_scans_public_file_metadata(tmp_path: Path) -> None:
    """Public directory provider returns typed size and CRC metadata."""

    _write(tmp_path, "nested/data.bin", b"payload")
    _write(tmp_path, "ignored.rqft-part", b"partial")

    filesystem = LocalDirFs(tmp_path)

    assert filesystem.scan() == {
        "nested/data.bin": LocalFile("nested/data.bin", 7, 0x422C6A15)
    }
    assert filesystem.file_info("nested/data.bin") == LocalFile(
        "nested/data.bin", 7, 0x422C6A15
    )


def test_blocking_session_driver_pumps_one_typed_turn() -> None:
    """Shared driver flushes, reads, and returns activity with typed events."""

    session = Session(Role.CONTROLLER, sid_source=lambda: 0x52)
    session.start(now_ms=0)
    hello_ok = build_frame(
        FrameType.HELLO_OK,
        0x52,
        0,
        0,
        HelloOk(1, Role.RESPONDER, 512, 4, 0).encode(),
    )
    transport = _ScriptedTransport([hello_ok])
    clock: Callable[[], float] = lambda: 0.0
    driver = BlockingSessionDriver(transport, session, clock=clock)

    result = driver.pump(max_wait_s=0.0)

    assert result.events == (Established(0x52, 1, Role.CONTROLLER, 512, 4, 0),)
    assert result.bytes_received == len(hello_ok)
    assert len(transport.writes) == 1


def test_blocking_session_driver_drains_rx_before_due_idle_flush() -> None:
    """A buffered trailing delimiter completes its frame before timer polling."""

    session = Session(Role.RESPONDER)
    hello = build_frame(
        FrameType.HELLO,
        0x53,
        0,
        0,
        Hello(1, 1, Role.CONTROLLER, 512, 4, 0).encode(),
    )
    assert session.receive_bytes(hello[:-1], now_ms=0) == []

    clock_s = [0.0]
    transport = _ScriptedTransport([hello[-1:]])
    driver = BlockingSessionDriver(transport, session, clock=lambda: clock_s[0])
    clock_s[0] = T_FLUSH_MS / 1000.0

    result = driver.pump(max_wait_s=0.0)

    assert result.events == (
        Established(0x53, 1, Role.RESPONDER, 512, 4, 0),
    )
    assert result.bytes_received == 1
    assert session.diagnostics().valid_candidates_idle_flushed == 0


def test_sync_client_drains_events_after_operation_result(tmp_path: Path) -> None:
    """Trailing ENDED state is retained after a completed client operation."""

    client = SyncClient(_FailingTransport(), tmp_path)
    client._connected = True
    client._established = Established(1, 1, Role.CONTROLLER, 512, 4, 0)
    events: list[SessionEvent] = [
        ListDone(0),
        Ended(AbortReason.CLOSE, from_peer=True),
    ]

    result = client._handle_events(
        events,
        lambda event: "listed" if isinstance(event, ListDone) else None,
    )

    assert result == "listed"
    assert not client._connected
    assert client._established is None


def test_sync_client_lists_diffs_gets_deletes_and_closes(tmp_path: Path) -> None:
    """SyncClient drives the happy path against a c_peer responder."""

    remote = {
        "already.bin": b"same-content",
        "nested/missing.bin": b"download-me",
    }
    _write(tmp_path, "already.bin", remote["already.bin"])
    progress: list[SyncProgress] = []
    peer = CPeer(["--role", "responder", "--seed", "0xD18A"] + _file_args(remote))
    try:
        client = SyncClient(
            CPeerTransport(peer),
            tmp_path,
            sid_source=lambda: 0x52,
            progress=progress.append,
        )

        result = client.sync_from_peer(delete_remote=True, timeout_s=20.0)
        peer.assert_clean_exit()

        assert _read(tmp_path, "already.bin") == remote["already.bin"]
        assert _read(tmp_path, "nested/missing.bin") == remote["nested/missing.bin"]
        assert [entry.path for entry in result.skipped] == ["already.bin"]
        assert [entry.path for entry in result.fetched] == ["nested/missing.bin"]
        assert result.deleted == ("nested/missing.bin",)
        assert peer.events_named("plan")[-1] == {
            "event": "plan",
            "nfiles": 1,
            "nbytes": len(remote["nested/missing.bin"]),
        }
        assert peer.file_hex("already.bin") == remote["already.bin"].hex()
        assert peer.file_hex("nested/missing.bin") is None
        assert [event.phase for event in progress] == [
            ProgressPhase.PLAN,
            ProgressPhase.GET,
            ProgressPhase.DEL,
            ProgressPhase.DONE,
        ]
        bytes_done = [event.bytes_done for event in progress]
        assert bytes_done == sorted(bytes_done)
        assert {event.bytes_total for event in progress} == {
            len(remote["nested/missing.bin"])
        }
    finally:
        peer.kill()


def test_sync_client_cancels_mid_batch_with_user_abort(tmp_path: Path) -> None:
    """Cancellation event aborts the active session between batch files."""

    remote = {
        "batch/0.bin": b"zero",
        "batch/1.bin": b"one" * 100,
        "batch/2.bin": b"two" * 100,
    }
    cancel = threading.Event()
    progress: list[SyncProgress] = []

    def on_progress(event: SyncProgress) -> None:
        progress.append(event)
        if event.phase is ProgressPhase.GET and event.files_done == 1:
            cancel.set()

    peer = CPeer(["--role", "responder", "--seed", "0xD18B"] + _file_args(remote))
    try:
        client = SyncClient(
            CPeerTransport(peer),
            tmp_path,
            sid_source=lambda: 0x53,
            progress=on_progress,
            cancel_event=cancel,
        )

        with pytest.raises(SyncCancelled):
            client.sync_from_peer(timeout_s=20.0)
        peer.assert_clean_exit()

        assert _read(tmp_path, "batch/0.bin") == remote["batch/0.bin"]
        assert not (tmp_path / "batch/1.bin").exists()
        assert not (tmp_path / "batch/2.bin").exists()
        assert progress[-1].phase is ProgressPhase.GET
        assert progress[-1].bytes_done == len(remote["batch/0.bin"])
        ended = peer.events_named("ended")
        assert ended and ended[-1]["reason"] == 6
    finally:
        peer.kill()


def test_sync_client_cancels_mid_file_with_user_abort(tmp_path: Path) -> None:
    """Cancellation aborts an active GET and discards the partial temp file."""

    remote = {"large.bin": bytes(range(256)) * 64}
    cancel = threading.Event()
    progress: list[SyncProgress] = []
    peer = CPeer(["--role", "responder", "--seed", "0xD18C"] + _file_args(remote))
    try:
        transport = _CancelAfterTempWriteTransport(
            CPeerTransport(peer), tmp_path, "large.bin", cancel
        )
        client = SyncClient(
            transport,
            tmp_path,
            sid_source=lambda: 0x54,
            progress=progress.append,
            cancel_event=cancel,
            read_size=64,
        )

        with pytest.raises(SyncCancelled):
            client.sync_from_peer(timeout_s=20.0)
        peer.assert_clean_exit()

        assert not (tmp_path / "large.bin").exists()
        assert not (tmp_path / "large.bin.rqft-part").exists()
        assert [event.phase for event in progress] == [ProgressPhase.PLAN]
        ended = peer.events_named("ended")
        assert ended and ended[-1]["reason"] == 6
    finally:
        peer.kill()


def test_sync_client_surfaces_transport_read_errors(tmp_path: Path) -> None:
    """Read-side connection failures are not converted into timeouts."""

    transport = _FailingTransport(read_error=ConnectionResetError("connection reset"))
    client = SyncClient(transport, tmp_path, sid_source=lambda: 0x55)

    with pytest.raises(ConnectionResetError, match="connection reset"):
        client.connect(timeout_s=1.0)


def test_sync_client_surfaces_transport_write_errors(tmp_path: Path) -> None:
    """Write-side connection failures are not hidden by the pump."""

    transport = _FailingTransport(write_error=BrokenPipeError("broken pipe"))
    client = SyncClient(transport, tmp_path, sid_source=lambda: 0x56)

    with pytest.raises(BrokenPipeError, match="broken pipe"):
        client.connect(timeout_s=1.0)
