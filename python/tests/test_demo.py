# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Interactive demo client behavior tests."""

from __future__ import annotations

import io
import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Optional, cast

import pytest

import rqft.demo as demo
from rqft.client import ByteTransport, LocalDirFs, PumpResult
from rqft.demo import (
    CountingTransport,
    DebugLog,
    DemoError,
    DeviceWorker,
    ListResult,
    Repl,
    Style,
)
from rqft.events import (
    Ended,
    EntryListed,
    EntrySkipped,
    Established,
    GetDone,
    GetServed,
    ListDone,
    SessionEvent,
)
from rqft.link import AbortReason
from rqft.messages import ErrCode, MsgType, Role
from rqft.session import SessionDiagnostics, TransferPhase, TransferProgress


class _NullTransport:
    """Transport double that stays quiet and records closure."""

    def __init__(self) -> None:
        self.closed = False

    def write(self, data: bytes) -> None:
        pass

    def read(self, max_len: int, timeout: float) -> bytes:
        return b""

    def close(self) -> None:
        self.closed = True


class _BlockingTransport:
    """Transport whose read returns only after close unblocks it."""

    def __init__(self) -> None:
        self.read_started = threading.Event()
        self._release = threading.Event()
        self.closed = False

    def write(self, data: bytes) -> None:
        pass

    def read(self, max_len: int, timeout: float) -> bytes:
        self.read_started.set()
        self._release.wait()
        return b""

    def close(self) -> None:
        self.closed = True
        self._release.set()


class _TtyBuffer(io.StringIO):
    """Text buffer that enables terminal-only progress rendering."""

    def isatty(self) -> bool:
        return True


class _FlappingTransport:
    """Transport whose reads fail until told to recover."""

    def __init__(self) -> None:
        self.fail = True
        self.failures = 0
        self.closed = False

    def write(self, data: bytes) -> None:
        pass

    def read(self, max_len: int, timeout: float) -> bytes:
        if self.fail:
            self.failures += 1
            raise OSError(5, "Input/output error")
        return b""

    def close(self) -> None:
        self.closed = True


def _wait_until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


def _worker(tmp_path: Path) -> tuple[DeviceWorker, _NullTransport]:
    transport = _NullTransport()
    worker = DeviceWorker(
        CountingTransport(transport),
        LocalDirFs(tmp_path),
        DebugLog(Style(False)),
    )
    return worker, transport


def test_device_worker_shutdown_does_not_shadow_thread_stop(tmp_path: Path) -> None:
    """Worker shutdown remains compatible with every supported Python."""

    worker, transport = _worker(tmp_path)

    assert "_stop" not in vars(worker)

    worker.start()
    worker.shutdown()

    assert not worker.is_alive()
    assert transport.closed


def test_device_worker_shutdown_unblocks_transport_before_join(tmp_path: Path) -> None:
    """Shutdown closes a blocking transport before waiting for worker exit."""

    transport = _BlockingTransport()
    worker = DeviceWorker(
        CountingTransport(transport),
        LocalDirFs(tmp_path),
        DebugLog(Style(False)),
    )
    worker.start()
    assert transport.read_started.wait(timeout=1.0)

    started = time.monotonic()
    worker.shutdown()

    assert time.monotonic() - started < 1.0
    assert transport.closed
    assert not worker.is_alive()


def test_device_worker_consumes_events_after_operation_result(tmp_path: Path) -> None:
    """Trailing session events update state after an operation completes."""

    worker, _ = _worker(tmp_path)
    worker._established = Established(1, 1, Role.CONTROLLER, 512, 4, 0)
    events: list[SessionEvent] = [
        ListDone(0),
        Ended(AbortReason.CLOSE, from_peer=True),
    ]

    result = worker._consume(
        events,
        lambda event: "listed" if isinstance(event, ListDone) else None,
    )

    assert result == "listed"
    assert worker.established is None


def test_device_worker_preserves_informational_list_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LIST returns unreadable-entry reports alongside received entries."""

    worker, _ = _worker(tmp_path)
    worker._established = Established(1, 1, Role.CONTROLLER, 512, 4, 0)
    entry = EntryListed(0, "readable.bin", 4, 0, 0x12345678)
    skipped = EntrySkipped(ErrCode.E_FS_READ, 7)

    def drive(
        accept: Callable[[SessionEvent], Optional[object]],
    ) -> object:
        result: Optional[object] = None
        for event in (entry, skipped, ListDone(1)):
            candidate = accept(event)
            if candidate is not None:
                result = candidate
        assert result is not None
        return result

    monkeypatch.setattr(worker._session, "request_list", lambda *args, **kwargs: None)
    monkeypatch.setattr(worker, "_drive", drive)

    listing = worker._op_list("", want_crc=True)

    assert listing.entries == (entry,)
    assert listing.skipped == (skipped,)


def test_device_worker_logs_retransmitted_frame_delta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each pump exposes new link retransmissions through the debug log."""

    log = DebugLog(Style(False))
    worker = DeviceWorker(
        CountingTransport(_NullTransport()),
        LocalDirFs(tmp_path),
        log,
    )
    diagnostics = SessionDiagnostics(
        frames_ok=0,
        frames_crc_fail=0,
        frames_oversize=0,
        frames_dropped=0,
        candidates_idle_flushed=0,
        valid_candidates_idle_flushed=0,
        bytes_idle_flushed=0,
        frames_wrong_sid=0,
        frames_retransmitted=3,
        naks_sent=0,
        duplicate_data_received=0,
        out_of_order_data_received=0,
        bytes_passthrough=0,
        bytes_dropped_in_session=0,
        srtt_ms=None,
        rttvar_ms=None,
        rto_ms=1000,
        in_flight=3,
    )
    monkeypatch.setattr(worker._driver, "pump", lambda max_wait_s: PumpResult((), 0))
    monkeypatch.setattr(worker._session, "diagnostics", lambda: diagnostics)

    worker._pump(max_wait_s=0.02)

    assert [(category, message) for _, category, message in log.tail(1)] == [
        ("RTX", "3 DATA frames retransmitted (3 total)"),
    ]


def test_idle_pump_logs_repeated_transport_errors_once(tmp_path: Path) -> None:
    """A dead transport produces one idle-pump error, then one recovery."""

    transport = _FlappingTransport()
    log = DebugLog(Style(False))
    worker = DeviceWorker(CountingTransport(transport), LocalDirFs(tmp_path), log)
    worker.start()
    try:
        _wait_until(lambda: transport.failures >= 3)
        errors = [msg for _, cat, msg in log.tail(100) if cat == "ERR"]
        assert len(errors) == 1
        assert "repeats suppressed" in errors[0]

        transport.fail = False
        _wait_until(
            lambda: any(
                cat == "SES" and msg == "idle pump recovered"
                for _, cat, msg in log.tail(100)
            )
        )
    finally:
        worker.shutdown()


def test_stats_identifies_idle_flushed_valid_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Stats separates missing delimiters from generic foreign bytes."""

    worker, _ = _worker(tmp_path)
    snapshot = SimpleNamespace(
        connected=True,
        state="ACTIVE",
        established=None,
        uptime_s=1.0,
        srtt_ms=100,
        rttvar_ms=10,
        rto_ms=140,
        in_flight=0,
        frames_ok=10,
        frames_crc_fail=0,
        frames_oversize=0,
        frames_dropped=0,
        frames_wrong_sid=0,
        frames_retransmitted=0,
        naks_sent=3,
        duplicate_data_received=2,
        out_of_order_data_received=1,
        candidates_idle_flushed=3,
        valid_candidates_idle_flushed=3,
        bytes_idle_flushed=1536,
        bytes_passthrough=0,
        bytes_dropped_in_session=1536,
        tx_bytes=0,
        rx_bytes=0,
        ops_ok=0,
        ops_failed=0,
        files_down=0,
        files_up=0,
        bytes_down=0,
        bytes_up=0,
        deletes=0,
    )
    monkeypatch.setattr(worker, "stats", lambda: snapshot)

    Repl(worker, DebugLog(Style(False)), Style(False))._cmd_stats([])

    rendered = capsys.readouterr().out
    assert "NAKs sent" in rendered
    assert "duplicate=2 gap=1" in rendered
    assert "idle-flushed" in rendered
    assert "candidates=3 valid=3 bytes=1.5 KiB" in rendered


def test_ls_refreshes_missing_crcs_before_rendering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """LS restores CRC metadata omitted from the initial fast listing."""

    worker, _ = _worker(tmp_path)
    repl = Repl(worker, DebugLog(Style(False)), Style(False))
    repl._update_cache((EntryListed(0, "payload.bin", 4, 0, None),))
    requests: list[tuple[str, bool]] = []

    def list_remote(root: str = "", want_crc: bool = False) -> ListResult:
        requests.append((root, want_crc))
        return ListResult(
            (EntryListed(0, "payload.bin", 4, 0, 0x12345678),),
            (),
        )

    monkeypatch.setattr(worker, "list_remote", list_remote)

    repl._cmd_ls([])

    assert requests == [("", True)]
    assert "crc 0x12345678" in capsys.readouterr().out


def test_repl_progress_distinguishes_put_hash_and_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PUT display labels hash work separately from wire streaming."""

    worker, _ = _worker(tmp_path)
    output = _TtyBuffer()
    ticks = iter((1.0, 1.2, 1.4))
    monkeypatch.setattr(sys, "stdout", output)
    monkeypatch.setattr("rqft.demo.time.monotonic", lambda: next(ticks))
    callback = Repl(worker, DebugLog(Style(False)), Style(False))._progress_printer(
        "payload.bin"
    )

    callback(TransferProgress(MsgType.PUT_REQ, TransferPhase.HASH, 512, 1024))
    callback(TransferProgress(MsgType.PUT_REQ, TransferPhase.STREAM, 128, 1024))

    rendered = output.getvalue()
    assert "hash payload.bin" in rendered
    assert "put payload.bin" in rendered


def test_cat_rejects_large_file_before_reading_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Large cat downloads stay on disk instead of entering host memory."""

    worker, _ = _worker(tmp_path)
    monkeypatch.setattr(
        worker,
        "get",
        lambda path: GetDone(path, 256 * 1024 + 1, 0),
    )

    def fail_read(path: Path) -> bytes:
        raise AssertionError(f"read_bytes called for {path}")

    monkeypatch.setattr(Path, "read_bytes", fail_read)

    with pytest.raises(DemoError, match="downloaded to"):
        Repl(worker, DebugLog(Style(False)), Style(False))._cmd_cat(["large.bin"])


def test_plan_rejects_totals_outside_wire_fields(tmp_path: Path) -> None:
    """PLAN input errors stay user-facing instead of escaping SessionError."""

    worker, _ = _worker(tmp_path)
    repl = Repl(worker, DebugLog(Style(False)), Style(False))

    with pytest.raises(DemoError, match="nfiles must fit u16"):
        repl._cmd_plan(["-1", "0"])
    with pytest.raises(DemoError, match="nbytes must fit u32"):
        repl._cmd_plan(["0", str(0x1_0000_0000)])


def test_main_rejects_window_outside_protocol_range() -> None:
    """Argument parsing enforces advertised send-window limits."""

    with pytest.raises(SystemExit):
        demo.main(["--window", "0"])
    with pytest.raises(SystemExit):
        demo.main(["--window", "9"])


def test_main_reports_direct_port_open_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Explicit serial-port failures produce concise CLI output."""

    def fail_open(port: str, baudrate: int) -> ByteTransport:
        raise OSError("permission denied")

    monkeypatch.setattr(demo, "_serial_transport", fail_open)

    assert demo.main(["--port", "/dev/ttyDENIED"]) == 1
    assert "could not open /dev/ttyDENIED: permission denied" in capsys.readouterr().out


class _EofSocket:
    """Connected-socket double whose peer has closed cleanly."""

    def settimeout(self, timeout: float) -> None:
        pass

    def recv(self, max_len: int) -> bytes:
        return b""

    def sendall(self, data: bytes) -> None:
        pass

    def close(self) -> None:
        pass


def test_socket_transport_surfaces_peer_eof() -> None:
    """Socket EOF is a disconnect, not an ordinary empty timeout read."""

    transport = demo.SocketTransport(cast(socket.socket, _EofSocket()))

    with pytest.raises(ConnectionResetError, match="peer closed"):
        transport.read(1024, 0.01)


def test_loopback_transport_records_verdict_and_cleans_resources(tmp_path: Path) -> None:
    """Loopback close joins its responder and removes its temporary tree."""

    raw_transport, _ = demo.make_loopback_transport()
    loopback = cast(Any, raw_transport)
    device_root: Path = loopback.root
    worker = DeviceWorker(
        CountingTransport(raw_transport),
        LocalDirFs(tmp_path / "local"),
        DebugLog(Style(False)),
    )
    worker.start()
    try:
        worker.connect()
        worker.get("README.txt")
        worker.close_session()
    finally:
        worker.shutdown()

    served = [event for event in loopback.device_events if isinstance(event, GetServed)]
    assert [event.path for event in served] == ["README.txt"]
    assert not loopback.responder_alive
    assert not device_root.exists()
