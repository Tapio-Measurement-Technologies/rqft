# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Interactive terminal demo client for RQFT devices.

A shell-like controller for exploring an RQFT responder over a serial
link: browse the remote file tree, download, upload, delete, sync, and
watch protocol statistics and debug logs while doing it.

Usage::

    python -m rqft.demo                     # scan serial ports, pick one
    python -m rqft.demo --port /dev/ttyACM0 # open a specific port
    python -m rqft.demo --loopback          # no hardware: in-process demo device

The session is driven by a background worker thread so the controller
keepalive (PING/T_DEAD, SPEC.md section 4.5) keeps running while the
user sits at the prompt. All protocol logic stays in the library; this
module only adds transport selection, a REPL, and presentation.
"""

from __future__ import annotations

import argparse
import importlib
import queue
import shlex
import shutil
import socket
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Deque, Optional, TypeVar, cast

from rqft import WINDOW_MAX
from rqft.client import BlockingSessionDriver, ByteTransport, LocalDirFs, PumpResult
from rqft.events import (
    DelDone,
    Ended,
    EntryListed,
    EntrySkipped,
    Established,
    GetDone,
    ListDone,
    OpFailed,
    Passthrough,
    PlanReceived,
    PutDone,
    SessionEvent,
)
from rqft.link import AbortReason
from rqft.messages import CAP_ALLOW_DELETE, ErrCode, MsgType, Role, path_valid
from rqft.session import Session, SessionError, SessionState, TransferPhase, TransferProgress

T = TypeVar("T")

# Transport read chunk used by the worker loop.
_READ_SIZE = 65536

# Idle watchdog for one operation: no event, byte, or progress movement
# for this long fails the operation. The session's own T_DEAD (10 s)
# normally fires first.
_OP_IDLE_TIMEOUT_S = 15.0

# Friendly explanations for SPEC.md section 5.3 error codes.
_ERR_HINTS = {
    ErrCode.E_FS_OPEN: "peer could not open the path",
    ErrCode.E_FS_READ: "peer failed reading the file",
    ErrCode.E_FS_WRITE: "peer failed writing the file",
    ErrCode.E_FS_REMOVE: "peer failed removing the path",
    ErrCode.E_PATH: "path violates the protocol path rules",
    ErrCode.E_CRC_FILE: "file CRC verification failed",
    ErrCode.E_TOO_LARGE: "file is too large for the peer",
    ErrCode.E_DENIED: "peer denied the request (delete gate?)",
    ErrCode.E_BAD_STATE: "peer rejected the request in its current state",
    ErrCode.E_UNSUPPORTED: "peer does not support the request",
}


class DemoError(RuntimeError):
    """Base class for demo client failures shown to the user."""


class DemoTimeout(DemoError):
    """Raised when an operation stops making progress."""


class Cancelled(DemoError):
    """Raised after Ctrl-C aborted the session with E_USER."""


class SessionEndedError(DemoError):
    """Raised when the session terminates during an operation."""


class OperationError(DemoError):
    """Raised when the peer answers ERR for a requested operation."""

    def __init__(self, event: OpFailed) -> None:
        self.event = event
        hint = _ERR_HINTS.get(event.code, "")
        where = f" '{event.path}'" if event.path else ""
        detail = f" — {hint}" if hint else ""
        super().__init__(f"{event.request.name}{where} failed: {event.code.name}{detail}")


# ---------------------------------------------------------------------------
# Presentation helpers


class Style:
    """ANSI styling that degrades to plain text off a tty."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

        def c(code: str) -> str:
            return f"\033[{code}m" if enabled else ""

        self.reset = c("0")
        self.bold = c("1")
        self.dim = c("2")
        self.red = c("31")
        self.green = c("32")
        self.yellow = c("33")
        self.blue = c("34")
        self.cyan = c("36")

    def prompt(self, text: str, code: str) -> str:
        """Wrap prompt color codes in readline zero-width markers."""

        if not self.enabled:
            return text
        return f"\001\033[{code}m\002{text}\001\033[0m\002"


def human_bytes(n: float) -> str:
    """Render a byte count with a binary unit suffix."""

    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024.0 or unit == "GiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GiB"


def _fmt_mtime(mtime: int) -> str:
    if mtime <= 0:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))


class DebugLog:
    """Timestamped ring buffer of protocol-level happenings.

    Categories: SES (session life-cycle), OP (operations), RTX
    (retransmissions), ERR (failures), PT (passthrough text from the device).
    """

    def __init__(self, style: Style, echo: bool = False) -> None:
        self._style = style
        self._entries: Deque[tuple[str, str, str]] = deque(maxlen=2000)
        self._lock = threading.Lock()
        self.echo = echo

    def add(self, cat: str, msg: str) -> None:
        stamp = time.strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
        with self._lock:
            self._entries.append((stamp, cat, msg))
        if self.echo:
            print(f"\r{self.render(stamp, cat, msg)}")

    def render(self, stamp: str, cat: str, msg: str) -> str:
        s = self._style
        color = {
            "SES": s.cyan,
            "OP": s.green,
            "RTX": s.yellow,
            "ERR": s.red,
            "PT": s.yellow,
        }.get(cat, "")
        return f"{s.dim}{stamp}{s.reset} {color}{cat:<3}{s.reset} {msg}"

    def tail(self, n: int) -> list[tuple[str, str, str]]:
        with self._lock:
            return list(self._entries)[-n:]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# ---------------------------------------------------------------------------
# Transports


class CountingTransport:
    """ByteTransport wrapper counting raw bytes in each direction."""

    def __init__(self, inner: ByteTransport) -> None:
        self._inner = inner
        self.tx_bytes = 0
        self.rx_bytes = 0

    def write(self, data: bytes) -> None:
        self._inner.write(data)
        self.tx_bytes += len(data)

    def read(self, max_len: int, timeout: float) -> bytes:
        data = self._inner.read(max_len, timeout)
        self.rx_bytes += len(data)
        return data

    def close(self) -> None:
        self._inner.close()


class SocketTransport:
    """ByteTransport over a connected socket (loopback demo device)."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def write(self, data: bytes) -> None:
        self._sock.sendall(data)

    def read(self, max_len: int, timeout: float) -> bytes:
        self._sock.settimeout(max(timeout, 0.001))
        try:
            data = self._sock.recv(max_len)
        except socket.timeout:
            return b""
        if data == b"":
            raise ConnectionResetError("socket peer closed")
        return data

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Statistics


@dataclass
class StatsSnapshot:
    """One consistent view of session, link, frame, and demo counters."""

    connected: bool
    state: str
    established: Optional[Established]
    uptime_s: Optional[float]
    srtt_ms: Optional[int]
    rttvar_ms: Optional[int]
    rto_ms: Optional[int]
    in_flight: Optional[int]
    frames_ok: int
    frames_crc_fail: int
    frames_oversize: int
    frames_dropped: int
    candidates_idle_flushed: int
    valid_candidates_idle_flushed: int
    bytes_idle_flushed: int
    frames_wrong_sid: int
    frames_retransmitted: int
    naks_sent: int
    duplicate_data_received: int
    out_of_order_data_received: int
    bytes_passthrough: int
    bytes_dropped_in_session: int
    tx_bytes: int
    rx_bytes: int
    ops_ok: int
    ops_failed: int
    files_down: int
    files_up: int
    bytes_down: int
    bytes_up: int
    deletes: int


@dataclass(frozen=True)
class ListResult:
    """Completed remote listing including informational skip reports.

    Attributes:
        entries: Entries received before LIST_END.
        skipped: Unreadable entries reported by the responder. RQFT does
            not carry their paths, so only error details are available.
    """

    entries: tuple[EntryListed, ...]
    skipped: tuple[EntrySkipped, ...]


# ---------------------------------------------------------------------------
# Session worker


class _Pending:
    """One submitted operation and its completion signal."""

    __slots__ = ("fn", "counted", "done", "result", "error")

    def __init__(self, fn: Callable[[], object], counted: bool) -> None:
        self.fn = fn
        self.counted = counted
        self.done = threading.Event()
        self.result: object = None
        self.error: Optional[BaseException] = None


class DeviceWorker(threading.Thread):
    """Owns the Session and transport; sole thread touching either.

    Operations are submitted from the REPL thread and executed here in
    order. Between operations the worker pumps the session so keepalive
    PINGs flow, device console text (passthrough) is surfaced, and a
    device-initiated doorbell HELLO is answered.
    """

    def __init__(
        self,
        transport: CountingTransport,
        fs: LocalDirFs,
        log: DebugLog,
        window: int = 4,
    ) -> None:
        super().__init__(name="rqft-demo-worker", daemon=True)
        self._transport = transport
        self.fs = fs
        self._log = log
        self._window = window
        self._queue: "queue.Queue[_Pending]" = queue.Queue()
        self._stop_event = threading.Event()
        self._cancel = threading.Event()
        self._driver = BlockingSessionDriver(
            transport,
            self._new_session(),
            read_size=_READ_SIZE,
            io_timeout_s=0.05,
        )
        self._established: Optional[Established] = None
        self._connected_at: Optional[float] = None
        self._ops_ok = 0
        self._ops_failed = 0
        self._files_down = 0
        self._files_up = 0
        self._bytes_down = 0
        self._bytes_up = 0
        self._deletes = 0
        self._frames_retransmitted = 0

    # -- public API (REPL thread) -------------------------------------

    @property
    def established(self) -> Optional[Established]:
        return self._established

    def connect(self) -> Established:
        return cast(Established, self._call(self._op_connect))

    def list_remote(self, root: str = "", want_crc: bool = False) -> ListResult:
        return cast(ListResult, self._call(lambda: self._op_list(root, want_crc)))

    def get(
        self, path: str, progress: Optional[Callable[[TransferProgress], None]] = None
    ) -> GetDone:
        return cast(GetDone, self._call(lambda: self._op_get(path, progress)))

    def put(
        self, path: str, progress: Optional[Callable[[TransferProgress], None]] = None
    ) -> PutDone:
        return cast(PutDone, self._call(lambda: self._op_put(path, progress)))

    def delete(self, path: str, is_dir: bool) -> DelDone:
        return cast(DelDone, self._call(lambda: self._op_del(path, is_dir)))

    def plan(self, nfiles: int, nbytes: int) -> None:
        self._call(lambda: self._op_plan(nfiles, nbytes))

    def close_session(self) -> None:
        self._call(self._op_close, counted=False)

    def stats(self) -> StatsSnapshot:
        return cast(StatsSnapshot, self._call(self._op_stats, counted=False))

    def shutdown(self) -> None:
        """Stop the worker and close the transport."""

        self._stop_event.set()
        self._transport.close()
        self.join(timeout=3.0)
        if self.is_alive():
            raise DemoError("session worker did not stop")

    def _call(self, fn: Callable[[], object], counted: bool = True) -> object:
        if not self.is_alive():
            raise DemoError("session worker is not running")
        item = _Pending(fn, counted)
        # Drop any stale cancel request so it cannot abort this operation.
        self._cancel.clear()
        self._queue.put(item)
        while not item.done.wait(0.1):
            pass
        if item.error is not None:
            raise item.error
        return item.result

    def request_cancel(self) -> None:
        """Ask the in-flight operation to abort the session (E_USER)."""

        self._cancel.set()

    # -- worker thread ------------------------------------------------

    def run(self) -> None:
        idle_error: Optional[str] = None
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.05)
            except queue.Empty:
                try:
                    self._idle_pump()
                    if idle_error is not None:
                        self._log.add("SES", "idle pump recovered")
                        idle_error = None
                except Exception as exc:  # transport death must not kill the worker
                    # A dead transport repeats the same failure every pump
                    # turn; log each distinct message once.
                    message = str(exc)
                    if message != idle_error:
                        idle_error = message
                        self._log.add(
                            "ERR", f"idle pump: {message} (repeats suppressed)"
                        )
                    self._established = None
                    time.sleep(0.2)
                continue
            try:
                item.result = item.fn()
                if item.counted:
                    self._ops_ok += 1
            except BaseException as exc:
                if item.counted:
                    self._ops_failed += 1
                item.error = exc
            self._cancel.clear()
            item.done.set()

    def _new_session(self) -> Session:
        return Session(Role.CONTROLLER, fs=self.fs, window=self._window)

    @property
    def _session(self) -> Session:
        return self._driver.session

    def _idle_pump(self) -> None:
        """One pump turn between operations: timers, reads, doorbell."""

        if self._session.state is SessionState.ENDED:
            # Fresh idle session so a device doorbell HELLO can be answered.
            self._driver.replace_session(self._new_session())
        turn = self._pump(max_wait_s=0.05)
        for event in turn.events:
            self._note_event(event)

    def _pump(self, max_wait_s: float) -> PumpResult:
        """Pump once and record newly retransmitted DATA frames."""

        turn = self._driver.pump(max_wait_s=max_wait_s)
        current = self._session.diagnostics().frames_retransmitted
        previous = (
            self._frames_retransmitted
            if current >= self._frames_retransmitted
            else 0
        )
        retransmitted = current - previous
        self._frames_retransmitted = current
        if retransmitted:
            noun = "frame" if retransmitted == 1 else "frames"
            self._log.add(
                "RTX",
                f"{retransmitted} DATA {noun} retransmitted ({current} total)",
            )
        return turn

    def _note_event(self, event: SessionEvent) -> None:
        """Record one session event in the debug log and worker state."""

        if isinstance(event, Passthrough):
            text = event.data.decode("utf-8", errors="replace").rstrip()
            if text:
                self._log.add("PT", f"device: {text}")
        elif isinstance(event, Established):
            self._established = event
            self._connected_at = time.monotonic()
            self._log.add(
                "SES",
                f"established sid=0x{event.sid:02X} v{event.version} "
                f"payload={event.max_payload} window={event.window} "
                f"caps=0x{event.peer_caps:02X}",
            )
        elif isinstance(event, Ended):
            self._established = None
            self._connected_at = None
            who = "peer" if event.from_peer else "local"
            self._log.add("SES", f"ended: {event.reason.name} ({who})")
        elif isinstance(event, PlanReceived):
            self._log.add("SES", f"peer PLAN: {event.nfiles} files, {event.nbytes} bytes")
        elif isinstance(event, EntrySkipped):
            self._log.add(
                "ERR",
                f"LIST skipped unreadable entry: {event.code.name} detail={event.detail}",
            )
        elif isinstance(event, OpFailed):
            self._log.add("ERR", str(OperationError(event)))

    def _require_connected(self) -> None:
        if self._established is None:
            raise DemoError("not connected — run 'connect' first")

    def _consume(
        self,
        events: list[SessionEvent],
        accept: Callable[[SessionEvent], Optional[T]],
    ) -> Optional[T]:
        found: Optional[T] = None
        failure: Optional[DemoError] = None
        for event in events:
            self._note_event(event)
            if found is not None or failure is not None:
                continue
            if isinstance(event, Ended):
                failure = SessionEndedError(
                    f"session ended: {event.reason.name}"
                    f" ({'peer' if event.from_peer else 'local'})"
                )
            elif isinstance(event, OpFailed):
                failure = OperationError(event)
            else:
                found = accept(event)
        if failure is not None:
            raise failure
        return found

    def _abort_user(self) -> None:
        for event in self._driver.abort(AbortReason.E_USER):
            self._note_event(event)
        self._established = None

    def _drive(
        self,
        accept: Callable[[SessionEvent], Optional[T]],
        idle_timeout_s: float = _OP_IDLE_TIMEOUT_S,
        progress: Optional[Callable[[TransferProgress], None]] = None,
    ) -> T:
        """Pump the session until accept() yields, with an idle watchdog."""

        last_activity = time.monotonic()
        last_progress: Optional[tuple[MsgType, TransferPhase, int]] = None
        while True:
            if self._cancel.is_set():
                self._abort_user()
                raise Cancelled("cancelled — session aborted with E_USER")
            turn = self._pump(max_wait_s=0.02)
            events = list(turn.events)
            if events or turn.bytes_received:
                last_activity = time.monotonic()
            found = self._consume(events, accept)
            if found is not None:
                return found
            if progress is not None:
                snapshot = self._session.progress()
                if snapshot is not None:
                    marker = (snapshot.request, snapshot.phase, snapshot.done)
                    if marker != last_progress:
                        last_progress = marker
                        last_activity = time.monotonic()
                    progress(snapshot)
            if time.monotonic() - last_activity > idle_timeout_s:
                raise DemoTimeout(f"no progress for {idle_timeout_s:.0f}s")

    def _await_outbound_ack(
        self,
        idle_timeout_s: float = _OP_IDLE_TIMEOUT_S,
    ) -> None:
        """Pump until peer acknowledges all reliable outbound frames."""

        last_activity = time.monotonic()
        while self._session.diagnostics().in_flight:
            turn = self._pump(max_wait_s=0.02)
            events = list(turn.events)
            if events or turn.bytes_received:
                last_activity = time.monotonic()
            self._consume(events, lambda event: None)
            if time.monotonic() - last_activity > idle_timeout_s:
                raise DemoTimeout(f"no progress for {idle_timeout_s:.0f}s")

    # -- operations (worker thread) -------------------------------------

    def _op_connect(self) -> Established:
        if self._established is not None:
            return self._established
        if self._session.state is not SessionState.IDLE:
            self._driver.replace_session(self._new_session())
        self._session.start(self._driver.now_ms())
        established = self._drive(
            lambda event: event if isinstance(event, Established) else None
        )
        return established

    def _op_list(self, root: str, want_crc: bool) -> ListResult:
        self._require_connected()
        entries: list[EntryListed] = []
        skipped: list[EntrySkipped] = []
        self._session.request_list(
            root, want_crc=want_crc, now_ms=self._driver.now_ms()
        )

        def accept(event: SessionEvent) -> Optional[ListResult]:
            if isinstance(event, EntryListed):
                entries.append(event)
                return None
            if isinstance(event, EntrySkipped):
                skipped.append(event)
                return None
            if isinstance(event, ListDone):
                return ListResult(tuple(entries), tuple(skipped))
            return None

        result = self._drive(accept)
        self._log.add(
            "OP",
            f"LIST '{root or '/'}' -> {len(result.entries)} entries, "
            f"{len(result.skipped)} skipped",
        )
        return result

    def _op_get(
        self, path: str, progress: Optional[Callable[[TransferProgress], None]]
    ) -> GetDone:
        self._require_connected()
        started = time.monotonic()
        self._session.request_get(path, now_ms=self._driver.now_ms())
        done = self._drive(
            lambda event: event
            if isinstance(event, GetDone) and event.path == path
            else None,
            progress=progress,
        )
        # GET completes locally when GET_DONE is queued. Wait for its ACK so
        # an immediate session close cannot discard responder-side verdict.
        self._await_outbound_ack()
        elapsed = time.monotonic() - started
        self._files_down += 1
        self._bytes_down += done.size
        self._log.add(
            "OP",
            f"GET '{path}' ok ({human_bytes(done.size)}, crc 0x{done.crc32:08X}, "
            f"total {elapsed:.2f} s)",
        )
        return done

    def _op_put(
        self, path: str, progress: Optional[Callable[[TransferProgress], None]]
    ) -> PutDone:
        self._require_connected()
        started = time.monotonic()
        self._session.request_put(path, now_ms=self._driver.now_ms())
        done = self._drive(
            lambda event: event
            if isinstance(event, PutDone) and event.path == path
            else None,
            progress=progress,
        )
        elapsed = time.monotonic() - started
        self._files_up += 1
        self._bytes_up += done.size
        self._log.add(
            "OP",
            f"PUT '{path}' ok ({human_bytes(done.size)}, crc 0x{done.crc32:08X}, "
            f"total {elapsed:.2f} s)",
        )
        return done

    def _op_del(self, path: str, is_dir: bool) -> DelDone:
        self._require_connected()
        self._session.request_del(
            path, is_dir=is_dir, now_ms=self._driver.now_ms()
        )
        done = self._drive(
            lambda event: event
            if isinstance(event, DelDone) and event.path == path
            else None
        )
        self._deletes += 1
        self._log.add("OP", f"{'DEL_DIR' if is_dir else 'DEL_FILE'} '{path}' ok")
        return done

    def _op_plan(self, nfiles: int, nbytes: int) -> None:
        self._require_connected()
        self._session.send_plan(nfiles, nbytes, self._driver.now_ms())
        self._driver.flush()
        self._log.add("OP", f"PLAN {nfiles} files, {human_bytes(nbytes)}")

    def _op_close(self) -> None:
        if self._session.state in (SessionState.ACTIVE, SessionState.HELLO_SENT):
            for event in self._driver.abort(AbortReason.CLOSE):
                if isinstance(event, Ended):
                    self._log.add("SES", "closed (ABORT CLOSE sent)")
                else:
                    self._note_event(event)
        self._established = None
        self._connected_at = None

    def _op_stats(self) -> StatsSnapshot:
        session = self._session
        diagnostics = session.diagnostics()
        return StatsSnapshot(
            connected=self._established is not None,
            state=session.state.value,
            established=self._established,
            uptime_s=(
                time.monotonic() - self._connected_at
                if self._connected_at is not None
                else None
            ),
            srtt_ms=diagnostics.srtt_ms,
            rttvar_ms=diagnostics.rttvar_ms,
            rto_ms=diagnostics.rto_ms,
            in_flight=diagnostics.in_flight,
            frames_ok=diagnostics.frames_ok,
            frames_crc_fail=diagnostics.frames_crc_fail,
            frames_oversize=diagnostics.frames_oversize,
            frames_dropped=diagnostics.frames_dropped,
            candidates_idle_flushed=diagnostics.candidates_idle_flushed,
            valid_candidates_idle_flushed=diagnostics.valid_candidates_idle_flushed,
            bytes_idle_flushed=diagnostics.bytes_idle_flushed,
            frames_wrong_sid=diagnostics.frames_wrong_sid,
            frames_retransmitted=diagnostics.frames_retransmitted,
            naks_sent=diagnostics.naks_sent,
            duplicate_data_received=diagnostics.duplicate_data_received,
            out_of_order_data_received=diagnostics.out_of_order_data_received,
            bytes_passthrough=diagnostics.bytes_passthrough,
            bytes_dropped_in_session=diagnostics.bytes_dropped_in_session,
            tx_bytes=self._transport.tx_bytes,
            rx_bytes=self._transport.rx_bytes,
            ops_ok=self._ops_ok,
            ops_failed=self._ops_failed,
            files_down=self._files_down,
            files_up=self._files_up,
            bytes_down=self._bytes_down,
            bytes_up=self._bytes_up,
            deletes=self._deletes,
        )


# ---------------------------------------------------------------------------
# Loopback demo device


def _seed_demo_tree(root: Path) -> None:
    """Populate the loopback device with a small believable file tree."""

    import random

    rng = random.Random(0x52514654)
    (root / "logs" / "2026-07-14").mkdir(parents=True, exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "artifacts").mkdir(exist_ok=True)
    (root / "README.txt").write_text(
        "RQFT loopback demo device.\n"
        "Files here live in a temporary directory served by an\n"
        "in-process responder session.\n"
    )
    (root / "logs" / "boot.log").write_text(
        "".join(f"[{i:6d} ms] boot stage {i} ok\n" for i in range(0, 500, 7))
    )
    (root / "logs" / "2026-07-14" / "trace.bin").write_bytes(rng.randbytes(96 * 1024))
    (root / "data" / "samples.csv").write_text(
        "t_s,value\n"
        + "".join(f"{i * 0.1:.1f},{rng.uniform(-4, 4):.3f}\n" for i in range(400))
    )
    (root / "artifacts" / "payload.bin").write_bytes(rng.randbytes(192 * 1024))


class LoopbackResponder(threading.Thread):
    """In-process responder session serving a directory over a socket.

    Emits a console line over the raw stream every few seconds while no
    session is active, demonstrating passthrough handling.
    """

    def __init__(self, sock: socket.socket, root: Path) -> None:
        super().__init__(name="rqft-demo-responder", daemon=True)
        self._sock = sock
        self._root = root
        self._events: Deque[SessionEvent] = deque(maxlen=2000)
        self._event_lock = threading.Lock()

    @property
    def events(self) -> tuple[SessionEvent, ...]:
        """Return responder-side events retained for demo inspection."""

        with self._event_lock:
            return tuple(self._events)

    def stop(self) -> None:
        """Close the responder socket to unblock its receive loop."""

        try:
            self._sock.close()
        except OSError:
            pass

    def _record(self, events: list[SessionEvent]) -> None:
        if not events:
            return
        with self._event_lock:
            self._events.extend(events)

    def run(self) -> None:
        fs = LocalDirFs(self._root)
        started = time.monotonic()
        last_console = time.monotonic()

        def new_session() -> Session:
            return Session(Role.RESPONDER, fs=fs, window=8, caps=CAP_ALLOW_DELETE)

        driver = BlockingSessionDriver(
            SocketTransport(self._sock),
            new_session(),
            read_size=_READ_SIZE,
            io_timeout_s=0.02,
        )
        try:
            while True:
                self._record(list(driver.pump(max_wait_s=0.02).events))
                if driver.session.state is SessionState.ENDED:
                    driver.replace_session(new_session())
                if (
                    not driver.session.session_active
                    and time.monotonic() - last_console > 12.0
                ):
                    uptime = int(time.monotonic() - started)
                    self._sock.sendall(
                        f"[demo-device] console: uptime {uptime}s, battery 87%\r\n".encode()
                    )
                    last_console = time.monotonic()
        except OSError:
            pass
        finally:
            self.stop()


class _LoopbackTransport(SocketTransport):
    """Socket transport owning its responder thread and temporary tree."""

    def __init__(
        self,
        sock: socket.socket,
        responder: LoopbackResponder,
        temporary: tempfile.TemporaryDirectory[str],
    ) -> None:
        super().__init__(sock)
        self._responder = responder
        self._temporary = temporary
        self._closed = False

    @property
    def root(self) -> Path:
        """Return loopback device filesystem root while transport is open."""

        return Path(self._temporary.name)

    @property
    def device_events(self) -> tuple[SessionEvent, ...]:
        """Return responder-side session events observed so far."""

        return self._responder.events

    @property
    def responder_alive(self) -> bool:
        """Return whether loopback responder thread is still running."""

        return self._responder.is_alive()

    def close(self) -> None:
        """Close both socket endpoints, join responder, and remove its tree."""

        if self._closed:
            return
        self._closed = True
        super().close()
        self._responder.join(timeout=3.0)
        if self._responder.is_alive():
            self._responder.stop()
            self._responder.join(timeout=3.0)
        if self._responder.is_alive():
            raise DemoError("loopback responder did not stop")
        self._temporary.cleanup()


def make_loopback_transport() -> tuple[ByteTransport, str]:
    """Create a socketpair transport backed by an in-process responder."""

    left, right = socket.socketpair()
    temporary = tempfile.TemporaryDirectory(prefix="rqft-demo-device-")
    root = Path(temporary.name)
    _seed_demo_tree(root)
    responder = LoopbackResponder(right, root)
    responder.start()
    return _LoopbackTransport(left, responder, temporary), f"loopback demo device ({root})"


# ---------------------------------------------------------------------------
# REPL


@dataclass(frozen=True)
class _Command:
    handler: Callable[[list[str]], None]
    usage: str
    help: str


class Repl:
    """Interactive shell over a DeviceWorker."""

    def __init__(self, client: DeviceWorker, log: DebugLog, style: Style) -> None:
        self._client = client
        self._log = log
        self._style = style
        self._cwd = ""
        self._files: dict[str, EntryListed] = {}
        self._dirs: set[str] = {""}
        self._commands = self._build_commands()

    # -- remote tree cache ----------------------------------------------

    def _update_cache(self, entries: tuple[EntryListed, ...]) -> None:
        self._files = {e.path: e for e in entries if e.etype == 0}
        self._dirs = {""}
        for path in self._files:
            parts = path.split("/")
            for i in range(1, len(parts)):
                self._dirs.add("/".join(parts[:i]))
        if self._cwd not in self._dirs:
            self._cwd = ""

    def _resolve(self, arg: str) -> str:
        """Turn a user path (absolute or cwd-relative) into a protocol path."""

        if arg.startswith("/"):
            parts: list[str] = []
            arg = arg[1:]
        else:
            parts = self._cwd.split("/") if self._cwd else []
        for piece in arg.split("/"):
            if piece in ("", "."):
                continue
            if piece == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(piece)
        return "/".join(parts)

    def _children(self, directory: str) -> tuple[list[str], list[EntryListed]]:
        prefix = directory + "/" if directory else ""
        subdirs = sorted(
            d[len(prefix):]
            for d in self._dirs
            if d and d.startswith(prefix) and "/" not in d[len(prefix):]
        )
        files = sorted(
            (
                e
                for p, e in self._files.items()
                if p.startswith(prefix) and "/" not in p[len(prefix):]
            ),
            key=lambda e: e.path,
        )
        return subdirs, files

    def _files_under(self, directory: str) -> list[EntryListed]:
        prefix = directory + "/" if directory else ""
        return sorted(
            (e for p, e in self._files.items() if p.startswith(prefix)),
            key=lambda e: e.path,
        )

    # -- infrastructure ---------------------------------------------------

    def _print(self, text: str = "") -> None:
        print(text)

    def _error(self, text: str) -> None:
        print(f"{self._style.red}error:{self._style.reset} {text}")

    def _info(self, text: str) -> None:
        print(f"{self._style.dim}{text}{self._style.reset}")

    def _warning(self, text: str) -> None:
        print(f"{self._style.yellow}warning:{self._style.reset} {text}")

    def _confirm(self, question: str) -> bool:
        try:
            answer = input(f"{question} [y/N] ").strip().lower()
        except EOFError:
            return False
        return answer in ("y", "yes")

    def _prompt_text(self) -> str:
        s = self._style
        if self._client.established is None:
            return f"{s.prompt('rqft', '1;36')}{s.prompt(' (offline) ▸ ', '2')}"
        where = "/" + self._cwd if self._cwd else "/"
        return f"{s.prompt('rqft', '1;36')}{s.prompt(':' + where, '34')}{s.prompt(' ▸ ', '1')}"

    def _refresh(self, want_crc: bool) -> None:
        listing = self._client.list_remote("", want_crc=want_crc)
        self._update_cache(listing.entries)
        total = sum(e.size for e in self._files.values())
        self._info(
            f"{len(self._files)} remote files, {human_bytes(total)}"
            + (" (with CRCs)" if want_crc else "")
        )
        if listing.skipped:
            self._warning(
                f"listing incomplete: {len(listing.skipped)} unreadable remote "
                f"{'entry was' if len(listing.skipped) == 1 else 'entries were'} skipped"
            )

    def _progress_printer(self, label: str) -> Callable[[TransferProgress], None]:
        """Build a rate-limited single-line progress renderer."""

        start = time.monotonic()
        last_draw = 0.0
        phase: Optional[TransferPhase] = None
        phase_started = start
        phase_origin = 0
        tty = sys.stdout.isatty()

        def cb(snapshot: TransferProgress) -> None:
            nonlocal last_draw, phase, phase_started, phase_origin
            now = time.monotonic()
            if snapshot.phase is not phase:
                if phase is not None:
                    phase_started = now
                    phase_origin = snapshot.done
                phase = snapshot.phase
            if now - last_draw < 0.1:
                return
            last_draw = now
            if not tty:
                return
            elapsed = max(now - phase_started, 1e-6)
            rate = human_bytes(max(0, snapshot.done - phase_origin) / elapsed) + "/s"
            if snapshot.phase is TransferPhase.HASH:
                action = "hash"
            elif snapshot.request is MsgType.GET_REQ:
                action = "get"
            else:
                action = "put"
            display_label = f"{action} {label}"
            if snapshot.total is not None:
                width = 24
                filled = (
                    width
                    if snapshot.total == 0
                    else min(width, int(width * snapshot.done / snapshot.total))
                )
                bar = "#" * filled + "-" * (width - filled)
                line = (
                    f"  {display_label} [{bar}] {human_bytes(snapshot.done)}/"
                    f"{human_bytes(snapshot.total)} {rate}"
                )
            else:
                line = f"  {display_label} ... {human_bytes(snapshot.done)} {rate}"
            print(f"\r{line:<78}", end="", flush=True)

        return cb

    def _finish_progress(self, label: str, size: int, started: float) -> None:
        elapsed = max(time.monotonic() - started, 1e-6)
        rate = human_bytes(size / elapsed) + "/s"
        line = f"  {label} {human_bytes(size)} in {elapsed:.1f}s ({rate})"
        end = "\r" if sys.stdout.isatty() else ""
        print(f"{end}{line:<78}")

    # -- commands -------------------------------------------------------

    def _build_commands(self) -> dict[str, _Command]:
        return {
            "connect": _Command(self._cmd_connect, "connect", "open the session (HELLO)"),
            "close": _Command(self._cmd_close, "close", "close the session, keep the port"),
            "ls": _Command(self._cmd_ls, "ls [path]", "list the current remote directory"),
            "cd": _Command(self._cmd_cd, "cd <dir>", "change remote directory ('..' works)"),
            "pwd": _Command(self._cmd_pwd, "pwd", "print the remote working directory"),
            "tree": _Command(self._cmd_tree, "tree [path]", "show the remote tree"),
            "refresh": _Command(
                self._cmd_refresh, "refresh [-c]", "re-list the device (-c: with CRCs)"
            ),
            "get": _Command(
                self._cmd_get, "get <path>...", "download files (or a whole directory)"
            ),
            "cat": _Command(self._cmd_cat, "cat <path>", "download and print a text file"),
            "put": _Command(
                self._cmd_put, "put <local> [remote]", "upload a local file to the device"
            ),
            "sync": _Command(
                self._cmd_sync,
                "sync [--delete]",
                "fetch all new/changed files (--delete removes them remotely)",
            ),
            "rm": _Command(self._cmd_rm, "rm <path>", "delete a remote file"),
            "rmdir": _Command(
                self._cmd_rmdir, "rmdir <dir>", "delete a remote directory recursively"
            ),
            "plan": _Command(
                self._cmd_plan, "plan <nfiles> <nbytes>", "announce batch totals (PLAN)"
            ),
            "lls": _Command(self._cmd_lls, "lls", "list the local mirror directory"),
            "stats": _Command(self._cmd_stats, "stats", "session/link/frame statistics"),
            "log": _Command(
                self._cmd_log, "log [n|all|on|off|clear]", "view or control the debug log"
            ),
            "help": _Command(self._cmd_help, "help", "show this help"),
        }

    def _cmd_connect(self, args: list[str]) -> None:
        established = self._client.connect()
        delete_ok = "yes" if established.peer_caps & CAP_ALLOW_DELETE else "no"
        self._print(
            f"connected: sid=0x{established.sid:02X} v{established.version} "
            f"payload={established.max_payload} window={established.window} "
            f"peer-allows-delete={delete_ok}"
        )
        self._refresh(want_crc=False)

    def _cmd_close(self, args: list[str]) -> None:
        self._client.close_session()
        self._print("session closed")

    def _cmd_ls(self, args: list[str]) -> None:
        target = self._resolve(args[0]) if args else self._cwd
        if any(entry.crc32 is None for entry in self._files.values()):
            self._refresh(want_crc=True)
        if target in self._files:
            entry = self._files[target]
            self._print(self._format_file(entry, entry.path))
            return
        if target not in self._dirs:
            raise DemoError(f"no such remote directory: /{target}")
        subdirs, files = self._children(target)
        s = self._style
        for name in subdirs:
            child = (target + "/" + name) if target else name
            below = self._files_under(child)
            size = sum(e.size for e in below)
            self._print(
                f"  {s.blue}{name + '/':<32}{s.reset} {len(below):>4} files  {human_bytes(size):>10}"
            )
        for entry in files:
            self._print(self._format_file(entry, entry.path.rsplit('/', 1)[-1]))
        if not subdirs and not files:
            self._info("(empty)")

    def _format_file(self, entry: EntryListed, name: str) -> str:
        crc = f"crc 0x{entry.crc32:08X}" if entry.crc32 is not None else ""
        return (
            f"  {name:<32} {human_bytes(entry.size):>16}  "
            f"{_fmt_mtime(entry.mtime):<16} {crc}"
        )

    def _cmd_cd(self, args: list[str]) -> None:
        target = self._resolve(args[0]) if args else ""
        if target not in self._dirs:
            raise DemoError(f"no such remote directory: /{target}")
        self._cwd = target

    def _cmd_pwd(self, args: list[str]) -> None:
        self._print("/" + self._cwd if self._cwd else "/")

    def _cmd_tree(self, args: list[str]) -> None:
        root = self._resolve(args[0]) if args else ""
        if root not in self._dirs:
            raise DemoError(f"no such remote directory: /{root}")

        def render(directory: str, indent: str) -> None:
            subdirs, files = self._children(directory)
            entries: list[tuple[str, bool, Optional[EntryListed]]] = [
                (d, True, None) for d in subdirs
            ] + [(f.path.rsplit("/", 1)[-1], False, f) for f in files]
            for i, (name, is_dir, entry) in enumerate(entries):
                last = i == len(entries) - 1
                branch = "└── " if last else "├── "
                if is_dir:
                    self._print(f"{indent}{branch}{self._style.blue}{name}/{self._style.reset}")
                    child = (directory + "/" + name) if directory else name
                    render(child, indent + ("    " if last else "│   "))
                else:
                    assert entry is not None
                    self._print(f"{indent}{branch}{name}  ({human_bytes(entry.size)})")

        self._print("/" + root if root else "/")
        render(root, "")

    def _cmd_refresh(self, args: list[str]) -> None:
        self._refresh(want_crc="-c" in args)

    def _cmd_get(self, args: list[str]) -> None:
        if not args:
            raise DemoError("usage: get <path>...")
        targets: list[str] = []
        for arg in args:
            path = self._resolve(arg)
            if path in self._files:
                targets.append(path)
            elif path in self._dirs:
                below = [e.path for e in self._files_under(path)]
                if not below:
                    self._info(f"/{path}: no files")
                targets.extend(below)
            else:
                # Not in the cache; let the device answer authoritatively.
                targets.append(path)
        batch_started = time.monotonic()
        batch_bytes = 0
        for path in targets:
            started = time.monotonic()
            done = self._client.get(path, self._progress_printer(path))
            self._finish_progress(f"get {path}:", done.size, started)
            batch_bytes += done.size
        if len(targets) > 1:
            elapsed = time.monotonic() - batch_started
            self._log.add(
                "OP",
                f"GET batch: {len(targets)} files, {human_bytes(batch_bytes)}, "
                f"total {elapsed:.2f} s",
            )
        self._info(f"saved under {self._client.fs.root}")

    def _cmd_cat(self, args: list[str]) -> None:
        if not args:
            raise DemoError("usage: cat <path>")
        path = self._resolve(args[0])
        done = self._client.get(path)
        local = self._client.fs.root / Path(*path.split("/"))
        if done.size > 256 * 1024:
            raise DemoError(f"file is {human_bytes(done.size)}; downloaded to {local}")
        data = local.read_bytes()
        try:
            self._print(data.decode("utf-8"))
        except UnicodeDecodeError:
            self._info(f"binary file ({human_bytes(done.size)}), first 256 bytes:")
            self._print(data[:256].hex(" "))

    def _cmd_put(self, args: list[str]) -> None:
        if not args:
            raise DemoError("usage: put <local-file> [remote-path]")
        source = Path(args[0]).expanduser()
        if not source.is_file():
            raise DemoError(f"no such local file: {source}")
        remote = self._resolve(args[1]) if len(args) > 1 else self._resolve(source.name)
        if remote in self._dirs and remote:
            remote = remote + "/" + source.name
        if not path_valid(remote.encode("utf-8")):
            raise DemoError(f"invalid remote path: {remote!r}")
        staged = self._client.fs.root / Path(*remote.split("/"))
        if source.resolve() != staged.resolve():
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, staged)
            self._info(f"staged to {staged}")
        started = time.monotonic()
        done = self._client.put(remote, self._progress_printer(remote))
        self._finish_progress(f"put {remote}:", done.size, started)
        self._files[remote] = EntryListed(
            etype=0, path=remote, size=done.size, mtime=int(time.time()), crc32=done.crc32
        )
        self._update_cache(tuple(self._files.values()))

    def _cmd_sync(self, args: list[str]) -> None:
        delete_remote = "--delete" in args
        if delete_remote and not self._confirm(
            "delete every fetched file from the device afterwards?"
        ):
            return
        sync_started = time.monotonic()
        self._info("listing with CRCs (device hashes every file) ...")
        listing = self._client.list_remote("", want_crc=True)
        self._update_cache(listing.entries)
        if listing.skipped:
            self._warning(
                f"sync source incomplete: {len(listing.skipped)} unreadable remote "
                f"{'entry was' if len(listing.skipped) == 1 else 'entries were'} skipped"
            )
        local = self._client.fs.scan()
        to_fetch: list[EntryListed] = []
        skipped = 0
        for entry in self._files.values():
            have = local.get(entry.path)
            if (
                entry.crc32 is not None
                and have is not None
                and have.size == entry.size
                and have.crc32 == entry.crc32
            ):
                skipped += 1
            else:
                to_fetch.append(entry)
        total = sum(e.size for e in to_fetch)
        self._client.plan(len(to_fetch), total)
        self._info(
            f"{len(to_fetch)} to fetch ({human_bytes(total)}), {skipped} already up to date"
        )
        fetched = 0
        fetched_bytes = 0
        for entry in sorted(to_fetch, key=lambda e: e.path):
            started = time.monotonic()
            done = self._client.get(entry.path, self._progress_printer(entry.path))
            self._finish_progress(f"get {entry.path}:", done.size, started)
            fetched += 1
            fetched_bytes += done.size
            if delete_remote:
                self._client.delete(entry.path, is_dir=False)
                self._files.pop(entry.path, None)
        if delete_remote:
            self._update_cache(tuple(self._files.values()))
        elapsed = time.monotonic() - sync_started
        self._log.add(
            "OP",
            f"SYNC done: {fetched} fetched ({human_bytes(fetched_bytes)}), "
            f"{skipped} skipped, total {elapsed:.2f} s",
        )
        self._print(
            f"sync done: {fetched} fetched, {skipped} skipped"
            + (f", {fetched} deleted remotely" if delete_remote else "")
        )

    def _cmd_rm(self, args: list[str]) -> None:
        if not args:
            raise DemoError("usage: rm <path>")
        path = self._resolve(args[0])
        self._client.delete(path, is_dir=False)
        self._files.pop(path, None)
        self._update_cache(tuple(self._files.values()))
        self._print(f"deleted /{path}")

    def _cmd_rmdir(self, args: list[str]) -> None:
        if not args:
            raise DemoError("usage: rmdir <dir>")
        path = self._resolve(args[0])
        if not path:
            raise DemoError("refusing to delete the device root")
        count = len(self._files_under(path)) if path in self._dirs else "?"
        if not self._confirm(f"recursively delete /{path} ({count} known files) on the device?"):
            return
        self._client.delete(path, is_dir=True)
        for known in list(self._files):
            if known == path or known.startswith(path + "/"):
                del self._files[known]
        self._update_cache(tuple(self._files.values()))
        self._print(f"deleted /{path} recursively")

    def _cmd_plan(self, args: list[str]) -> None:
        if len(args) != 2:
            raise DemoError("usage: plan <nfiles> <nbytes>")
        try:
            nfiles, nbytes = int(args[0]), int(args[1])
        except ValueError:
            raise DemoError("nfiles and nbytes must be integers") from None
        if not 0 <= nfiles <= 0xFFFF:
            raise DemoError("nfiles must fit u16")
        if not 0 <= nbytes <= 0xFFFFFFFF:
            raise DemoError("nbytes must fit u32")
        self._client.plan(nfiles, nbytes)
        self._print(f"PLAN sent: {nfiles} files, {human_bytes(nbytes)}")

    def _cmd_lls(self, args: list[str]) -> None:
        root = self._client.fs.root
        found = sorted(self._client.fs.scan().values(), key=lambda f: f.path)
        if not found:
            self._info(f"(local mirror {root} is empty)")
            return
        self._info(f"local mirror: {root}")
        for item in found:
            self._print(f"  {item.path:<40} {human_bytes(item.size):>10}  crc 0x{item.crc32:08X}")

    def _cmd_stats(self, args: list[str]) -> None:
        snap = self._client.stats()
        s = self._style
        est = snap.established

        def row(label: str, value: str) -> None:
            self._print(f"  {s.dim}{label:<22}{s.reset}{value}")

        self._print(f"{s.bold}session{s.reset}")
        row("state", snap.state + (" (connected)" if snap.connected else ""))
        if est is not None:
            delete_ok = "yes" if est.peer_caps & CAP_ALLOW_DELETE else "no"
            row("negotiated", f"sid=0x{est.sid:02X} v{est.version} role={est.role.name}")
            row("limits", f"payload={est.max_payload} B, window={est.window}")
            row("peer allows delete", delete_ok)
        if snap.uptime_s is not None:
            row("uptime", f"{snap.uptime_s:.0f} s")
        self._print(f"{s.bold}link{s.reset}")
        if snap.srtt_ms is not None:
            row("rtt", f"srtt={snap.srtt_ms} ms, var={snap.rttvar_ms} ms")
        if snap.rto_ms is not None:
            row("rto", f"{snap.rto_ms} ms")
        if snap.in_flight is not None:
            row("frames in flight", str(snap.in_flight))
        row("retransmitted", str(snap.frames_retransmitted))
        row("NAKs sent", str(snap.naks_sent))
        row(
            "receive anomalies",
            f"duplicate={snap.duplicate_data_received} "
            f"gap={snap.out_of_order_data_received}",
        )
        self._print(f"{s.bold}frames{s.reset}")
        row("valid", str(snap.frames_ok))
        row(
            "rejected",
            f"crc={snap.frames_crc_fail} oversize={snap.frames_oversize} "
            f"shape={snap.frames_dropped} wrong-sid={snap.frames_wrong_sid}",
        )
        row(
            "idle-flushed",
            f"candidates={snap.candidates_idle_flushed} "
            f"valid={snap.valid_candidates_idle_flushed} "
            f"bytes={human_bytes(snap.bytes_idle_flushed)}",
        )
        row(
            "unframed bytes",
            f"passthrough={human_bytes(snap.bytes_passthrough)}, "
            f"dropped in-session={human_bytes(snap.bytes_dropped_in_session)}",
        )
        self._print(f"{s.bold}transport{s.reset}")
        row("raw bytes", f"tx={human_bytes(snap.tx_bytes)}, rx={human_bytes(snap.rx_bytes)}")
        self._print(f"{s.bold}operations{s.reset}")
        row("completed / failed", f"{snap.ops_ok} / {snap.ops_failed}")
        row(
            "downloaded",
            f"{snap.files_down} files, {human_bytes(snap.bytes_down)}",
        )
        row("uploaded", f"{snap.files_up} files, {human_bytes(snap.bytes_up)}")
        row("deletes", str(snap.deletes))

    def _cmd_log(self, args: list[str]) -> None:
        if args and args[0] == "on":
            self._log.echo = True
            self._print("live debug log on")
            return
        if args and args[0] == "off":
            self._log.echo = False
            self._print("live debug log off")
            return
        if args and args[0] == "clear":
            self._log.clear()
            self._print("debug log cleared")
            return
        count = 50
        if args and args[0] == "all":
            count = 10**9
        elif args:
            try:
                count = int(args[0])
            except ValueError:
                raise DemoError("usage: log [n|all|on|off|clear]") from None
        entries = self._log.tail(count)
        if not entries:
            self._info("(debug log is empty)")
        for stamp, cat, msg in entries:
            self._print(self._log.render(stamp, cat, msg))

    def _cmd_help(self, args: list[str]) -> None:
        s = self._style
        groups = [
            ("session", ["connect", "close"]),
            ("browse", ["ls", "cd", "pwd", "tree", "refresh"]),
            ("transfer", ["get", "cat", "put", "sync"]),
            ("modify", ["rm", "rmdir", "plan"]),
            ("inspect", ["lls", "stats", "log"]),
        ]
        for title, names in groups:
            self._print(f"{s.bold}{title}{s.reset}")
            for name in names:
                cmd = self._commands[name]
                self._print(f"  {cmd.usage:<28} {cmd.help}")
        self._print(f"{s.bold}other{s.reset}")
        self._print(f"  {'help':<28} show this help")
        self._print(f"  {'quit / exit':<28} close the session and leave")
        self._info("Ctrl-C during a transfer aborts the session (E_USER); reconnect with 'connect'.")

    # -- completion -------------------------------------------------------

    def _remote_candidates(self, text: str, dirs_only: bool) -> list[str]:
        head, _, leaf = text.rpartition("/")
        base = self._resolve(head) if head else self._cwd
        if head and base not in self._dirs:
            return []
        prefix = head + "/" if head else ""
        subdirs, files = self._children(base)
        out = [prefix + d + "/" for d in subdirs if d.startswith(leaf)]
        if not dirs_only:
            out += [
                prefix + f.path.rsplit("/", 1)[-1]
                for f in files
                if f.path.rsplit("/", 1)[-1].startswith(leaf)
            ]
        return out

    def _complete(self, text: str, state: int) -> Optional[str]:
        import readline

        buffer = readline.get_line_buffer()[: readline.get_endidx()]
        words = buffer.split()
        at_command = not words or (len(words) == 1 and not buffer.endswith(" "))
        if at_command:
            names = sorted(list(self._commands) + ["quit", "exit"])
            matches = [n + " " for n in names if n.startswith(text)]
        else:
            command = words[0].lower()
            if command in ("cd", "tree", "rmdir"):
                matches = self._remote_candidates(text, dirs_only=True)
            elif command in ("ls", "get", "cat", "rm"):
                matches = self._remote_candidates(text, dirs_only=False)
            elif command == "put" and (len(words) == 1 or (len(words) == 2 and not buffer.endswith(" "))):
                import glob

                matches = [
                    p + ("/" if Path(p).is_dir() else "")
                    for p in glob.glob(text + "*")
                ]
            else:
                matches = []
        return matches[state] if state < len(matches) else None

    # -- main loop ----------------------------------------------------------

    def run(self) -> None:
        try:
            import readline

            readline.set_completer_delims(" \t")
            readline.parse_and_bind("tab: complete")
            readline.set_completer(self._complete)
            history = Path.home() / ".rqft-demo-history"
            try:
                readline.read_history_file(str(history))
            except OSError:
                pass
        except ImportError:
            history = None

        self._info("type 'help' for commands, 'quit' to leave")
        while True:
            try:
                line = input(self._prompt_text())
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print("^C")
                continue
            line = line.strip()
            if not line:
                continue
            try:
                words = shlex.split(line)
            except ValueError as exc:
                self._error(f"bad quoting: {exc}")
                continue
            name, args = words[0].lower(), words[1:]
            if name in ("quit", "exit", "q"):
                break
            command = self._commands.get(name)
            if command is None:
                self._error(f"unknown command {name!r} — try 'help'")
                continue
            try:
                command.handler(args)
            except KeyboardInterrupt:
                self._client.request_cancel()
                print()
                self._error("cancelled — session aborted; reconnect with 'connect'")
            except DemoError as exc:
                print()
                self._error(str(exc))
            except SessionError as exc:
                print()
                self._error(str(exc))
            except OSError as exc:
                print()
                self._error(f"transport failure: {exc}")

        if history is not None:
            try:
                import readline

                readline.write_history_file(str(history))
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Startup


def _serial_transport(port: str, baudrate: int) -> ByteTransport:
    from rqft.serial_transport import SerialTransport

    return SerialTransport(port, baudrate=baudrate)


def _list_serial_ports() -> list[tuple[str, str]]:
    """Return (device, description) pairs, or [] when pyserial is absent."""

    try:
        list_ports = importlib.import_module("serial.tools.list_ports")
    except ImportError:
        return []
    ports: list[tuple[str, str]] = []
    for info in cast(Any, list_ports).comports():
        ports.append((info.device, info.description or ""))
    return sorted(ports)


def _choose_transport(args: argparse.Namespace, style: Style) -> Optional[tuple[ByteTransport, str]]:
    """Resolve flags or run the interactive device picker."""

    if args.loopback:
        return make_loopback_transport()
    if args.port:
        try:
            return _serial_transport(args.port, args.baud), f"{args.port} @ {args.baud}"
        except Exception as exc:
            raise DemoError(f"could not open {args.port}: {exc}") from exc

    ports = _list_serial_ports()
    print(f"{style.bold}Select RQFT device{style.reset}")
    for i, (device, description) in enumerate(ports, start=1):
        print(f"  {i}. {device:<24} {style.dim}{description}{style.reset}")
    if not ports:
        print(f"  {style.dim}(no serial ports found — is pyserial installed?){style.reset}")
    print("  m. enter a port path manually")
    print("  l. loopback demo device (no hardware)")
    print("  q. quit")
    while True:
        try:
            choice = input("device> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if choice == "q":
            return None
        if choice == "l":
            return make_loopback_transport()
        if choice == "m":
            port = input("port path> ").strip()
            if not port:
                continue
        elif choice.isdigit() and 1 <= int(choice) <= len(ports):
            port = ports[int(choice) - 1][0]
        else:
            print("pick a number, 'm', 'l', or 'q'")
            continue
        try:
            return _serial_transport(port, args.baud), f"{port} @ {args.baud}"
        except Exception as exc:
            print(f"{style.red}could not open {port}: {exc}{style.reset}")


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for ``python -m rqft.demo`` and the rqft-demo script."""

    parser = argparse.ArgumentParser(
        prog="rqft-demo",
        description="Interactive RQFT demo client: browse, transfer, and inspect.",
    )
    transport_group = parser.add_mutually_exclusive_group()
    transport_group.add_argument(
        "--port", help="serial port (skip the interactive picker)"
    )
    parser.add_argument("--baud", type=int, default=115200, help="baud rate (default 115200)")
    parser.add_argument(
        "--dir",
        default="rqft-local",
        help="local mirror directory for downloads/uploads (default ./rqft-local)",
    )
    parser.add_argument(
        "--window",
        type=int,
        choices=range(1, WINDOW_MAX + 1),
        default=4,
        help="send window offered in HELLO (1-8, default 4)",
    )
    transport_group.add_argument(
        "--loopback",
        action="store_true",
        help="talk to an in-process demo responder instead of hardware",
    )
    parser.add_argument(
        "--debug", action="store_true", help="start with the live debug log enabled"
    )
    args = parser.parse_args(argv)

    style = Style(sys.stdout.isatty())
    log = DebugLog(style, echo=args.debug)

    try:
        chosen = _choose_transport(args, style)
    except DemoError as exc:
        print(f"{style.red}error:{style.reset} {exc}")
        return 1
    if chosen is None:
        return 0
    transport, label = chosen

    fs = LocalDirFs(args.dir)
    client = DeviceWorker(CountingTransport(transport), fs, log, window=args.window)
    client.start()
    print(f"{style.bold}rqft-demo{style.reset} — {label}")
    print(f"local mirror: {fs.root}")

    repl = Repl(client, log, style)
    try:
        try:
            repl._cmd_connect([])
        except (DemoError, OSError) as exc:
            print(f"{style.yellow}connect failed:{style.reset} {exc}")
            print("the device may be offline — try 'connect' again from the prompt")
        repl.run()
    finally:
        try:
            client.close_session()
        except Exception:
            pass
        client.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
