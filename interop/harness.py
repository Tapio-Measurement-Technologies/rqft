# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Subprocess harness connecting Python Session to native c_peer."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, TypeVar

ROOT = Path(__file__).resolve().parents[1]
PY_SRC = ROOT / "python" / "src"
if str(PY_SRC) not in sys.path:
    sys.path.insert(0, str(PY_SRC))

from rqft.fs import FsEntry
from rqft.messages import Role
from rqft.session import Session

from fault_shim import FaultShim

EventT = TypeVar("EventT")


class MemoryFs:
    """Small in-memory FsProvider for process interop tests."""

    def __init__(self, files: Optional[dict[str, bytes]] = None) -> None:
        self.files: dict[str, bytes] = dict(files or {})
        self._read_path: Optional[str] = None
        self._read_pos = 0
        self._write_path: Optional[str] = None
        self._write_buf = bytearray()

    @property
    def writing(self) -> bool:
        """True while a temporary write is open."""

        return self._write_path is not None

    def list_entries(self, root: str) -> Optional[Iterator[FsEntry]]:
        if root and not any(path.startswith(root + "/") for path in self.files):
            return None
        prefix = root + "/" if root else ""
        entries = [
            FsEntry(path, len(self.files[path]), 0, 0)
            for path in sorted(self.files)
            if path.startswith(prefix)
        ]
        return iter(entries)

    def open_read(self, path: str) -> Optional[int]:
        if path not in self.files:
            return None
        self._read_path = path
        self._read_pos = 0
        return len(self.files[path])

    def read(self, max_len: int) -> Optional[bytes]:
        assert self._read_path is not None
        data = self.files[self._read_path]
        chunk = data[self._read_pos : self._read_pos + max_len]
        self._read_pos += len(chunk)
        return chunk

    def close_read(self) -> None:
        self._read_path = None
        self._read_pos = 0

    def open_write(self, path: str) -> bool:
        self._write_path = path
        self._write_buf = bytearray()
        return True

    def write(self, data: bytes) -> bool:
        assert self._write_path is not None
        self._write_buf += data
        return True

    def commit(self) -> bool:
        assert self._write_path is not None
        self.files[self._write_path] = bytes(self._write_buf)
        self._write_path = None
        self._write_buf = bytearray()
        return True

    def discard(self) -> None:
        self._write_path = None
        self._write_buf = bytearray()

    def remove_file(self, path: str) -> bool:
        if path not in self.files:
            return False
        del self.files[path]
        return True

    def remove_dir(self, path: str) -> bool:
        victims = [name for name in self.files if name.startswith(path + "/")]
        for name in victims:
            del self.files[name]
        return bool(victims)

    def allow_delete(self, path: str) -> bool:
        return bool(path)


def ensure_c_peer() -> Path:
    """Build and return the native c_peer executable."""

    build_dir = ROOT / "c" / "build"
    exe = build_dir / "c_peer"
    if not (build_dir / "CMakeCache.txt").exists():
        subprocess.run(
            ["cmake", "-S", "c", "-B", "c/build", "-DCMAKE_BUILD_TYPE=Debug"],
            cwd=ROOT,
            check=True,
        )
    subprocess.run(
        ["cmake", "--build", "c/build", "--target", "c_peer"],
        cwd=ROOT,
        check=True,
    )
    return exe


class CPeer:
    """Running c_peer process with JSONL diagnostics."""

    def __init__(self, args: list[str]) -> None:
        exe = ensure_c_peer()
        env = os.environ.copy()
        asan = env.get("ASAN_OPTIONS", "")
        env["ASAN_OPTIONS"] = (
            f"{asan}:detect_leaks=0" if asan else "detect_leaks=0"
        )
        self.proc = subprocess.Popen(
            [str(exe)] + args,
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=env,
        )
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        assert self.proc.stderr is not None
        self.stdin = self.proc.stdin
        self._selector = selectors.DefaultSelector()
        self._selector.register(self.proc.stdout, selectors.EVENT_READ, "stdout")
        self._selector.register(self.proc.stderr, selectors.EVENT_READ, "stderr")
        self.events: list[dict[str, Any]] = []
        self.raw_stderr: list[str] = []
        self._stderr_buf = b""

    def send(self, data: bytes) -> None:
        """Write bytes to c_peer stdin."""

        try:
            self.stdin.write(data)
            self.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass

    def close_stdin(self) -> None:
        """Close the peer's stdin pipe."""

        try:
            self.stdin.close()
        except BrokenPipeError:
            pass

    def kill(self) -> None:
        """Terminate a still-running peer."""

        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def read_available(self, timeout: float) -> list[bytes]:
        """Drain ready stdout/stderr without blocking past timeout."""

        stdout_chunks: list[bytes] = []
        for key, _ in self._selector.select(timeout):
            fileobj = key.fileobj
            assert not isinstance(fileobj, int)
            data = os.read(fileobj.fileno(), 65536)
            if not data:
                try:
                    self._selector.unregister(key.fileobj)
                except KeyError:
                    pass
                continue
            if key.data == "stdout":
                stdout_chunks.append(data)
            else:
                self._consume_stderr(data)
        return stdout_chunks

    def wait(self, timeout: float = 5.0) -> int:
        """Wait for process exit while draining diagnostics."""

        deadline = time.monotonic() + timeout
        while self.proc.poll() is None and time.monotonic() < deadline:
            self.read_available(0.01)
        if self.proc.poll() is None:
            raise AssertionError("c_peer did not exit")
        self.drain_after_exit()
        return int(self.proc.returncode)

    def drain_after_exit(self, timeout: float = 1.0) -> list[bytes]:
        """Drain protocol output and diagnostics after process exit.

        Args:
            timeout: Maximum seconds allowed for pipe EOF delivery.

        Returns:
            Remaining protocol-byte chunks read from stdout.

        Raises:
            ValueError: Process has not exited or timeout is negative.
            AssertionError: Pipe EOF does not arrive before timeout.
        """

        if timeout < 0:
            raise ValueError("timeout must not be negative")
        if self.proc.poll() is None:
            raise ValueError("c_peer is still running")
        deadline = time.monotonic() + timeout
        stdout_chunks: list[bytes] = []
        while self._selector.get_map() and time.monotonic() < deadline:
            stdout_chunks += self.read_available(
                max(0.0, min(0.01, deadline - time.monotonic()))
            )
        if self._selector.get_map():
            raise AssertionError("c_peer pipes did not reach EOF")
        if self._stderr_buf:
            self._consume_stderr(b"\n")
        return stdout_chunks

    def assert_clean_exit(self) -> None:
        """Assert process returned success."""

        rc = self.wait()
        if rc != 0:
            raise AssertionError(
                f"c_peer exited {rc}; events={self.events!r}; stderr={self.raw_stderr!r}"
            )

    def events_named(self, name: str) -> list[dict[str, Any]]:
        """Return peer events with the given JSON event name."""

        return [event for event in self.events if event.get("event") == name]

    def file_hex(self, path: str) -> Optional[str]:
        """Return the last dumped hex payload for one peer file."""

        matches = [
            event.get("hex")
            for event in self.events_named("fs_file")
            if event.get("path") == path
        ]
        if not matches:
            return None
        value = matches[-1]
        assert isinstance(value, str)
        return value

    def _consume_stderr(self, data: bytes) -> None:
        self._stderr_buf += data
        while b"\n" in self._stderr_buf:
            raw, self._stderr_buf = self._stderr_buf.split(b"\n", 1)
            if not raw:
                continue
            text = raw.decode("utf-8", errors="replace")
            try:
                event = json.loads(text)
            except json.JSONDecodeError:
                self.raw_stderr.append(text)
                continue
            if isinstance(event, dict):
                self.events.append(event)
            else:
                self.raw_stderr.append(text)


class CPeerTransport:
    """Blocking byte transport facade over a running CPeer.

    This gives high-level client tests the same read/write/close shape as
    serial_transport.SerialTransport while still using the native interop
    peer and deterministic byte fault shims.
    """

    def __init__(
        self,
        peer: CPeer,
        *,
        py_to_c: FaultShim | None = None,
        c_to_py: FaultShim | None = None,
    ) -> None:
        """Wrap peer stdio with optional deterministic fault shims.

        Args:
            peer: Running native peer process.
            py_to_c: Transform bytes written by Python before C sees
                them. Defaults to a clean shim.
            c_to_py: Transform bytes read from C before Python sees
                them. Defaults to a clean shim.
        """

        self._peer = peer
        self._py_to_c = py_to_c or FaultShim(seed=0xC0DE)
        self._c_to_py = c_to_py or FaultShim(seed=0xFACE)
        self._in = bytearray()
        self._closed = False

    def write(self, data: bytes) -> None:
        """Write bytes toward c_peer."""

        if self._closed:
            raise ValueError("transport is closed")
        for chunk in self._py_to_c.feed(data):
            self._peer.send(chunk)

    def read(self, max_len: int, timeout: float) -> bytes:
        """Read at most max_len bytes, returning empty bytes on timeout."""

        if max_len <= 0:
            raise ValueError("max_len must be positive")
        if self._closed:
            return b""
        self._drain_outgoing_delay()
        if not self._in:
            for data in self._peer.read_available(timeout):
                for chunk in self._c_to_py.feed(data):
                    self._in += chunk
            for chunk in self._c_to_py.feed(b""):
                self._in += chunk
        if not self._in:
            return b""
        out = bytes(self._in[:max_len])
        del self._in[:max_len]
        return out

    def close(self) -> None:
        """Close the peer stdin side after flushing delayed writes."""

        if self._closed:
            return
        self._drain_outgoing_delay(flush=True)
        self._closed = True
        self._peer.close_stdin()

    def _drain_outgoing_delay(self, *, flush: bool = False) -> None:
        chunks = self._py_to_c.flush() if flush else self._py_to_c.feed(b"")
        for chunk in chunks:
            self._peer.send(chunk)


class InteropHarness:
    """Pump bytes between one Python Session and one c_peer process."""

    def __init__(
        self,
        peer: CPeer,
        session: Session,
        *,
        py_to_c: FaultShim | None = None,
        c_to_py: FaultShim | None = None,
    ) -> None:
        self.peer = peer
        self.session = session
        self.py_to_c = py_to_c or FaultShim(seed=0xA11CE)
        self.c_to_py = c_to_py or FaultShim(seed=0xB0B)
        self.now_ms = 0
        self.py_events: list[object] = []

    def drive_until(
        self,
        predicate: Callable[[list[object], list[dict[str, Any]]], bool],
        *,
        max_steps: int = 20000,
    ) -> None:
        """Drive both endpoints until predicate observes success."""

        quiet_after_match = 0
        for _ in range(max_steps):
            progressed = self.step()
            if predicate(self.py_events, self.peer.events):
                quiet_after_match = quiet_after_match + 1 if not progressed else 0
                if quiet_after_match >= 2:
                    return
            if self.peer.proc.poll() is not None and not predicate(
                self.py_events, self.peer.events
            ):
                self._drain_exited_peer()
                if predicate(self.py_events, self.peer.events):
                    return
                raise AssertionError(
                    f"c_peer exited {self.peer.proc.returncode} early; "
                    f"events={self.peer.events!r}; "
                    f"stderr={self.peer.raw_stderr!r}"
                )
        raise AssertionError(
            f"interop drive stalled; py_events={self.py_events!r}; "
            f"c_events={self.peer.events!r}; stderr={self.peer.raw_stderr!r}"
        )

    def drive_peer_exit(self) -> None:
        """Drive until c_peer exits, then assert clean status."""

        for _ in range(20000):
            self.step()
            if self.peer.proc.poll() is not None:
                self._drain_exited_peer()
                self.peer.assert_clean_exit()
                return
        raise AssertionError("c_peer did not exit while harness was pumping")

    def step(self) -> bool:
        """Run one duplex pump turn."""

        progressed = False
        outbound = self.session.data_to_send()
        if outbound:
            for chunk in self.py_to_c.feed(outbound):
                self.peer.send(chunk)
            progressed = True

        deadline = self.session.next_timeout()
        timer_due = deadline is not None and deadline <= self.now_ms
        if self.session.work_pending() or timer_due:
            self.py_events += self.session.handle_timeout(self.now_ms)
            progressed = True

        for data in self.peer.read_available(0.001):
            for chunk in self.c_to_py.feed(data):
                self.py_events += self.session.receive_bytes(chunk, self.now_ms)
            progressed = True

        self.now_ms += 1
        return progressed

    def _drain_exited_peer(self) -> None:
        """Deliver all process output written before peer exit."""

        for data in self.peer.drain_after_exit():
            for chunk in self.c_to_py.feed(data):
                self.py_events += self.session.receive_bytes(chunk, self.now_ms)
        for chunk in self.c_to_py.flush():
            self.py_events += self.session.receive_bytes(chunk, self.now_ms)


def has_py_event(events: list[object], typ: type[EventT]) -> bool:
    """Return whether events contains an instance of typ."""

    return any(isinstance(event, typ) for event in events)
