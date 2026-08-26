# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Blocking host utilities for SPEC.md section 5 operations.

BlockingSessionDriver binds any Python sans-io Session to a host-supplied
byte transport. SyncClient adds controller sync policy and LocalDirFs adds
path-confined temp-and-commit storage. GUI frameworks and serial details
stay outside this module.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Optional, Protocol, Sequence, TypeVar, Union

from rqft.crc32 import crc32_update
from rqft.events import (
    DelDone,
    Ended,
    EntryListed,
    Established,
    GetDone,
    ListDone,
    OpFailed,
    SessionEvent,
)
from rqft.fs import FsEntry
from rqft.link import AbortReason
from rqft.messages import ErrCode, Role, path_valid
from rqft.session import Session


class ByteTransport(Protocol):
    """Blocking byte transport consumed by SyncClient.

    Implementations may wrap serial ports, sockets, subprocess pipes, or
    tests. Empty reads mean timeout, not necessarily EOF.
    """

    def write(self, data: bytes) -> None:
        """Write all bytes to the peer or raise an exception."""
        ...

    def read(self, max_len: int, timeout: float) -> bytes:
        """Read up to max_len bytes, waiting at most timeout seconds."""
        ...

    def close(self) -> None:
        """Close the underlying transport."""
        ...


class CancelToken(Protocol):
    """Minimal cancellation token shape used by SyncClient."""

    def is_set(self) -> bool:
        """Return True when the caller requests cancellation."""
        ...


class ProgressPhase(Enum):
    """Progress event phase within one sync batch."""

    PLAN = "PLAN"
    GET = "GET"
    DEL = "DEL"
    DONE = "DONE"


@dataclass(frozen=True)
class SyncProgress:
    """Cumulative sync progress reported to the host callback.

    Attributes:
        phase: Current batch phase.
        path: File being processed, or None for batch-wide events.
        files_done: Files fetched and verified so far.
        files_total: Files selected for transfer by the diff.
        bytes_done: Bytes in fetched and verified files so far.
        bytes_total: Bytes selected for transfer by the diff.
    """

    phase: ProgressPhase
    path: Optional[str]
    files_done: int
    files_total: int
    bytes_done: int
    bytes_total: int


@dataclass(frozen=True)
class RemoteFile:
    """One file from the responder LIST result.

    Attributes:
        path: Validated relative remote path.
        size: File size in bytes.
        crc32: Whole-file CRC32, or None when responder omitted it.
        mtime: Modification time in Unix seconds.
    """

    path: str
    size: int
    crc32: Optional[int]
    mtime: int


@dataclass(frozen=True)
class SyncResult:
    """Summary of one completed SyncClient batch.

    Attributes:
        remote: Files returned by responder LIST.
        fetched: Remote files downloaded and verified locally.
        skipped: Remote files already matching local size and CRC32.
        deleted: Remote paths deleted after successful download.
    """

    remote: tuple[RemoteFile, ...]
    fetched: tuple[RemoteFile, ...]
    skipped: tuple[RemoteFile, ...]
    deleted: tuple[str, ...]


class SyncClientError(RuntimeError):
    """Base class for blocking client failures."""


class SyncTimeout(SyncClientError):
    """Raised when the peer does not complete an expected operation."""


class SyncCancelled(SyncClientError):
    """Raised after cancellation sends ABORT(E_USER)."""


class SyncOperationError(SyncClientError):
    """Raised when the peer answers ERR for a requested operation."""

    def __init__(self, event: OpFailed) -> None:
        """Capture the failed operation event for caller inspection."""

        self.event = event
        path = f" path={event.path!r}" if event.path is not None else ""
        super().__init__(
            f"operation {event.request.name} failed with {event.code.name}{path}"
        )


@dataclass(frozen=True)
class LocalFile:
    """Metadata used when diffing one local regular file.

    Attributes:
        path: Validated relative path below the provider root.
        size: File size in bytes.
        crc32: Whole-file CRC32.
    """

    path: str
    size: int
    crc32: int


class LocalDirFs:
    """Path-confined directory provider for controller transfers.

    Downloads are staged under ``<name>.rqft-part`` and atomically replace
    their destination only after session verification. Paths are confined
    below :attr:`root`; invalid or escaping protocol paths are rejected.
    """

    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._read: Optional[BinaryIO] = None
        self._write: Optional[BinaryIO] = None
        self._write_target: Optional[Path] = None
        self._write_temp: Optional[Path] = None

    def scan(self) -> dict[str, LocalFile]:
        """Return size and CRC for all regular files under the root."""

        found: dict[str, LocalFile] = {}
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.name.endswith(".rqft-part"):
                continue
            rel = path.relative_to(self.root).as_posix()
            if not _path_valid_text(rel, allow_empty=False):
                continue
            size = path.stat().st_size
            found[rel] = LocalFile(rel, size, _crc32_path(path))
        return found

    def file_info(self, path: str) -> Optional[LocalFile]:
        """Return local file size and CRC, or None when absent."""

        try:
            resolved = self._resolve(path)
        except ValueError:
            return None
        if not resolved.is_file():
            return None
        return LocalFile(path, resolved.stat().st_size, _crc32_path(resolved))

    def list_entries(self, root: str) -> Optional[Iterator[FsEntry]]:
        """List regular files under root for responder-mode use."""

        try:
            base = self._resolve(root, allow_empty=True)
        except ValueError:
            return None
        if not base.exists():
            return None
        files = [base] if base.is_file() else sorted(base.rglob("*"))
        entries: list[FsEntry] = []
        for path in files:
            if not path.is_file() or path.name.endswith(".rqft-part"):
                continue
            rel = path.relative_to(self.root).as_posix()
            if _path_valid_text(rel, allow_empty=False):
                stat = path.stat()
                entries.append(FsEntry(rel, stat.st_size, int(stat.st_mtime), 0))
        return iter(entries)

    def open_read(self, path: str) -> Optional[int]:
        """Open one local file for PUT or LIST hashing."""

        self.close_read()
        try:
            resolved = self._resolve(path)
            size = resolved.stat().st_size
            self._read = resolved.open("rb")
        except (OSError, ValueError):
            self._read = None
            return None
        return size

    def read(self, max_len: int) -> Optional[bytes]:
        """Read from the current local read cursor."""

        if self._read is None:
            return None
        try:
            return self._read.read(max_len)
        except OSError:
            return None

    def close_read(self) -> None:
        """Close the current read cursor if open."""

        if self._read is not None:
            self._read.close()
            self._read = None

    def open_write(self, path: str) -> bool:
        """Open a temporary file for an incoming GET."""

        self.discard()
        try:
            target = self._resolve(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            temp = target.with_name(target.name + ".rqft-part")
            self._write = temp.open("wb")
            self._write_target = target
            self._write_temp = temp
        except (OSError, ValueError):
            self._write = None
            self._write_target = None
            self._write_temp = None
            return False
        return True

    def write(self, data: bytes) -> bool:
        """Append bytes to the temporary write cursor."""

        if self._write is None:
            return False
        try:
            self._write.write(data)
        except OSError:
            return False
        return True

    def commit(self) -> bool:
        """Atomically replace the final path with the temporary file."""

        if self._write is None or self._write_target is None or self._write_temp is None:
            return False
        target = self._write_target
        temp = self._write_temp
        try:
            self._write.close()
            self._write = None
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(temp, target)
        except OSError:
            self._unlink_temp()
            return False
        finally:
            self._write_target = None
            self._write_temp = None
        return True

    def discard(self) -> None:
        """Discard any open temporary file."""

        if self._write is not None:
            self._write.close()
            self._write = None
        self._unlink_temp()
        self._write_target = None
        self._write_temp = None

    def remove_file(self, path: str) -> bool:
        """Remove one local file for responder-mode use."""

        try:
            resolved = self._resolve(path)
            resolved.unlink()
        except (OSError, ValueError):
            return False
        return True

    def remove_dir(self, path: str) -> bool:
        """Remove one local directory tree for responder-mode use."""

        try:
            shutil.rmtree(self._resolve(path))
        except (OSError, ValueError):
            return False
        return True

    def allow_delete(self, path: str) -> bool:
        """Permit local deletes when this provider is used by a responder."""

        return _path_valid_text(path, allow_empty=False)

    def _resolve(self, path: str, *, allow_empty: bool = False) -> Path:
        if not _path_valid_text(path, allow_empty=allow_empty):
            raise ValueError("path violates SPEC.md section 1 rules")
        candidate = self.root if path == "" else self.root.joinpath(*path.split("/"))
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError:
            raise ValueError("path escapes root") from None
        return resolved

    def _unlink_temp(self) -> None:
        if self._write_temp is not None:
            try:
                self._write_temp.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


T = TypeVar("T")

_BUSY_READ_TIMEOUT_S = 0.001


@dataclass(frozen=True)
class PumpResult:
    """Events and transport activity produced by one blocking pump turn.

    Attributes:
        events: Session events emitted by timers and received bytes.
        bytes_received: Raw transport bytes read during this turn.
    """

    events: tuple[SessionEvent, ...]
    bytes_received: int


class BlockingSessionDriver:
    """Drive one sans-io session over a blocking byte transport.

    The driver centralizes monotonic time, outbound draining, bounded reads,
    inbound delivery, and timer polling. Operation policy and event meaning
    remain with callers such as :class:`SyncClient` and interactive hosts.
    """

    def __init__(
        self,
        transport: ByteTransport,
        session: Session,
        *,
        read_size: int = 4096,
        io_timeout_s: float = 0.005,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind a session to a transport and monotonic clock.

        Args:
            transport: Blocking byte transport used for complete writes and
                timeout-bounded reads.
            session: Sans-io session owned by this driver.
            read_size: Maximum bytes requested from one transport read.
            io_timeout_s: Maximum idle wait in one :meth:`pump` call.
            clock: Monotonic seconds source; injectable for deterministic tests.

        Raises:
            ValueError: If read_size or io_timeout_s is not positive.
        """

        if read_size <= 0:
            raise ValueError("read_size must be positive")
        if io_timeout_s <= 0:
            raise ValueError("io_timeout_s must be positive")
        self._transport = transport
        self._session = session
        self._read_size = read_size
        self._io_timeout_s = io_timeout_s
        self._clock = clock
        self._clock_zero = clock()

    @property
    def session(self) -> Session:
        """Return session currently owned by the driver."""

        return self._session

    def replace_session(self, session: Session) -> None:
        """Replace ended or idle session while keeping transport and clock."""

        self._session = session

    def now_ms(self) -> int:
        """Return driver-relative monotonic milliseconds."""

        elapsed = self._clock() - self._clock_zero
        return max(0, int(elapsed * 1000.0))

    def flush(self) -> None:
        """Write all bytes currently queued by the session."""

        data = self._session.data_to_send()
        if data:
            self._transport.write(data)

    def pump(self, max_wait_s: Optional[float] = None) -> PumpResult:
        """Flush output, read once, deliver bytes, then run timers.

        Args:
            max_wait_s: Optional upper bound for this turn's transport wait.
                Zero requests a non-blocking read.

        Returns:
            Typed events plus raw received-byte count for activity tracking.

        Raises:
            ValueError: If max_wait_s is negative.
            OSError: If transport I/O fails.
        """

        if max_wait_s is not None and max_wait_s < 0:
            raise ValueError("max_wait_s must not be negative")
        events: list[SessionEvent] = []
        self.flush()

        data = self._transport.read(self._read_size, self._read_timeout(max_wait_s))
        if data:
            events += self._session.receive_bytes(data, self.now_ms())
        now_ms = self.now_ms()
        deadline = self._session.next_timeout()
        if self._session.work_pending() or (deadline is not None and deadline <= now_ms):
            events += self._session.handle_timeout(now_ms)
        self.flush()
        return PumpResult(tuple(events), len(data))

    def abort(self, reason: AbortReason) -> tuple[SessionEvent, ...]:
        """Abort current session, flush best-effort wire bytes, and return events."""

        events = tuple(self._session.abort(reason, self.now_ms()))
        self.flush()
        return events

    def _read_timeout(self, max_wait_s: Optional[float]) -> float:
        timeout = self._io_timeout_s
        if max_wait_s is not None:
            timeout = min(timeout, max_wait_s)
        if self._session.work_pending():
            timeout = min(timeout, _BUSY_READ_TIMEOUT_S)
        deadline = self._session.next_timeout()
        if deadline is not None:
            timeout = min(timeout, max(0.0, (deadline - self.now_ms()) / 1000.0))
        return max(0.0, timeout)


class SyncClient:
    """Blocking controller client for syncing files from a responder."""

    def __init__(
        self,
        transport: ByteTransport,
        root: Union[str, Path],
        *,
        sid_source: Optional[Callable[[], int]] = None,
        progress: Optional[Callable[[SyncProgress], None]] = None,
        cancel_event: Optional[CancelToken] = None,
        read_size: int = 4096,
        io_timeout_s: float = 0.005,
    ) -> None:
        """Create a client bound to a byte transport and local directory.

        Args:
            transport: Blocking byte transport to the peer.
            root: Local directory used for diffing and temp-write
                downloads.
            sid_source: Optional deterministic session id source for
                tests; production callers normally omit this.
            progress: Optional callback receiving cumulative progress
                events.
            cancel_event: Optional token checked between pump turns.
            read_size: Maximum bytes per transport read.
            io_timeout_s: Maximum idle wait per pump turn.

        Raises:
            ValueError: If read_size or io_timeout_s is not positive.
        """

        self._transport = transport
        self._fs = LocalDirFs(root)
        self._session = Session(Role.CONTROLLER, sid_source=sid_source, fs=self._fs)
        self._driver = BlockingSessionDriver(
            transport,
            self._session,
            read_size=read_size,
            io_timeout_s=io_timeout_s,
        )
        self._progress = progress
        self._cancel_event = cancel_event
        self._connected = False
        self._closed = False
        self._established: Optional[Established] = None

    def connect(self, timeout_s: float = 10.0) -> Established:
        """Open the RQFT session with HELLO/HELLO_OK.

        Args:
            timeout_s: Maximum seconds to wait for handshake completion.

        Returns:
            Established event describing negotiated parameters.

        Raises:
            SyncTimeout: If HELLO/HELLO_OK does not complete in time.
            SyncCancelled: If the cancellation token is set.
            SyncClientError: If the session ends during the handshake.
        """

        if self._connected:
            assert self._established is not None
            return self._established
        self._ensure_open()
        self._session.start(self._driver.now_ms())
        established = self._drive_until(
            lambda event: event if isinstance(event, Established) else None,
            timeout_s,
        )
        self._connected = True
        self._established = established
        return established

    def list_remote(self, root: str = "", timeout_s: float = 30.0) -> tuple[RemoteFile, ...]:
        """List responder files with per-file CRCs.

        Args:
            root: Relative remote directory root; empty lists all files.
            timeout_s: Maximum seconds to wait for LIST completion.

        Returns:
            Files surfaced by LIST_ENTRY, in peer order.

        Raises:
            SyncTimeout: If handshake or LIST does not complete in time.
            SyncCancelled: If cancellation is requested.
            SyncOperationError: If responder rejects LIST.
            SyncClientError: If session ends before LIST completes.
            OSError: If transport I/O fails.
        """

        self.connect(timeout_s=timeout_s)
        entries: list[RemoteFile] = []
        self._session.request_list(root, want_crc=True, now_ms=self._driver.now_ms())

        def accept(event: object) -> Optional[tuple[RemoteFile, ...]]:
            if isinstance(event, EntryListed) and event.etype == 0:
                entries.append(RemoteFile(event.path, event.size, event.crc32, event.mtime))
            if isinstance(event, ListDone):
                return tuple(entries)
            return None

        return self._drive_until(accept, timeout_s)

    def sync_from_peer(
        self,
        root: str = "",
        *,
        delete_remote: bool = False,
        timeout_s: float = 60.0,
        close: bool = True,
    ) -> SyncResult:
        """Download files missing or changed in the local directory.

        The batch performs HELLO when needed, LIST, local size+CRC diff,
        PLAN, GET for every non-matching file, optional remote DEL for
        fetched files, then a clean CLOSE by default.

        Args:
            root: Relative remote listing root; empty syncs all files.
            delete_remote: Delete each remote file after it is fetched
                and verified locally.
            timeout_s: Per-operation timeout in seconds.
            close: Send ABORT(CLOSE) and close the transport on success.

        Returns:
            SyncResult containing remote, fetched, skipped, and deleted
            paths.

        Raises:
            SyncTimeout: If handshake or an operation does not complete
                in time.
            SyncCancelled: If cancellation is requested.
            SyncOperationError: If responder rejects an operation.
            SyncClientError: If session ends or downloaded data fails
                post-commit verification.
            OSError: If transport or local filesystem I/O fails.
        """

        remote = self.list_remote(root, timeout_s=timeout_s)
        local = self._fs.scan()
        missing: list[RemoteFile] = []
        skipped: list[RemoteFile] = []
        for entry in remote:
            local_entry = local.get(entry.path)
            if (
                entry.crc32 is not None
                and local_entry is not None
                and local_entry.size == entry.size
                and local_entry.crc32 == entry.crc32
            ):
                skipped.append(entry)
            else:
                missing.append(entry)

        total_bytes = sum(entry.size for entry in missing)
        self._session.send_plan(len(missing), total_bytes, self._driver.now_ms())
        self._emit(
            SyncProgress(ProgressPhase.PLAN, None, 0, len(missing), 0, total_bytes)
        )

        fetched: list[RemoteFile] = []
        deleted: list[str] = []
        bytes_done = 0
        for entry in missing:
            self._check_cancel()
            event = self._get(entry, timeout_s)
            self._verify_download(entry, event)
            fetched.append(entry)
            bytes_done += entry.size
            self._emit(
                SyncProgress(
                    ProgressPhase.GET,
                    entry.path,
                    len(fetched),
                    len(missing),
                    bytes_done,
                    total_bytes,
                )
            )
            self._check_cancel()
            if delete_remote:
                self._delete(entry.path, timeout_s)
                deleted.append(entry.path)
                self._emit(
                    SyncProgress(
                        ProgressPhase.DEL,
                        entry.path,
                        len(fetched),
                        len(missing),
                        bytes_done,
                        total_bytes,
                    )
                )

        self._emit(
            SyncProgress(
                ProgressPhase.DONE,
                None,
                len(fetched),
                len(missing),
                bytes_done,
                total_bytes,
            )
        )
        result = SyncResult(tuple(remote), tuple(fetched), tuple(skipped), tuple(deleted))
        if close:
            self.close()
        return result

    def close(self) -> None:
        """Send ABORT(CLOSE) if live, then close the transport.

        Repeated calls are no-ops. Transport write/close exceptions propagate.
        """

        if self._closed:
            return
        if self._connected:
            self._driver.abort(AbortReason.CLOSE)
        self._transport.close()
        self._connected = False
        self._established = None
        self._closed = True

    def _get(self, entry: RemoteFile, timeout_s: float) -> GetDone:
        self._session.request_get(entry.path, now_ms=self._driver.now_ms())
        return self._drive_until(
            lambda event: event
            if isinstance(event, GetDone) and event.path == entry.path
            else None,
            timeout_s,
        )

    def _delete(self, path: str, timeout_s: float) -> DelDone:
        self._session.request_del(path, is_dir=False, now_ms=self._driver.now_ms())
        return self._drive_until(
            lambda event: event
            if isinstance(event, DelDone) and event.path == path and not event.is_dir
            else None,
            timeout_s,
        )

    def _verify_download(self, entry: RemoteFile, event: GetDone) -> None:
        if event.size != entry.size:
            raise SyncClientError(f"download size mismatch for {entry.path!r}")
        if entry.crc32 is not None and event.crc32 != entry.crc32:
            raise SyncClientError(f"download crc mismatch for {entry.path!r}")
        local = self._fs.file_info(entry.path)
        if local is None:
            raise SyncClientError(f"download missing after commit for {entry.path!r}")
        if local.size != entry.size:
            raise SyncClientError(f"local size mismatch after GET for {entry.path!r}")
        if entry.crc32 is not None and local.crc32 != entry.crc32:
            raise SyncClientError(f"local crc mismatch after GET for {entry.path!r}")

    def _drive_until(
        self,
        accept: Callable[[object], Optional[T]],
        timeout_s: float,
    ) -> T:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() <= deadline:
            self._check_cancel()
            turn = self._driver.pump(max(0.0, deadline - time.monotonic()))
            found = self._handle_events(turn.events, accept)
            if found is not None:
                return found
        raise SyncTimeout("timed out waiting for peer")

    def _handle_events(
        self, events: Sequence[object], accept: Callable[[object], Optional[T]]
    ) -> Optional[T]:
        found: Optional[T] = None
        failure: Optional[SyncClientError] = None
        for event in events:
            if isinstance(event, Ended):
                self._connected = False
                self._established = None
                if found is None and failure is None:
                    failure = SyncClientError(
                        f"session ended with {event.reason.name} "
                        f"from_peer={event.from_peer}"
                    )
                continue
            if found is not None or failure is not None:
                continue
            if isinstance(event, OpFailed):
                failure = SyncOperationError(event)
            else:
                found = accept(event)
        if failure is not None:
            raise failure
        return found

    def _emit(self, event: SyncProgress) -> None:
        if self._progress is not None:
            self._progress(event)

    def _check_cancel(self) -> None:
        if self._cancel_event is not None and self._cancel_event.is_set():
            self._abort_cancelled()
            raise SyncCancelled("sync cancelled")

    def _abort_cancelled(self) -> None:
        if self._closed:
            return
        if self._connected:
            self._driver.abort(AbortReason.E_USER)
        self._transport.close()
        self._connected = False
        self._established = None
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise SyncClientError("transport is closed")


def _path_valid_text(path: str, *, allow_empty: bool) -> bool:
    try:
        raw = path.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return path_valid(raw, allow_empty=allow_empty)


def _crc32_path(path: Path) -> int:
    crc = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(65536)
            if chunk == b"":
                return crc
            crc = crc32_update(crc, chunk)
