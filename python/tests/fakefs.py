# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Deterministic in-memory FsProvider for session-layer tests."""

from __future__ import annotations

from typing import Iterator, Optional

from rqft.fs import FsEntry


class FakeFs:
    """In-memory filesystem with scripted failures and full call logging.

    Attributes:
        files: Path to content mapping; mutated by commits and deletes.
        mtimes: Optional per-path modification times (default 0).
        fail_open_read: Paths whose open_read fails.
        fail_read_at: Path to byte offset after which read returns None.
        fail_read_total: Cumulative bytes across all reads after which
            every read returns None; None disables the fault.
        fail_open_write: Paths whose open_write fails.
        fail_write: When True every write fails.
        fail_commit: When True commit fails (and discards).
        fail_remove: Paths whose remove_file/remove_dir fails.
        deny_delete: Paths the per-request delete gate refuses.
        list_override: When set, list_entries yields exactly these.
        read_log: (path, returned_length) per successful read call.
        discarded: Count of discarded temporary files.
    """

    def __init__(
        self,
        files: Optional[dict[str, bytes]] = None,
        mtimes: Optional[dict[str, int]] = None,
    ) -> None:
        self.files: dict[str, bytes] = dict(files or {})
        self.mtimes: dict[str, int] = dict(mtimes or {})
        self.fail_open_read: set[str] = set()
        self.fail_read_at: dict[str, int] = {}
        self.fail_read_total: Optional[int] = None
        self.fail_open_write: set[str] = set()
        self.fail_write = False
        self.fail_commit = False
        self.fail_remove: set[str] = set()
        self.deny_delete: set[str] = set()
        self.list_override: Optional[list[FsEntry]] = None
        self.read_log: list[tuple[str, int]] = []
        self.discarded = 0
        self._read_path: Optional[str] = None
        self._read_pos = 0
        self._write_path: Optional[str] = None
        self._write_buf = bytearray()

    def entry(self, path: str) -> FsEntry:
        return FsEntry(path, len(self.files[path]), self.mtimes.get(path, 0), 0)

    def list_entries(self, root: str) -> Optional[Iterator[FsEntry]]:
        if self.list_override is not None:
            return iter(self.list_override)
        if root and not any(path.startswith(root + "/") for path in self.files):
            return None
        prefix = root + "/" if root else ""
        return iter(
            [self.entry(path) for path in sorted(self.files) if path.startswith(prefix)]
        )

    def open_read(self, path: str) -> Optional[int]:
        if path in self.fail_open_read or path not in self.files:
            return None
        self._read_path = path
        self._read_pos = 0
        return len(self.files[path])

    def read(self, max_len: int) -> Optional[bytes]:
        assert self._read_path is not None
        if self._read_pos >= self.fail_read_at.get(self._read_path, 1 << 62):
            return None
        total = sum(length for _, length in self.read_log)
        if self.fail_read_total is not None and total >= self.fail_read_total:
            return None
        data = self.files[self._read_path]
        chunk = data[self._read_pos : self._read_pos + max_len]
        self._read_pos += len(chunk)
        self.read_log.append((self._read_path, len(chunk)))
        return chunk

    def close_read(self) -> None:
        self._read_path = None

    def open_write(self, path: str) -> bool:
        if path in self.fail_open_write:
            return False
        self._write_path = path
        self._write_buf = bytearray()
        return True

    def write(self, data: bytes) -> bool:
        assert self._write_path is not None
        if self.fail_write:
            return False
        self._write_buf += data
        return True

    def commit(self) -> bool:
        assert self._write_path is not None
        path = self._write_path
        self._write_path = None
        if self.fail_commit:
            self.discarded += 1
            return False
        self.files[path] = bytes(self._write_buf)
        return True

    def discard(self) -> None:
        if self._write_path is not None:
            self._write_path = None
            self.discarded += 1

    def remove_file(self, path: str) -> bool:
        if path in self.fail_remove or path not in self.files:
            return False
        del self.files[path]
        return True

    def remove_dir(self, path: str) -> bool:
        if path in self.fail_remove:
            return False
        victims = [name for name in self.files if name.startswith(path + "/")]
        if not victims:
            return False
        for name in victims:
            del self.files[name]
        return True

    def allow_delete(self, path: str) -> bool:
        return path not in self.deny_delete

    @property
    def writing(self) -> bool:
        """True while a temporary file is open (not committed/discarded)."""

        return self._write_path is not None

    @property
    def reading(self) -> bool:
        """True while the read cursor is open."""

        return self._read_path is not None
