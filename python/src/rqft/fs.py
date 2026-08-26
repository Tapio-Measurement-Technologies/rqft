# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Host filesystem interface consumed by the session layer (SPEC.md section 5.4).

The session never touches storage directly: a responder answers LIST,
GET, PUT, and DEL against an injected :class:`FsProvider`; a controller
uses the same provider to stage received files (temp-write-then-commit)
and to source uploads. All calls are synchronous and expected to do a
small bounded amount of work.

The provider holds at most one read cursor and one write cursor at a
time; the session opens and closes them in strict pairs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional, Protocol


@dataclass(frozen=True)
class FsEntry:
    """One file offered by a listing iterator.

    Attributes:
        path: Full relative path with ``/`` separators.
        size: File size in bytes.
        mtime: Modification time in Unix seconds.
        etype: Entry type byte; 0 is a file, other values are reserved.
    """

    path: str
    size: int
    mtime: int = 0
    etype: int = 0


class FsProvider(Protocol):
    """Filesystem callbacks the host supplies to a session.

    Which entries a listing yields (recursion, filtering) is host
    policy; the session only encodes what the iterator produces.
    """

    def list_entries(self, root: str) -> Optional[Iterator[FsEntry]]:
        """Open a listing cursor under root.

        Args:
            root: Relative directory path; empty means the whole tree.

        Returns:
            An iterator of entries, or None when the root cannot be
            opened.
        """
        ...

    def open_read(self, path: str) -> Optional[int]:
        """Open the single read cursor on a file.

        Args:
            path: Relative file path.

        Returns:
            The file size in bytes, or None when the file cannot be
            opened.
        """
        ...

    def read(self, max_len: int) -> Optional[bytes]:
        """Read from the open read cursor.

        Args:
            max_len: Largest chunk to return.

        Returns:
            1 to max_len bytes, empty bytes at end of file, or None on
            a read error.
        """
        ...

    def close_read(self) -> None:
        """Close the read cursor; a no-op when none is open."""
        ...

    def open_write(self, path: str) -> bool:
        """Open the single write cursor as a temporary file for path.

        The temporary naming scheme is the provider's business; the
        session only sees commit/discard.

        Args:
            path: Final relative destination path.

        Returns:
            True when the temporary file is ready for writing.
        """
        ...

    def write(self, data: bytes) -> bool:
        """Append to the open write cursor.

        Args:
            data: Bytes to append.

        Returns:
            True on success; False on a write error.
        """
        ...

    def commit(self) -> bool:
        """Atomically publish the written temporary file.

        Creates missing parent directories of the destination and
        renames the temporary file over it, closing the write cursor.

        Returns:
            True on success; False when the rename or directory
            creation failed (the temporary file is discarded).
        """
        ...

    def discard(self) -> None:
        """Delete the temporary file and close the write cursor."""
        ...

    def remove_file(self, path: str) -> bool:
        """Remove one file.

        Args:
            path: Relative file path.

        Returns:
            True on success.
        """
        ...

    def remove_dir(self, path: str) -> bool:
        """Remove one directory tree recursively.

        Args:
            path: Relative directory path.

        Returns:
            True on success.
        """
        ...

    def allow_delete(self, path: str) -> bool:
        """Per-request delete gate (SPEC.md section 5.4 double-gating).

        Args:
            path: Path a DEL_FILE/DEL_DIR names.

        Returns:
            True when the host permits this specific delete.
        """
        ...
