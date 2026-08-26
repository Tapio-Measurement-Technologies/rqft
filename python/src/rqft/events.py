# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Typed host events emitted by the session layer (SPEC.md section 5).

Every event is a frozen dataclass; the union type ``SessionEvent`` is what
:meth:`rqft.session.Session.receive_bytes` and
:meth:`rqft.session.Session.handle_timeout` return. Foreign line noise is
surfaced as :class:`rqft.frame.Passthrough`, re-exported here so hosts can
match on one module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from rqft.frame import Passthrough
from rqft.link import AbortReason
from rqft.messages import ErrCode, MsgType, Role

__all__ = [
    "DelDone",
    "Ended",
    "EntryListed",
    "EntrySkipped",
    "Established",
    "GetDone",
    "GetServed",
    "ListDone",
    "NotifyReceived",
    "OpFailed",
    "Passthrough",
    "PlanReceived",
    "PutDone",
    "SessionEvent",
]


@dataclass(frozen=True)
class Established:
    """Handshake completed; the session is active.

    Attributes:
        sid: Session id shared by both endpoints.
        version: Negotiated protocol version.
        role: This endpoint's role.
        max_payload: Effective frame payload limit (pair minimum).
        window: Effective send window (pair minimum).
        peer_caps: Capability bits declared by the peer.
    """

    sid: int
    version: int
    role: Role
    max_payload: int
    window: int
    peer_caps: int


@dataclass(frozen=True)
class Ended:
    """The session terminated and no further traffic is possible.

    Attributes:
        reason: ABORT reason code; CLOSE marks a clean shutdown.
        from_peer: True when the peer initiated the termination.
    """

    reason: AbortReason
    from_peer: bool


@dataclass(frozen=True)
class EntryListed:
    """One LIST_ENTRY collected by the controller.

    Attributes:
        etype: Entry type byte; 0 is a file, other values are reserved.
        path: Validated relative file path.
        size: File size in bytes.
        mtime: Modification time in Unix seconds.
        crc32: Whole-file CRC32, or None when the responder skipped it.
    """

    etype: int
    path: str
    size: int
    mtime: int
    crc32: Optional[int]


@dataclass(frozen=True)
class EntrySkipped:
    """The responder's LIST skipped one file it could not read.

    Informative only: the responder reported the skip with an
    ERR(E_FS_READ) during a LIST (SPEC.md section 5.4). The listing
    continues and the LIST_END count excludes the file.

    Attributes:
        code: Error code carried by the informational ERR.
        detail: Implementation-defined detail value carried by the ERR.
    """

    code: ErrCode
    detail: int


@dataclass(frozen=True)
class ListDone:
    """A LIST operation completed.

    Attributes:
        count: Entries received, matching the responder's LIST_END count.
    """

    count: int


@dataclass(frozen=True)
class GetDone:
    """A GET operation verified and committed its file.

    Attributes:
        path: Relative destination path of the committed file.
        size: File size in bytes, as verified against FILE_INFO.
        crc32: Whole-file CRC32, as verified against FILE_END.
    """

    path: str
    size: int
    crc32: int


@dataclass(frozen=True)
class GetServed:
    """A GET this responder served was verified and committed by the peer.

    Emitted when the controller's GET_DONE(0) confirms the download
    (SPEC.md section 5.4). A non-zero GET_DONE status surfaces as
    :class:`OpFailed` instead.

    Attributes:
        path: Relative source path of the served file.
        size: File size in bytes, as sent in FILE_INFO.
        crc32: Whole-file CRC32, as sent in FILE_END.
    """

    path: str
    size: int
    crc32: int


@dataclass(frozen=True)
class PutDone:
    """A PUT operation was verified and committed by the responder.

    Attributes:
        path: Relative destination path of the committed file.
        size: File size in bytes, as promised by PUT_REQ.
        crc32: Whole-file CRC32, as promised by PUT_REQ.
    """

    path: str
    size: int
    crc32: int


@dataclass(frozen=True)
class DelDone:
    """A DEL operation completed on the responder.

    Attributes:
        path: Relative path that was removed.
        is_dir: True when the request was a recursive DEL_DIR.
    """

    path: str
    is_dir: bool


@dataclass(frozen=True)
class PlanReceived:
    """Batch totals announced by the controller's PLAN (responder side).

    Informative only: no reply is sent; hosts typically feed this to a
    progress display.

    Attributes:
        nfiles: Number of files the controller intends to transfer.
        nbytes: Total bytes the controller intends to transfer.
    """

    nfiles: int
    nbytes: int


@dataclass(frozen=True)
class NotifyReceived:
    """The responder asked this controller to pull files (NOTIFY).

    Informative only: no reply is sent and no operation slot is held;
    hosts typically start their sync flow.

    Attributes:
        flags: NOTIFY_* bits describing the requested sync. Bit 0 is the
            sync mode: 0 = full sync, 1 = incremental sync.
    """

    flags: int


@dataclass(frozen=True)
class OpFailed:
    """An operation failed without ending the session (SPEC.md section 5.3).

    Attributes:
        request: msg_type of the request that failed.
        path: Path the operation named, or None for path-less failures.
        code: Error code from the ERR message or local verification.
        detail: Implementation-defined detail value; 0 for local failures.
    """

    request: MsgType
    path: Optional[str]
    code: ErrCode
    detail: int


# Event union emitted by the session layer to the host.
SessionEvent = Union[
    Established,
    Ended,
    Passthrough,
    EntryListed,
    EntrySkipped,
    ListDone,
    GetDone,
    GetServed,
    PutDone,
    DelDone,
    PlanReceived,
    NotifyReceived,
    OpFailed,
]
