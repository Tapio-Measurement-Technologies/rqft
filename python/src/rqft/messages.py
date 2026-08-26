# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Session-layer body codecs for SPEC.md sections 5.2 and 5.3.

HELLO and HELLO_OK bodies travel as the payload of their frame types;
every other message is ``u8 msg_type`` plus a typed body carried as the
entire payload of one DATA frame. All codecs are pure: dataclasses in,
bytes out, and decode raises :class:`MessageError` on any structural
violation.

Paths stay ``bytes`` at this layer: SPEC.md section 1 path *content*
rules are checked separately with :func:`path_valid` so the session can
answer ``ERR(E_PATH)`` instead of treating a bad path as a protocol
violation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Final, Union

from rqft import MAX_PATH, MAX_PAYLOAD, WINDOW_MAX

# HELLO and HELLO_OK bodies are fixed eight bytes, from SPEC.md section 5.2.
_HELLO_LEN: Final = 8

# caps bit granting DEL_FILE/DEL_DIR against this endpoint's filesystem.
CAP_ALLOW_DELETE: Final = 0x01

# caps bits not defined by protocol version 1; they must be zero.
_CAPS_RESERVED_MASK: Final = 0xFE

# NOTIFY sync-mode flag bit: clear = full sync (complete mirror), set =
# incremental sync (pull only files new since the controller's last sync).
NOTIFY_SYNC_INCREMENTAL: Final = 0x00000001

# NOTIFY flag bit: delete each file from the responder's filesystem after
# a verified fetch. Only actionable together with CAP_ALLOW_DELETE, which
# gates the DEL operations.
NOTIFY_DELETE_AFTER_SYNC: Final = 0x00000002

# NOTIFY flag bits defined by this implementation; the rest are masked
# on receive and rejected on send per SPEC.md section 5.4.
_NOTIFY_DEFINED_MASK: Final = 0x00000003


class MessageError(ValueError):
    """Raised when a body cannot be encoded or decoded per the spec."""


class Role(IntEnum):
    """Endpoint roles from SPEC.md section 5.1."""

    CONTROLLER = 0x00
    RESPONDER = 0x01


def _u16_le(value: int) -> bytes:
    return value.to_bytes(2, "little")


@dataclass(frozen=True)
class Hello:
    """HELLO body from SPEC.md section 5.2.

    Attributes:
        ver_min: Lowest protocol version supported.
        ver_max: Highest protocol version supported.
        role: Sender's session role.
        max_payload: Largest frame payload the sender accepts, 1 to 512.
        window: Largest send window the sender can buffer, 1 to 8.
        caps: Capability bits; only CAP_ALLOW_DELETE is defined.
    """

    ver_min: int
    ver_max: int
    role: Role
    max_payload: int
    window: int
    caps: int

    def encode(self) -> bytes:
        """Encode into the eight-byte wire body.

        Returns:
            The HELLO body bytes.

        Raises:
            MessageError: If any field is out of its spec range.
        """

        _check_hello_fields(self.ver_min, self.ver_max, self.max_payload, self.window, self.caps)
        return (
            bytes([self.ver_min, self.ver_max, self.role])
            + _u16_le(self.max_payload)
            + bytes([self.window, self.caps, 0])
        )

    @classmethod
    def decode(cls, data: bytes) -> Hello:
        """Decode a HELLO body.

        Args:
            data: Exactly eight body bytes.

        Returns:
            The decoded HELLO.

        Raises:
            MessageError: If the length, a field range, or a reserved
                byte violates the spec.
        """

        if len(data) != _HELLO_LEN:
            raise MessageError("HELLO body must be 8 bytes")
        if data[7] != 0:
            raise MessageError("HELLO reserved byte must be 0")
        role = _decode_role(data[2])
        max_payload = int.from_bytes(data[3:5], "little")
        hello = cls(data[0], data[1], role, max_payload, data[5], data[6])
        _check_hello_fields(hello.ver_min, hello.ver_max, hello.max_payload, hello.window, hello.caps)
        return hello


@dataclass(frozen=True)
class HelloOk:
    """HELLO_OK body from SPEC.md section 5.2.

    Attributes:
        ver: Chosen protocol version.
        role: Replier's session role, the complement of HELLO.role.
        max_payload: Replier's payload limit; effective is the pair minimum.
        window: Replier's window limit; effective is the pair minimum.
        caps: Replier's capability bits.
    """

    ver: int
    role: Role
    max_payload: int
    window: int
    caps: int

    def encode(self) -> bytes:
        """Encode into the eight-byte wire body.

        Returns:
            The HELLO_OK body bytes.

        Raises:
            MessageError: If any field is out of its spec range.
        """

        _check_hello_fields(self.ver, self.ver, self.max_payload, self.window, self.caps)
        return (
            bytes([self.ver, self.role])
            + _u16_le(self.max_payload)
            + bytes([self.window, self.caps, 0, 0])
        )

    @classmethod
    def decode(cls, data: bytes) -> HelloOk:
        """Decode a HELLO_OK body.

        Args:
            data: Exactly eight body bytes.

        Returns:
            The decoded HELLO_OK.

        Raises:
            MessageError: If the length, a field range, or a reserved
                byte violates the spec.
        """

        if len(data) != _HELLO_LEN:
            raise MessageError("HELLO_OK body must be 8 bytes")
        if data[6] != 0 or data[7] != 0:
            raise MessageError("HELLO_OK reserved bytes must be 0")
        role = _decode_role(data[1])
        max_payload = int.from_bytes(data[2:4], "little")
        ok = cls(data[0], role, max_payload, data[4], data[5])
        _check_hello_fields(ok.ver, ok.ver, ok.max_payload, ok.window, ok.caps)
        return ok


def _decode_role(byte: int) -> Role:
    """Map a wire role byte to a Role.

    Raises:
        MessageError: If the byte is not a defined role.
    """

    try:
        return Role(byte)
    except ValueError:
        raise MessageError(f"undefined role byte 0x{byte:02x}") from None


def _check_hello_fields(
    ver_min: int, ver_max: int, max_payload: int, window: int, caps: int
) -> None:
    """Validate shared HELLO/HELLO_OK field ranges.

    Raises:
        MessageError: If a version ordering, limit range, or reserved
            caps bit violates SPEC.md section 5.2.
    """

    if not 0 <= ver_min <= ver_max <= 255:
        raise MessageError("version range must satisfy 0 <= ver_min <= ver_max <= 255")
    if not 1 <= max_payload <= MAX_PAYLOAD:
        raise MessageError("max_payload must be in [1, MAX_PAYLOAD]")
    if not 1 <= window <= WINDOW_MAX:
        raise MessageError("window must be in [1, WINDOW_MAX]")
    if caps & _CAPS_RESERVED_MASK:
        raise MessageError("reserved caps bits must be 0")


class MsgType(IntEnum):
    """Message type values from SPEC.md section 5.3."""

    LIST_REQ = 0x10
    LIST_ENTRY = 0x11
    LIST_END = 0x12
    GET_REQ = 0x20
    FILE_INFO = 0x21
    FILE_DATA = 0x22
    FILE_END = 0x23
    GET_DONE = 0x24
    PUT_REQ = 0x28
    PUT_OK = 0x29
    PUT_DONE = 0x2A
    DEL_FILE = 0x30
    DEL_DIR = 0x31
    DEL_OK = 0x32
    PLAN = 0x40
    NOTIFY = 0x41
    PING = 0x50
    PONG = 0x51
    ERR = 0x7F


class ErrCode(IntEnum):
    """Non-fatal per-operation error codes from SPEC.md section 5.3."""

    E_FS_OPEN = 0x01
    E_FS_READ = 0x02
    E_FS_WRITE = 0x03
    E_FS_REMOVE = 0x04
    E_PATH = 0x05
    E_CRC_FILE = 0x06
    E_TOO_LARGE = 0x07
    E_DENIED = 0x08
    E_BAD_STATE = 0x09
    E_UNSUPPORTED = 0x0A


def path_valid(path: bytes, allow_empty: bool = False) -> bool:
    """Check SPEC.md section 1 path content rules.

    Args:
        path: Raw wire path bytes.
        allow_empty: Accept the zero-length path (LIST_REQ whole-tree
            root only).

    Returns:
        True when the path is relative UTF-8 with non-empty segments,
        no ``.``/``..`` segments, no NUL, and no backslash.
    """

    if len(path) == 0:
        return allow_empty
    if len(path) > MAX_PATH:
        return False
    if b"\x00" in path or b"\\" in path:
        return False
    try:
        path.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(segment not in (b"", b".", b"..") for segment in path.split(b"/"))


def _u32_le(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _check_u8(value: int, name: str) -> int:
    if not 0 <= value <= 0xFF:
        raise MessageError(f"{name} must fit u8")
    return value


def _check_u16(value: int, name: str) -> int:
    if not 0 <= value <= 0xFFFF:
        raise MessageError(f"{name} must fit u16")
    return value


def _check_u32(value: int, name: str) -> int:
    if not 0 <= value <= 0xFFFFFFFF:
        raise MessageError(f"{name} must fit u32")
    return value


def _encode_path(path: bytes) -> bytes:
    """Encode the u8-length-prefixed path field.

    Raises:
        MessageError: If the path exceeds MAX_PATH bytes.
    """

    if len(path) > MAX_PATH:
        raise MessageError("path exceeds MAX_PATH")
    return bytes([len(path)]) + path


class _Reader:
    """Bounded little-endian field reader over one message body."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def _take(self, count: int) -> bytes:
        if self._pos + count > len(self._data):
            raise MessageError("message body too short")
        chunk = self._data[self._pos : self._pos + count]
        self._pos += count
        return chunk

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self._take(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self._take(4), "little")

    def path(self) -> bytes:
        length = self.u8()
        if length > MAX_PATH:
            raise MessageError("path length prefix exceeds MAX_PATH")
        return self._take(length)

    def rest(self) -> bytes:
        chunk = self._data[self._pos :]
        self._pos = len(self._data)
        return chunk

    def finish(self) -> None:
        if self._pos != len(self._data):
            raise MessageError("trailing bytes after message body")


@dataclass(frozen=True)
class ListReq:
    """LIST_REQ body: start a listing operation (controller to responder).

    Attributes:
        want_crc: Ask the responder to compute per-file CRC32.
        root: Listing root path; empty means the whole tree.
    """

    want_crc: bool
    root: bytes = b""

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a long root."""

        return bytes([MsgType.LIST_REQ, 0x01 if self.want_crc else 0x00]) + _encode_path(self.root)


@dataclass(frozen=True)
class ListEntry:
    """LIST_ENTRY body: one listed file (responder to controller).

    Attributes:
        etype: Entry type byte; 0 is a file, other values are reserved.
        crc_valid: True when crc32 holds a computed value.
        size: File size in bytes.
        crc32: Whole-file CRC32 when crc_valid, otherwise 0.
        mtime: Modification time in Unix seconds.
        path: Full relative file path.
    """

    etype: int
    crc_valid: bool
    size: int
    crc32: int
    mtime: int
    path: bytes

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on bad fields."""

        return (
            bytes([MsgType.LIST_ENTRY, _check_u8(self.etype, "etype"), 0x01 if self.crc_valid else 0x00])
            + _u32_le(_check_u32(self.size, "size"))
            + _u32_le(_check_u32(self.crc32, "crc32"))
            + _u32_le(_check_u32(self.mtime, "mtime"))
            + _encode_path(self.path)
        )


@dataclass(frozen=True)
class ListEnd:
    """LIST_END body: listing finished.

    Attributes:
        count: Number of LIST_ENTRY messages sent.
    """

    count: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a bad count."""

        return bytes([MsgType.LIST_END]) + _check_u16(self.count, "count").to_bytes(2, "little")


@dataclass(frozen=True)
class GetReq:
    """GET_REQ body: request a file download.

    Attributes:
        offset: Resume offset; must be 0 in protocol version 1.
        path: File path to fetch.
    """

    offset: int
    path: bytes

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on bad fields."""

        return (
            bytes([MsgType.GET_REQ])
            + _u32_le(_check_u32(self.offset, "offset"))
            + _encode_path(self.path)
        )


@dataclass(frozen=True)
class FileInfo:
    """FILE_INFO body: accepted GET, download starting.

    Attributes:
        size: Total file size in bytes.
    """

    size: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a bad size."""

        return bytes([MsgType.FILE_INFO]) + _u32_le(_check_u32(self.size, "size"))


@dataclass(frozen=True)
class FileData:
    """FILE_DATA body: one chunk of raw file bytes (either direction).

    Attributes:
        data: Raw file bytes; full chunks carry max_payload - 1 bytes.
    """

    data: bytes

    def encode(self) -> bytes:
        """Encode msg_type and body."""

        return bytes([MsgType.FILE_DATA]) + self.data


@dataclass(frozen=True)
class FileEnd:
    """FILE_END body: file stream finished (either direction).

    Attributes:
        crc32: CRC32 over the whole file.
    """

    crc32: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a bad CRC."""

        return bytes([MsgType.FILE_END]) + _u32_le(_check_u32(self.crc32, "crc32"))


@dataclass(frozen=True)
class GetDone:
    """GET_DONE body: download verification result.

    Attributes:
        status: 0 after a committed verify, otherwise an ErrCode value.
    """

    status: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a bad status."""

        return bytes([MsgType.GET_DONE, _check_done_status(self.status)])


@dataclass(frozen=True)
class PutReq:
    """PUT_REQ body: request a file upload.

    Attributes:
        size: Total file size in bytes.
        crc32: Whole-file CRC32, repeated by the closing FILE_END.
        path: Destination path.
    """

    size: int
    crc32: int
    path: bytes

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on bad fields."""

        return (
            bytes([MsgType.PUT_REQ])
            + _u32_le(_check_u32(self.size, "size"))
            + _u32_le(_check_u32(self.crc32, "crc32"))
            + _encode_path(self.path)
        )


@dataclass(frozen=True)
class PutOk:
    """PUT_OK body: upload accepted, stream may start."""

    def encode(self) -> bytes:
        """Encode msg_type; the body is empty."""

        return bytes([MsgType.PUT_OK])


@dataclass(frozen=True)
class PutDone:
    """PUT_DONE body: upload verification result.

    Attributes:
        status: 0 after a committed rename, otherwise an ErrCode value.
    """

    status: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a bad status."""

        return bytes([MsgType.PUT_DONE, _check_done_status(self.status)])


@dataclass(frozen=True)
class DelFile:
    """DEL_FILE body: delete one file.

    Attributes:
        path: File path to remove.
    """

    path: bytes

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a long path."""

        return bytes([MsgType.DEL_FILE]) + _encode_path(self.path)


@dataclass(frozen=True)
class DelDir:
    """DEL_DIR body: delete one directory tree recursively.

    Attributes:
        path: Directory path to remove.
    """

    path: bytes

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a long path."""

        return bytes([MsgType.DEL_DIR]) + _encode_path(self.path)


@dataclass(frozen=True)
class DelOk:
    """DEL_OK body: delete completed."""

    def encode(self) -> bytes:
        """Encode msg_type; the body is empty."""

        return bytes([MsgType.DEL_OK])


@dataclass(frozen=True)
class Plan:
    """PLAN body: informative batch totals; no reply.

    Attributes:
        nfiles: Number of files the controller intends to transfer.
        nbytes: Total bytes the controller intends to transfer.
    """

    nfiles: int
    nbytes: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on bad fields."""

        return (
            bytes([MsgType.PLAN])
            + _check_u16(self.nfiles, "nfiles").to_bytes(2, "little")
            + _u32_le(_check_u32(self.nbytes, "nbytes"))
        )


@dataclass(frozen=True)
class Notify:
    """NOTIFY body: the responder asks the controller to pull files.

    Informative for the controller's sync policy; no reply is sent and
    no operation slot is held.

    Attributes:
        flags: NOTIFY_* bits describing the requested sync. Bit 0 is the
            sync mode: 0 = full sync, 1 = incremental sync.
    """

    flags: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on bad flags."""

        if self.flags & ~_NOTIFY_DEFINED_MASK:
            raise MessageError("undefined NOTIFY flag bits must be 0")
        return bytes([MsgType.NOTIFY]) + _u32_le(self.flags)


@dataclass(frozen=True)
class Ping:
    """PING body: keepalive probe.

    Attributes:
        token: Opaque value echoed by the PONG.
    """

    token: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a bad token."""

        return bytes([MsgType.PING]) + _u32_le(_check_u32(self.token, "token"))


@dataclass(frozen=True)
class Pong:
    """PONG body: keepalive answer.

    Attributes:
        token: Token copied from the PING.
    """

    token: int

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on a bad token."""

        return bytes([MsgType.PONG]) + _u32_le(_check_u32(self.token, "token"))


@dataclass(frozen=True)
class Err:
    """ERR body: the referenced operation failed; the session lives.

    Attributes:
        code: Error code.
        ref_msgtype: msg_type of the message that failed.
        detail: Implementation-defined detail value.
    """

    code: ErrCode
    ref_msgtype: int
    detail: int = 0

    def encode(self) -> bytes:
        """Encode msg_type and body; raises MessageError on bad fields."""

        return bytes(
            [MsgType.ERR, self.code, _check_u8(self.ref_msgtype, "ref_msgtype")]
        ) + _check_u16(self.detail, "detail").to_bytes(2, "little")


@dataclass(frozen=True)
class Unknown:
    """A structurally intact message of a type this version does not know.

    Received between operations it is answered with ERR(E_UNSUPPORTED)
    for forward compatibility; it cannot be encoded.

    Attributes:
        msg_type: The undefined msg_type byte.
        body: The raw body bytes.
    """

    msg_type: int
    body: bytes


# Message union produced by decode_message().
Message = Union[
    ListReq,
    ListEntry,
    ListEnd,
    GetReq,
    FileInfo,
    FileData,
    FileEnd,
    GetDone,
    PutReq,
    PutOk,
    PutDone,
    DelFile,
    DelDir,
    DelOk,
    Plan,
    Notify,
    Ping,
    Pong,
    Err,
    Unknown,
]


_MSG_TYPE_BY_CLASS: Final[dict[type, MsgType]] = {
    ListReq: MsgType.LIST_REQ,
    ListEntry: MsgType.LIST_ENTRY,
    ListEnd: MsgType.LIST_END,
    GetReq: MsgType.GET_REQ,
    FileInfo: MsgType.FILE_INFO,
    FileData: MsgType.FILE_DATA,
    FileEnd: MsgType.FILE_END,
    GetDone: MsgType.GET_DONE,
    PutReq: MsgType.PUT_REQ,
    PutOk: MsgType.PUT_OK,
    PutDone: MsgType.PUT_DONE,
    DelFile: MsgType.DEL_FILE,
    DelDir: MsgType.DEL_DIR,
    DelOk: MsgType.DEL_OK,
    Plan: MsgType.PLAN,
    Notify: MsgType.NOTIFY,
    Ping: MsgType.PING,
    Pong: MsgType.PONG,
    Err: MsgType.ERR,
}


def msg_type_of(message: Message) -> int:
    """Wire msg_type byte of a decoded or built message.

    Args:
        message: Any Message union member.

    Returns:
        The msg_type byte, including the original byte for Unknown.
    """

    if isinstance(message, Unknown):
        return message.msg_type
    return _MSG_TYPE_BY_CLASS[type(message)]


def _decode_err_code(byte: int) -> ErrCode:
    """Map a wire error code byte to an ErrCode.

    Raises:
        MessageError: If the byte is not a defined code.
    """

    try:
        return ErrCode(byte)
    except ValueError:
        raise MessageError(f"undefined error code 0x{byte:02x}") from None


def _check_done_status(status: int) -> int:
    """Validate a GET_DONE/PUT_DONE status value.

    Raises:
        MessageError: If the status is neither 0 nor a defined ERR code.
    """

    if status != 0:
        _decode_err_code(status)
    return status


def decode_message(payload: bytes) -> Message:
    """Decode one DATA frame payload into a typed message.

    Args:
        payload: Complete frame payload: msg_type byte plus body.

    Returns:
        The decoded message, or Unknown for a msg_type this protocol
        version does not define.

    Raises:
        MessageError: If the payload is empty or a known-type body is
            structurally malformed (short, oversized prefix, trailing
            bytes, or reserved bits set).
    """

    if len(payload) == 0:
        raise MessageError("empty message payload")
    msg_type = payload[0]
    reader = _Reader(payload[1:])

    message: Message
    if msg_type == MsgType.LIST_REQ:
        flags = reader.u8()
        if flags & ~0x01:
            raise MessageError("reserved LIST_REQ flag bits must be 0")
        message = ListReq(want_crc=bool(flags & 0x01), root=reader.path())
    elif msg_type == MsgType.LIST_ENTRY:
        etype = reader.u8()
        eflags = reader.u8()
        if eflags & ~0x01:
            raise MessageError("reserved LIST_ENTRY eflags bits must be 0")
        message = ListEntry(
            etype=etype,
            crc_valid=bool(eflags & 0x01),
            size=reader.u32(),
            crc32=reader.u32(),
            mtime=reader.u32(),
            path=reader.path(),
        )
    elif msg_type == MsgType.LIST_END:
        message = ListEnd(count=reader.u16())
    elif msg_type == MsgType.GET_REQ:
        message = GetReq(offset=reader.u32(), path=reader.path())
    elif msg_type == MsgType.FILE_INFO:
        message = FileInfo(size=reader.u32())
    elif msg_type == MsgType.FILE_DATA:
        message = FileData(data=reader.rest())
    elif msg_type == MsgType.FILE_END:
        message = FileEnd(crc32=reader.u32())
    elif msg_type == MsgType.GET_DONE:
        message = GetDone(status=_check_done_status(reader.u8()))
    elif msg_type == MsgType.PUT_REQ:
        message = PutReq(size=reader.u32(), crc32=reader.u32(), path=reader.path())
    elif msg_type == MsgType.PUT_OK:
        message = PutOk()
    elif msg_type == MsgType.PUT_DONE:
        message = PutDone(status=_check_done_status(reader.u8()))
    elif msg_type == MsgType.DEL_FILE:
        message = DelFile(path=reader.path())
    elif msg_type == MsgType.DEL_DIR:
        message = DelDir(path=reader.path())
    elif msg_type == MsgType.DEL_OK:
        message = DelOk()
    elif msg_type == MsgType.PLAN:
        message = Plan(nfiles=reader.u16(), nbytes=reader.u32())
    elif msg_type == MsgType.NOTIFY:
        # Lenient receive: mask undefined bits, ignore appended future
        # fields (spec 5.4). A body shorter than 4 bytes still raises.
        message = Notify(flags=reader.u32() & _NOTIFY_DEFINED_MASK)
        reader.rest()
    elif msg_type == MsgType.PING:
        message = Ping(token=reader.u32())
    elif msg_type == MsgType.PONG:
        message = Pong(token=reader.u32())
    elif msg_type == MsgType.ERR:
        message = Err(
            code=_decode_err_code(reader.u8()),
            ref_msgtype=reader.u8(),
            detail=reader.u16(),
        )
    else:
        return Unknown(msg_type=msg_type, body=payload[1:])

    reader.finish()
    return message
