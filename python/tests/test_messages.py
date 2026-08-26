# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Session body and message codec tests for SPEC.md sections 5.2 and 5.3."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rqft.messages import (
    DelDir,
    DelFile,
    DelOk,
    Err,
    ErrCode,
    FileData,
    FileEnd,
    FileInfo,
    GetDone,
    GetReq,
    Hello,
    HelloOk,
    ListEnd,
    ListEntry,
    ListReq,
    Message,
    MessageError,
    NOTIFY_DELETE_AFTER_SYNC,
    NOTIFY_SYNC_INCREMENTAL,
    Notify,
    Ping,
    Plan,
    Pong,
    PutDone,
    PutOk,
    PutReq,
    Role,
    Unknown,
    decode_message,
    path_valid,
)

VECTORS = json.loads(
    (Path(__file__).parent.parent.parent / "testvectors" / "messages.json").read_text()
)


def hello_vectors() -> list[dict[str, Any]]:
    return [vector for vector in VECTORS if vector["kind"] == "hello"]


def hello_ok_vectors() -> list[dict[str, Any]]:
    return [vector for vector in VECTORS if vector["kind"] == "hello_ok"]


@pytest.mark.parametrize("vector", hello_vectors(), ids=lambda v: str(v["name"]))
def test_hello_golden_roundtrip(vector: dict[str, Any]) -> None:
    hello = Hello(
        ver_min=vector["ver_min"],
        ver_max=vector["ver_max"],
        role=Role(vector["role"]),
        max_payload=vector["max_payload"],
        window=vector["window"],
        caps=vector["caps"],
    )
    encoded = bytes.fromhex(vector["encoded_hex"])
    assert hello.encode() == encoded
    assert Hello.decode(encoded) == hello


@pytest.mark.parametrize("vector", hello_ok_vectors(), ids=lambda v: str(v["name"]))
def test_hello_ok_golden_roundtrip(vector: dict[str, Any]) -> None:
    ok = HelloOk(
        ver=vector["ver"],
        role=Role(vector["role"]),
        max_payload=vector["max_payload"],
        window=vector["window"],
        caps=vector["caps"],
    )
    encoded = bytes.fromhex(vector["encoded_hex"])
    assert ok.encode() == encoded
    assert HelloOk.decode(encoded) == ok


def valid_hello_bytes() -> bytearray:
    return bytearray(Hello(1, 1, Role.RESPONDER, 512, 4, 1).encode())


def valid_hello_ok_bytes() -> bytearray:
    return bytearray(HelloOk(1, Role.CONTROLLER, 512, 4, 0).encode())


def test_hello_decode_rejects_bad_length() -> None:
    with pytest.raises(MessageError):
        Hello.decode(bytes(valid_hello_bytes())[:7])
    with pytest.raises(MessageError):
        Hello.decode(bytes(valid_hello_bytes()) + b"\x00")


def test_hello_decode_rejects_reserved_byte() -> None:
    data = valid_hello_bytes()
    data[7] = 1
    with pytest.raises(MessageError):
        Hello.decode(bytes(data))


def test_hello_decode_rejects_undefined_role() -> None:
    data = valid_hello_bytes()
    data[2] = 2
    with pytest.raises(MessageError):
        Hello.decode(bytes(data))


def test_hello_decode_rejects_inverted_version_range() -> None:
    data = valid_hello_bytes()
    data[0] = 3
    data[1] = 2
    with pytest.raises(MessageError):
        Hello.decode(bytes(data))


@pytest.mark.parametrize("max_payload", [0, 513])
def test_hello_decode_rejects_max_payload_range(max_payload: int) -> None:
    data = valid_hello_bytes()
    data[3:5] = max_payload.to_bytes(2, "little")
    with pytest.raises(MessageError):
        Hello.decode(bytes(data))


@pytest.mark.parametrize("window", [0, 9])
def test_hello_decode_rejects_window_range(window: int) -> None:
    data = valid_hello_bytes()
    data[5] = window
    with pytest.raises(MessageError):
        Hello.decode(bytes(data))


def test_hello_decode_rejects_reserved_caps_bits() -> None:
    data = valid_hello_bytes()
    data[6] = 0x02
    with pytest.raises(MessageError):
        Hello.decode(bytes(data))


def test_hello_ok_decode_rejects_reserved_bytes() -> None:
    for index in (6, 7):
        data = valid_hello_ok_bytes()
        data[index] = 1
        with pytest.raises(MessageError):
            HelloOk.decode(bytes(data))


def test_hello_ok_decode_rejects_bad_length() -> None:
    with pytest.raises(MessageError):
        HelloOk.decode(bytes(valid_hello_ok_bytes())[:7])


def test_hello_ok_decode_rejects_undefined_role() -> None:
    data = valid_hello_ok_bytes()
    data[1] = 0xFF
    with pytest.raises(MessageError):
        HelloOk.decode(bytes(data))


def test_encode_rejects_out_of_range_fields() -> None:
    with pytest.raises(MessageError):
        Hello(1, 1, Role.CONTROLLER, 0, 4, 0).encode()
    with pytest.raises(MessageError):
        Hello(2, 1, Role.CONTROLLER, 512, 4, 0).encode()
    with pytest.raises(MessageError):
        HelloOk(1, Role.CONTROLLER, 512, 9, 0).encode()
    with pytest.raises(MessageError):
        HelloOk(1, Role.CONTROLLER, 512, 4, 0x80).encode()


def vector_message(vector: dict[str, Any]) -> Message:
    """Build the typed message a testvector line describes."""

    kind = vector["kind"]
    if kind == "list_req":
        return ListReq(bool(vector["want_crc"]), bytes.fromhex(vector["root_hex"]))
    if kind == "list_entry":
        return ListEntry(
            vector["etype"],
            bool(vector["crc_valid"]),
            vector["size"],
            vector["crc32"],
            vector["mtime"],
            bytes.fromhex(vector["path_hex"]),
        )
    if kind == "list_end":
        return ListEnd(vector["count"])
    if kind == "get_req":
        return GetReq(vector["offset"], bytes.fromhex(vector["path_hex"]))
    if kind == "file_info":
        return FileInfo(vector["size"])
    if kind == "file_data":
        return FileData(bytes.fromhex(vector["data_hex"]))
    if kind == "file_end":
        return FileEnd(vector["crc32"])
    if kind == "get_done":
        return GetDone(vector["status"])
    if kind == "put_req":
        return PutReq(vector["size"], vector["crc32"], bytes.fromhex(vector["path_hex"]))
    if kind == "put_ok":
        return PutOk()
    if kind == "put_done":
        return PutDone(vector["status"])
    if kind == "del_file":
        return DelFile(bytes.fromhex(vector["path_hex"]))
    if kind == "del_dir":
        return DelDir(bytes.fromhex(vector["path_hex"]))
    if kind == "del_ok":
        return DelOk()
    if kind == "plan":
        return Plan(vector["nfiles"], vector["nbytes"])
    if kind == "notify":
        return Notify(vector["flags"])
    if kind == "ping":
        return Ping(vector["token"])
    if kind == "pong":
        return Pong(vector["token"])
    assert kind == "err"
    return Err(ErrCode(vector["code"]), vector["ref_msgtype"], vector["detail"])


def message_vectors() -> list[dict[str, Any]]:
    return [vector for vector in VECTORS if vector["kind"] not in ("hello", "hello_ok")]


@pytest.mark.parametrize(
    "vector", message_vectors(), ids=lambda v: f"{v['kind']}_{v['name']}"
)
def test_message_golden_roundtrip(vector: dict[str, Any]) -> None:
    message = vector_message(vector)
    assert not isinstance(message, Unknown)
    encoded = bytes.fromhex(vector["encoded_hex"])
    assert message.encode() == encoded
    assert decode_message(encoded) == message


def test_unknown_msg_type_decodes_as_unknown() -> None:
    assert decode_message(b"\x60\x01\x02") == Unknown(0x60, b"\x01\x02")
    assert decode_message(b"\x00") == Unknown(0x00, b"")


def test_decode_rejects_structural_violations() -> None:
    with pytest.raises(MessageError):
        decode_message(b"")
    with pytest.raises(MessageError):
        decode_message(bytes([0x12, 0x03]))  # LIST_END with a short count
    with pytest.raises(MessageError):
        decode_message(bytes([0x10, 0x01, 0x05]) + b"ab")  # path prefix overruns body
    with pytest.raises(MessageError):
        decode_message(bytes([0x10, 0x01, 0x81]) + b"x" * 0x81)  # path prefix > MAX_PATH
    with pytest.raises(MessageError):
        decode_message(bytes([0x10, 0x02, 0x00]))  # reserved LIST_REQ flag bit
    with pytest.raises(MessageError):
        decode_message(bytes([0x11, 0x00, 0x02]) + bytes(13))  # reserved eflags bit
    with pytest.raises(MessageError):
        decode_message(bytes([0x12, 0x03, 0x00, 0xFF]))  # trailing byte
    with pytest.raises(MessageError):
        decode_message(bytes([0x7F, 0x63, 0x20, 0x00, 0x00]))  # undefined error code
    with pytest.raises(MessageError):
        decode_message(bytes([0x2A, 0x63]))  # PUT_DONE status not 0 or an ERR code
    with pytest.raises(MessageError):
        decode_message(bytes([0x24, 0x63]))  # GET_DONE status not 0 or an ERR code


def test_encode_rejects_long_path() -> None:
    with pytest.raises(MessageError):
        DelFile(b"a" * 129).encode()


def test_encode_rejects_undefined_put_status() -> None:
    with pytest.raises(MessageError):
        PutDone(0x63).encode()


def test_encode_rejects_undefined_get_status() -> None:
    with pytest.raises(MessageError):
        GetDone(0x63).encode()


def test_notify_encode_rejects_undefined_flags() -> None:
    # Senders must zero undefined NOTIFY flag bits (spec 5.4).
    for flags in (0x04, 1 << 31):
        with pytest.raises(MessageError):
            Notify(flags).encode()
    assert Notify(NOTIFY_SYNC_INCREMENTAL | NOTIFY_DELETE_AFTER_SYNC).encode() == (
        b"\x41\x03\x00\x00\x00"
    )


def test_notify_decode_masks_unknown_flags() -> None:
    assert decode_message(b"\x41\x07\x00\x00\x00") == Notify(
        NOTIFY_SYNC_INCREMENTAL | NOTIFY_DELETE_AFTER_SYNC
    )


def test_notify_decode_tolerates_longer_body() -> None:
    # Future fields append after flags; receivers ignore them.
    assert decode_message(b"\x41\x01\x00\x00\x00\xff\xff") == Notify(
        NOTIFY_SYNC_INCREMENTAL
    )


def test_notify_decode_rejects_short_body() -> None:
    with pytest.raises(MessageError):
        decode_message(b"\x41\x01\x00")


def test_path_valid_accepts_spec_paths() -> None:
    assert path_valid(b"a.data")
    assert path_valid(b"logs/2025/run1.data")
    assert path_valid("määräys.txt".encode())
    assert path_valid(b"a" * 128)
    assert path_valid(b"", allow_empty=True)


@pytest.mark.parametrize(
    "path",
    [
        b"",
        b"a" * 129,
        b"/etc/passwd",
        b"a//b",
        b"a/",
        b"./a",
        b"a/./b",
        b"../a",
        b"a/../b",
        b"a\\b",
        b"a\x00b",
        b"\xff\xfe",
    ],
    ids=repr,
)
def test_path_valid_rejects_violations(path: bytes) -> None:
    assert not path_valid(path)
