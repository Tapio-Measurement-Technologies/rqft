# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Shared golden COBS vectors for SPEC.md section 3.1."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from rqft.cobs import CobsError, StreamingDecoder, decode, encode


ROOT = Path(__file__).resolve().parents[2]


def test_cobs_vectors() -> None:
    vectors = json.loads((ROOT / "testvectors" / "cobs.json").read_text())
    assert len(vectors) == 9

    for vector in vectors:
        decoded = bytes.fromhex(vector["decoded_hex"])
        encoded = bytes.fromhex(vector["encoded_hex"])
        assert encode(decoded) == encoded
        assert decode(encoded) == decoded

        streaming = StreamingDecoder()
        chunks = [streaming.feed(bytes([byte])) for byte in encoded]
        chunks.append(streaming.feed(b"", finish=True))
        assert b"".join(chunks) == decoded


@given(st.binary(min_size=0, max_size=520))
def test_cobs_round_trip(data: bytes) -> None:
    encoded = encode(data)
    assert len(encoded) <= 523
    assert b"\x00" not in encoded
    assert decode(encoded) == data


@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        b"\x00",
        b"\x02",
        b"\x03\x11",
        b"\x02\x00",
    ],
)
def test_cobs_rejects_malformed(encoded: bytes) -> None:
    with pytest.raises(CobsError):
        decode(encoded)

    streaming = StreamingDecoder()
    with pytest.raises(CobsError):
        streaming.feed(encoded, finish=True)
