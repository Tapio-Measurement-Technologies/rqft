# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Shared golden CRC32 vectors for SPEC.md section 3.2."""

from __future__ import annotations

import json
from pathlib import Path

from rqft.crc32 import crc32, crc32_update


ROOT = Path(__file__).resolve().parents[2]


def test_crc32_vectors() -> None:
    vectors = json.loads((ROOT / "testvectors" / "crc32.json").read_text())
    assert len(vectors) == 5

    for vector in vectors:
        data = bytes.fromhex(vector["input_hex"])
        expected = vector["crc32"]
        assert crc32(data) == expected

        split = min(len(data), 17)
        incremental = crc32_update(0, data[:split])
        incremental = crc32_update(incremental, data[split:])
        assert incremental == expected
