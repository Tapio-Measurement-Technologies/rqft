# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""CRC-32/ISO-HDLC codec for SPEC.md section 3.2."""

from __future__ import annotations

import zlib


def crc32_update(crc: int, data: bytes) -> int:
    """Continue a CRC-32/ISO-HDLC calculation.

    Args:
        crc: Previous finalized CRC value, or 0 for a new stream.
        data: Bytes to add.

    Returns:
        Updated finalized CRC value, matching ``zlib.crc32`` convention.
    """

    return zlib.crc32(data, crc) & 0xFFFFFFFF


def crc32(data: bytes) -> int:
    """Compute CRC-32/ISO-HDLC for one byte string.

    Args:
        data: Bytes to checksum.

    Returns:
        Finalized CRC value.
    """

    return crc32_update(0, data)
