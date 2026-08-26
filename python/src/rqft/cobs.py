# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""COBS codec for SPEC.md section 3.1."""

from __future__ import annotations

from dataclasses import dataclass


class CobsError(ValueError):
    """Raised when encoded COBS bytes are malformed."""


def encode(decoded: bytes) -> bytes:
    """Encode decoded bytes with RQFT's COBS profile.

    Args:
        decoded: Unframed decoded bytes.

    Returns:
        COBS body bytes containing no zero bytes.
    """

    out = bytearray([0])
    code_pos = 0
    code = 1
    open_code = True

    for index, byte in enumerate(decoded):
        if byte == 0:
            out[code_pos] = code
            code_pos = len(out)
            out.append(0)
            code = 1
            open_code = True
            continue

        out.append(byte)
        code += 1
        if code == 0xFF:
            out[code_pos] = code
            code = 1
            if index + 1 < len(decoded):
                code_pos = len(out)
                out.append(0)
                open_code = True
            else:
                open_code = False

    if open_code:
        out[code_pos] = code
    return bytes(out)


def decode(encoded: bytes) -> bytes:
    """Decode a complete COBS body.

    Args:
        encoded: COBS body bytes without frame delimiters.

    Returns:
        Decoded bytes.

    Raises:
        CobsError: If the body is empty, contains zero bytes, or a code byte
            overruns the input.
    """

    if not encoded:
        raise CobsError("empty COBS body")

    out = bytearray()
    pos = 0
    while pos < len(encoded):
        code = encoded[pos]
        pos += 1
        if code == 0:
            raise CobsError("zero code byte")

        block_len = code - 1
        end = pos + block_len
        if end > len(encoded):
            raise CobsError("code byte overruns input")

        block = encoded[pos:end]
        if 0 in block:
            raise CobsError("zero byte inside encoded block")
        out.extend(block)
        pos = end

        if code != 0xFF and pos < len(encoded):
            out.append(0)

    return bytes(out)


@dataclass
class StreamingDecoder:
    """O(1)-state COBS decoder for parser integration.

    Attributes:
        remaining: Encoded data bytes left in the current block.
        needs_zero: Whether the next block boundary emits an implicit zero.
        started: Whether at least one code byte has been consumed.
        failed: Whether the decoder must be reinitialized before reuse.
    """

    remaining: int = 0
    needs_zero: bool = False
    started: bool = False
    failed: bool = False

    def feed(self, encoded: bytes, *, finish: bool = False) -> bytes:
        """Decode the next encoded chunk.

        Args:
            encoded: Next COBS body bytes.
            finish: True when this is the final chunk.

        Returns:
            Newly decoded bytes. The final implicit zero is omitted when
            finish is true.

        Raises:
            CobsError: If the stream is malformed or this decoder already
                failed.
        """

        if self.failed:
            raise CobsError("decoder already failed")

        out = bytearray()
        pos = 0
        while pos < len(encoded):
            if self.remaining == 0:
                if self.needs_zero:
                    out.append(0)
                    self.needs_zero = False

                code = encoded[pos]
                pos += 1
                if code == 0:
                    self.failed = True
                    raise CobsError("zero code byte")
                self.started = True
                self.remaining = code - 1
                self.needs_zero = code != 0xFF
                continue

            byte = encoded[pos]
            pos += 1
            if byte == 0:
                self.failed = True
                raise CobsError("zero byte inside encoded block")
            out.append(byte)
            self.remaining -= 1

        if finish:
            if not self.started:
                self.failed = True
                raise CobsError("empty COBS body")
            if self.remaining != 0:
                self.failed = True
                raise CobsError("code byte overruns input")
            self.needs_zero = False

        return bytes(out)
