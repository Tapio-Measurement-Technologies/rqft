# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Deterministic byte-level fault shim for interop transports.

The shim can drop, duplicate, corrupt, burst-drop, rechunk, delay, and
inject ASCII chatter into one transport direction. Clean profiles are an
identity transform while preserving the knobs needed by the fault matrix.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from rqft.cobs import CobsError, decode as cobs_decode


@dataclass(frozen=True)
class FaultProfile:
    """Configuration for one deterministic transport direction."""

    drop_permille: int = 0
    dup_permille: int = 0
    corrupt_permille: int = 0
    duplicate_frame_permille: int = 0
    duplicate_ack_permille: int = 0
    burst_len: int = 0
    burst_at: int = 0
    burst_every: int = 0
    rechunk: int = 0
    delay_ticks: int = 0
    inject_ascii: bytes = b""
    inject_at: int = 0
    inject_every: int = 0


class FaultShim:
    """Apply one seeded :class:`FaultProfile` to byte chunks."""

    def __init__(self, seed: int, profile: FaultProfile | None = None) -> None:
        self._rng = random.Random(seed)
        self._profile = profile or FaultProfile()
        self._seen = 0
        self._tick = 0
        self._burst_remaining = 0
        self._burst_fired = False
        self._inject_fired = False
        self._delayed: list[tuple[int, bytes]] = []

    def feed(self, data: bytes) -> list[bytes]:
        """Transform input bytes and return chunks ready for delivery."""

        self._tick += 1
        transformed = bytearray()
        profile = self._profile
        for byte in data:
            self._seen += 1
            if (
                profile.inject_ascii
                and profile.inject_at > 0
                and not self._inject_fired
                and self._seen >= profile.inject_at
            ):
                transformed += profile.inject_ascii
                self._inject_fired = True
            if (
                profile.inject_ascii
                and profile.inject_every > 0
                and self._seen % profile.inject_every == 1
            ):
                transformed += profile.inject_ascii
            if (
                profile.burst_at > 0
                and not self._burst_fired
                and self._seen >= profile.burst_at
            ):
                self._burst_remaining = profile.burst_len
                self._burst_fired = True
            if profile.burst_every > 0 and self._seen % profile.burst_every == 0:
                self._burst_remaining = profile.burst_len
            if self._burst_remaining > 0:
                self._burst_remaining -= 1
                continue
            if self._rng.randrange(1000) < profile.drop_permille:
                continue
            if self._rng.randrange(1000) < profile.corrupt_permille:
                byte ^= self._rng.randrange(1, 256)
            transformed.append(byte)
            if self._rng.randrange(1000) < profile.dup_permille:
                transformed.append(byte)

        duplicated = self._duplicate_frames(bytes(transformed))
        chunks = self._rechunk(duplicated)
        if profile.delay_ticks <= 0:
            return chunks + self._drain_due()
        due = self._tick + profile.delay_ticks
        self._delayed.extend((due, chunk) for chunk in chunks)
        return self._drain_due()

    def flush(self) -> list[bytes]:
        """Return all delayed chunks regardless of due tick."""

        chunks = [chunk for _, chunk in self._delayed]
        self._delayed.clear()
        return chunks

    def _rechunk(self, data: bytes) -> list[bytes]:
        if not data:
            return []
        size = self._profile.rechunk
        if size <= 0 or len(data) <= size:
            return [data]
        return [data[index : index + size] for index in range(0, len(data), size)]

    def _duplicate_frames(self, data: bytes) -> bytes:
        if (
            not data
            or (
                self._profile.duplicate_frame_permille <= 0
                and self._profile.duplicate_ack_permille <= 0
            )
        ):
            return data

        out = bytearray()
        index = 0
        while index < len(data):
            if data[index] != 0:
                out.append(data[index])
                index += 1
                continue
            end = data.find(b"\x00", index + 1)
            if end < 0:
                out += data[index:]
                break
            frame = data[index : end + 1]
            out += frame
            if self._should_duplicate_frame(frame):
                out += frame
            index = end + 1
        return bytes(out)

    def _should_duplicate_frame(self, frame: bytes) -> bool:
        if len(frame) <= 2:
            return False
        duplicate = False
        if self._profile.duplicate_frame_permille > 0:
            duplicate = self._rng.randrange(1000) < self._profile.duplicate_frame_permille
        if self._profile.duplicate_ack_permille > 0 and self._is_ack_frame(frame):
            duplicate = duplicate or (
                self._rng.randrange(1000) < self._profile.duplicate_ack_permille
            )
        return duplicate

    def _is_ack_frame(self, frame: bytes) -> bool:
        try:
            decoded = cobs_decode(frame[1:-1])
        except CobsError:
            return False
        return len(decoded) >= 4 and decoded[0] == 0x04

    def _drain_due(self) -> list[bytes]:
        ready = [chunk for due, chunk in self._delayed if due <= self._tick]
        self._delayed = [(due, chunk) for due, chunk in self._delayed if due > self._tick]
        return ready
