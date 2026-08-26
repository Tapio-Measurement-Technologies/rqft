# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Lossy in-process loopback tests for SPEC.md sections 3 and 4.

Two link endpoints are connected through a deterministic seeded fault
shim (drop, duplicate, corrupt, burst loss) in both directions; every
profile must still deliver 100 frames exactly once, in order.
"""

from __future__ import annotations

import random

import pytest

from rqft.frame import Frame, Parser
from rqft.link import Aborted, Delivered, Link

SID = 0x42
FRAME_COUNT = 100
STEP_MS = 5
DEADLINE_MS = 600_000


class FaultShim:
    """Deterministic byte-level fault injector for one direction.

    Args:
        seed: PRNG seed; equal seeds give byte-identical fault patterns.
        drop_permille: Per-byte probability (in 1/1000) of losing the byte.
        dup_permille: Per-byte probability (in 1/1000) of emitting it twice.
        corrupt_permille: Per-byte probability (in 1/1000) of flipping bits.
        burst_len: Contiguous bytes lost in each burst; 0 disables bursts.
        burst_every: Input-byte interval that triggers a burst.
    """

    def __init__(
        self,
        seed: int,
        drop_permille: int = 0,
        dup_permille: int = 0,
        corrupt_permille: int = 0,
        burst_len: int = 0,
        burst_every: int = 0,
    ) -> None:
        self._rng = random.Random(seed)
        self._drop = drop_permille
        self._dup = dup_permille
        self._corrupt = corrupt_permille
        self._burst_len = burst_len
        self._burst_every = burst_every
        self._seen = 0
        self._burst_remaining = 0

    def feed(self, data: bytes) -> bytes:
        """Pass bytes through the fault model, returning the survivors."""

        out = bytearray()
        for byte in data:
            self._seen += 1
            if self._burst_every and self._seen % self._burst_every == 0:
                self._burst_remaining = self._burst_len
            if self._burst_remaining > 0:
                self._burst_remaining -= 1
                continue
            if self._rng.randrange(1000) < self._drop:
                continue
            if self._rng.randrange(1000) < self._corrupt:
                byte ^= self._rng.randrange(1, 256)
            out.append(byte)
            if self._rng.randrange(1000) < self._dup:
                out.append(byte)
        return bytes(out)


class Endpoint:
    """One side of the loopback: frame parser + link + outbox."""

    def __init__(self) -> None:
        self.outbox = bytearray()
        self.parser = Parser()
        self.link = Link(sid=SID, window=4, transmit=self.outbox.extend)
        self.delivered: list[bytes] = []
        self.aborted: list[Aborted] = []

    def receive(self, data: bytes, now_ms: int) -> None:
        """Feed transport bytes through the parser into the link."""

        for event in self.parser.feed(data, now_ms):
            if isinstance(event, Frame):
                for link_event in self.link.on_frame(event, now_ms):
                    if isinstance(link_event, Delivered):
                        self.delivered.append(link_event.payload)
                    else:
                        self.aborted.append(link_event)


def make_payload(index: int) -> bytes:
    """A distinct payload containing 0x00 and the frame index."""

    return bytes([index & 0xFF, 0x00, 0xFF]) + b"payload-%03d" % index


def run_transfer(shim_ab: FaultShim, shim_ba: FaultShim) -> None:
    """Push 100 frames A->B through the fault shims until delivered."""

    a = Endpoint()
    b = Endpoint()
    payloads = [make_payload(i) for i in range(FRAME_COUNT)]
    sent = 0
    now = 0

    while len(b.delivered) < FRAME_COUNT:
        assert now < DEADLINE_MS, f"stalled at {len(b.delivered)} deliveries"
        assert not a.aborted and not b.aborted, "link died under fault profile"
        now += STEP_MS

        while sent < FRAME_COUNT and a.link.send(payloads[sent], now):
            sent += 1

        b.receive(shim_ab.feed(bytes(a.outbox)), now)
        a.outbox.clear()
        a.receive(shim_ba.feed(bytes(b.outbox)), now)
        b.outbox.clear()

        a.aborted.extend(event for event in a.link.poll(now) if isinstance(event, Aborted))
        b.aborted.extend(event for event in b.link.poll(now) if isinstance(event, Aborted))

    assert b.delivered == payloads


PROFILES = {
    "clean": {},
    "drop": {"drop_permille": 10},
    "duplicate": {"dup_permille": 20},
    "corrupt": {"corrupt_permille": 10},
    "burst": {"burst_len": 48, "burst_every": 1500},
    "mixed": {
        "drop_permille": 5,
        "dup_permille": 5,
        "corrupt_permille": 5,
        "burst_len": 32,
        "burst_every": 3000,
    },
}


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_exactly_once_in_order_delivery(profile: str) -> None:
    faults = PROFILES[profile]
    run_transfer(
        FaultShim(seed=0xC0FFEE, **faults),
        FaultShim(seed=0xBEEF, **faults),
    )


def test_bidirectional_streams_are_independent() -> None:
    """Both directions carry 100 frames at once over a lightly lossy line."""

    a = Endpoint()
    b = Endpoint()
    shim_ab = FaultShim(seed=1, drop_permille=5, corrupt_permille=5)
    shim_ba = FaultShim(seed=2, drop_permille=5, corrupt_permille=5)
    payloads_ab = [make_payload(i) for i in range(FRAME_COUNT)]
    payloads_ba = [make_payload(i + FRAME_COUNT) for i in range(FRAME_COUNT)]
    sent_ab = 0
    sent_ba = 0
    now = 0

    while len(b.delivered) < FRAME_COUNT or len(a.delivered) < FRAME_COUNT:
        assert now < DEADLINE_MS, "bidirectional transfer stalled"
        assert not a.aborted and not b.aborted
        now += STEP_MS

        while sent_ab < FRAME_COUNT and a.link.send(payloads_ab[sent_ab], now):
            sent_ab += 1
        while sent_ba < FRAME_COUNT and b.link.send(payloads_ba[sent_ba], now):
            sent_ba += 1

        b.receive(shim_ab.feed(bytes(a.outbox)), now)
        a.outbox.clear()
        a.receive(shim_ba.feed(bytes(b.outbox)), now)
        b.outbox.clear()

        a.link.poll(now)
        b.link.poll(now)

    assert b.delivered == payloads_ab
    assert a.delivered == payloads_ba
