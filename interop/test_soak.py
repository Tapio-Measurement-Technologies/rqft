# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Manually run seeded randomized SyncClient soak."""

from __future__ import annotations

import os
import random
import time
from pathlib import Path
from typing import Callable

import pytest

from fault_shim import FaultProfile, FaultShim
from harness import CPeer, CPeerTransport
from rqft.client import SyncClient


def _fixed_sid(value: int) -> Callable[[], int]:
    """Return a sid source that always yields value."""

    def source() -> int:
        return value

    return source


pytestmark = pytest.mark.skipif(
    os.environ.get("RQFT_RUN_SOAK") != "1",
    reason="set RQFT_RUN_SOAK=1 to run the manual soak",
)


def _blob(rng: random.Random, size: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(size))


def _file_args(files: dict[str, bytes]) -> list[str]:
    args: list[str] = []
    for path, data in sorted(files.items()):
        args += ["--file", f"{path}=hex:{data.hex()}"]
    return args


def _write(root: Path, path: str, data: bytes) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _profile(rng: random.Random) -> FaultProfile:
    choice = rng.randrange(6)
    if choice == 0:
        return FaultProfile()
    if choice == 1:
        return FaultProfile(rechunk=1)
    if choice == 2:
        return FaultProfile(duplicate_ack_permille=500)
    if choice == 3:
        return FaultProfile(
            inject_ascii=b"STATUS?\r\nLOG: soak\r\n",
            inject_at=rng.randrange(512, 4096),
        )
    if choice == 4:
        return FaultProfile(
            burst_len=rng.choice([16, 32, 64]),
            burst_at=rng.randrange(800, 2400),
        )
    return FaultProfile(
        inject_ascii=_blob(rng, rng.randrange(32, 128)),
        inject_at=rng.randrange(512, 4096),
    )


def test_sync_client_seeded_randomized_soak(tmp_path: Path) -> None:
    """Run randomized SyncClient batches against c_peer for the configured duration."""

    seed = int(os.environ.get("RQFT_SOAK_SEED", "0xD18"), 0)
    duration_s = float(os.environ.get("RQFT_SOAK_SECONDS", "600"))
    rng = random.Random(seed)
    deadline = time.monotonic() + duration_s
    cases = 0

    while cases == 0 or time.monotonic() < deadline:
        case_root = tmp_path / f"case-{cases:04}"
        case_rng = random.Random(rng.randrange(1 << 30))
        count = case_rng.randrange(1, 8)
        remote = {
            f"set{cases:04}/file{index:02}.bin": _blob(
                case_rng, case_rng.randrange(0, 3072)
            )
            for index in range(count)
        }
        matching = set(case_rng.sample(sorted(remote), case_rng.randrange(0, count + 1)))
        for path in matching:
            _write(case_root, path, remote[path])

        delete_remote = case_rng.randrange(4) == 0
        peer = CPeer(
            [
                "--role",
                "responder",
                "--seed",
                str(0xD18000 + cases),
            ]
            + _file_args(remote)
        )
        try:
            transport = CPeerTransport(
                peer,
                py_to_c=FaultShim(0xD18100 + cases, _profile(case_rng)),
                c_to_py=FaultShim(0xD18200 + cases, _profile(case_rng)),
            )
            sid = 1 + ((cases * 37) % 255)
            client = SyncClient(
                transport,
                case_root,
                sid_source=_fixed_sid(sid),
                io_timeout_s=0.002,
            )

            result = client.sync_from_peer(delete_remote=delete_remote, timeout_s=90.0)
            peer.assert_clean_exit()

            for path, data in remote.items():
                assert (case_root / path).read_bytes() == data
            assert {entry.path for entry in result.remote} == set(remote)
            assert {entry.path for entry in result.skipped} == matching
            if delete_remote:
                for entry in result.fetched:
                    assert peer.file_hex(entry.path) is None
        finally:
            peer.kill()
        cases += 1
