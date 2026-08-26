# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Adaptive RTO estimator tests for SPEC.md section 4.4."""

from __future__ import annotations

import json
from itertools import groupby
from pathlib import Path

from rqft.rto import RTO_INITIAL_MS, RTO_MAX_MS, RTO_MIN_MS, RtoEstimator


ROOT = Path(__file__).resolve().parents[2]


def _vectors() -> list[dict[str, object]]:
    vectors: list[dict[str, object]] = json.loads(
        (ROOT / "testvectors" / "rto.json").read_text()
    )
    return vectors


def test_initial_state_before_any_sample() -> None:
    estimator = RtoEstimator()

    assert estimator.srtt_ms == -1
    assert estimator.rttvar_ms == 0
    assert estimator.rto_ms == RTO_INITIAL_MS == 1000


def test_constants() -> None:
    assert RTO_MIN_MS == 100
    assert RTO_MAX_MS == 3000


def test_golden_vectors() -> None:
    cases = 0
    for _, steps in groupby(_vectors(), key=lambda entry: entry["case"]):
        estimator = RtoEstimator()
        for step in steps:
            estimator.sample(int(str(step["rtt"])))
            assert estimator.srtt_ms == step["srtt"], step
            assert estimator.rttvar_ms == step["rttvar"], step
            assert estimator.rto_ms == step["rto"], step
        cases += 1
    assert cases == 6
