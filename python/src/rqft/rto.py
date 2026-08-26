# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Adaptive retransmission-timeout estimator for SPEC.md section 4.4.

A simplified RFC 6298 estimator over three integers, using shift
arithmetic that is byte-exact with the C implementation. Round-trip
samples come only from frames that were never retransmitted (Karn's
rule, enforced by the caller).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# Retransmission timeout floor in milliseconds.
RTO_MIN_MS: Final = 100

# Retransmission timeout ceiling in milliseconds.
RTO_MAX_MS: Final = 3000

# Retransmission timeout before any round-trip sample.
RTO_INITIAL_MS: Final = 1000


@dataclass
class RtoEstimator:
    """Retransmission-timeout state over integer millisecond arithmetic.

    Attributes:
        srtt_ms: Smoothed round-trip time; -1 before any sample.
        rttvar_ms: Round-trip time variance; 0 before any sample.
        rto_ms: Current timeout, RTO_INITIAL_MS before any sample and
            clamped to [RTO_MIN_MS, RTO_MAX_MS] afterwards.
    """

    srtt_ms: int = -1
    rttvar_ms: int = 0
    rto_ms: int = RTO_INITIAL_MS

    def sample(self, rtt_ms: int) -> None:
        """Integrate one round-trip measurement.

        Args:
            rtt_ms: Time from a frame's first transmission to the ACK
                covering it. Values above RTO_MAX_MS are clamped before
                integration to keep the arithmetic bounded.
        """

        rtt = min(rtt_ms, RTO_MAX_MS)
        if self.srtt_ms < 0:
            self.srtt_ms = rtt
            self.rttvar_ms = rtt >> 1
        else:
            self.rttvar_ms = (3 * self.rttvar_ms + abs(self.srtt_ms - rtt)) >> 2
            self.srtt_ms = (7 * self.srtt_ms + rtt) >> 3
        self.rto_ms = max(RTO_MIN_MS, min(self.srtt_ms + 4 * self.rttvar_ms, RTO_MAX_MS))
