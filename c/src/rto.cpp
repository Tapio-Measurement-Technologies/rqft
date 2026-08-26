// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Adaptive retransmission-timeout estimator for SPEC.md section 4.4.
 */
#include "rqft/rto.h"

namespace {

int32_t clamp_rto(int32_t value)
{
    if (value < RQFT_RTO_MIN_MS) {
        return RQFT_RTO_MIN_MS;
    }
    if (value > RQFT_RTO_MAX_MS) {
        return RQFT_RTO_MAX_MS;
    }
    return value;
}

} // namespace

void rqft_rto_init(rqft_rto_t *rto)
{
    rto->srtt_ms = -1;
    rto->rttvar_ms = 0;
    rto->rto_ms = RQFT_RTO_INITIAL_MS;
}

void rqft_rto_sample(rqft_rto_t *rto, uint32_t rtt_ms)
{
    int32_t rtt = rtt_ms > RQFT_RTO_MAX_MS ? RQFT_RTO_MAX_MS : static_cast<int32_t>(rtt_ms);
    if (rto->srtt_ms < 0) {
        rto->srtt_ms = rtt;
        rto->rttvar_ms = rtt >> 1;
    } else {
        int32_t delta = rto->srtt_ms > rtt ? rto->srtt_ms - rtt : rtt - rto->srtt_ms;
        rto->rttvar_ms = (3 * rto->rttvar_ms + delta) >> 2;
        rto->srtt_ms = (7 * rto->srtt_ms + rtt) >> 3;
    }
    rto->rto_ms = static_cast<uint32_t>(clamp_rto(rto->srtt_ms + 4 * rto->rttvar_ms));
}
