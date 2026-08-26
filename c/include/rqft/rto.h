// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/** @file @brief Adaptive retransmission timeout estimator. */
#ifndef RQFT_RTO_H
#define RQFT_RTO_H

#include "rqft/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RQFT_RTO_MIN_MS 100
#define RQFT_RTO_INITIAL_MS 1000
#define RQFT_RTO_MAX_MS 3000

typedef struct rqft_rto {
    int32_t srtt_ms;
    int32_t rttvar_ms;
    uint32_t rto_ms;
} rqft_rto_t;

void rqft_rto_init(rqft_rto_t *rto);
void rqft_rto_sample(rqft_rto_t *rto, uint32_t rtt_ms);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_RTO_H */
