// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/** @file @brief Complete and streaming COBS codecs. */
#ifndef RQFT_COBS_H
#define RQFT_COBS_H

#include "rqft/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RQFT_COBS_DECODER_STORAGE_SIZE 8u

typedef struct rqft_cobs_decoder {
    uint64_t alignment;
    uint8_t storage[RQFT_COBS_DECODER_STORAGE_SIZE];
} rqft_cobs_decoder_t;

rqft_result_t rqft_cobs_encode(const uint8_t *decoded,
                               size_t decoded_len,
                               uint8_t *encoded,
                               size_t encoded_cap,
                               size_t *encoded_len);

rqft_result_t rqft_cobs_decode(const uint8_t *encoded,
                               size_t encoded_len,
                               uint8_t *decoded,
                               size_t decoded_cap,
                               size_t *decoded_len);

void rqft_cobs_decoder_init(rqft_cobs_decoder_t *decoder);

rqft_result_t rqft_cobs_decoder_feed(rqft_cobs_decoder_t *decoder,
                                     const uint8_t *encoded,
                                     size_t encoded_len,
                                     bool finish,
                                     uint8_t *decoded,
                                     size_t decoded_cap,
                                     size_t *decoded_len);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_COBS_H */
