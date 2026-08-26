// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/** @file @brief CRC-32/ISO-HDLC helpers. */
#ifndef RQFT_CRC32_H
#define RQFT_CRC32_H

#include "rqft/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Compute CRC-32/ISO-HDLC using the same convention as zlib crc32(). */
uint32_t rqft_crc32(const uint8_t *data, size_t len);

/** Continue a CRC calculation from a finalized value, or zero for a new stream. */
uint32_t rqft_crc32_update(uint32_t crc, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_CRC32_H */
