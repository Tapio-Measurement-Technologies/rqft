// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Consistent Overhead Byte Stuffing codec for SPEC.md section 3.1.
 */
#include "rqft/cobs.h"

#include <new>

namespace {

struct CobsDecoderState {
    uint8_t remaining;
    bool needs_zero;
    bool started;
    bool failed;
};

static_assert(sizeof(CobsDecoderState) <= RQFT_COBS_DECODER_STORAGE_SIZE,
              "rqft_cobs_decoder_t storage is too small");
static_assert(alignof(CobsDecoderState) <= alignof(rqft_cobs_decoder_t),
              "rqft_cobs_decoder_t storage is under-aligned");

CobsDecoderState &decoder_state(rqft_cobs_decoder_t *decoder)
{
    return *std::launder(reinterpret_cast<CobsDecoderState *>(&decoder->storage[0]));
}

} // namespace

rqft_result_t rqft_cobs_encode(const uint8_t *decoded,
                               size_t decoded_len,
                               uint8_t *encoded,
                               size_t encoded_cap,
                               size_t *encoded_len)
{
    if (encoded_cap == 0u) {
        return RQFT_ERR_OUTPUT_TOO_SMALL;
    }

    size_t out_len = 1u;
    size_t code_pos = 0u;
    uint8_t code = 1u;
    bool open_code = true;
    encoded[0] = 0u;

    for (size_t i = 0; i < decoded_len; i++) {
        if (decoded[i] == 0u) {
            encoded[code_pos] = code;
            if (out_len >= encoded_cap) {
                return RQFT_ERR_OUTPUT_TOO_SMALL;
            }
            code_pos = out_len;
            encoded[out_len] = 0u;
            out_len++;
            code = 1u;
            open_code = true;
            continue;
        }

        if (out_len >= encoded_cap) {
            return RQFT_ERR_OUTPUT_TOO_SMALL;
        }
        encoded[out_len] = decoded[i];
        out_len++;
        code++;

        if (code == 0xffu) {
            encoded[code_pos] = code;
            code = 1u;
            if ((i + 1u) < decoded_len) {
                if (out_len >= encoded_cap) {
                    return RQFT_ERR_OUTPUT_TOO_SMALL;
                }
                code_pos = out_len;
                encoded[out_len] = 0u;
                out_len++;
                open_code = true;
            } else {
                open_code = false;
            }
        }
    }

    if (open_code) {
        encoded[code_pos] = code;
    }
    *encoded_len = out_len;
    return RQFT_OK;
}

rqft_result_t rqft_cobs_decode(const uint8_t *encoded,
                               size_t encoded_len,
                               uint8_t *decoded,
                               size_t decoded_cap,
                               size_t *decoded_len)
{
    if (encoded_len == 0u) {
        return RQFT_ERR_MALFORMED;
    }

    size_t in_pos = 0u;
    size_t out_len = 0u;
    while (in_pos < encoded_len) {
        uint8_t code = encoded[in_pos];
        in_pos++;
        if (code == 0u) {
            return RQFT_ERR_MALFORMED;
        }

        size_t block_len = (size_t)code - 1u;
        if (block_len > (encoded_len - in_pos)) {
            return RQFT_ERR_MALFORMED;
        }
        if ((out_len + block_len) > decoded_cap) {
            return RQFT_ERR_OUTPUT_TOO_SMALL;
        }
        for (size_t i = 0; i < block_len; i++) {
            uint8_t byte = encoded[in_pos + i];
            if (byte == 0u) {
                return RQFT_ERR_MALFORMED;
            }
            decoded[out_len + i] = byte;
        }
        in_pos += block_len;
        out_len += block_len;

        if ((code != 0xffu) && (in_pos < encoded_len)) {
            if (out_len >= decoded_cap) {
                return RQFT_ERR_OUTPUT_TOO_SMALL;
            }
            decoded[out_len] = 0u;
            out_len++;
        }
    }

    *decoded_len = out_len;
    return RQFT_OK;
}

void rqft_cobs_decoder_init(rqft_cobs_decoder_t *decoder)
{
    static_cast<void>(::new (static_cast<void *>(&decoder->storage[0])) CobsDecoderState{0u, false, false, false});
}

rqft_result_t rqft_cobs_decoder_feed(rqft_cobs_decoder_t *decoder,
                                     const uint8_t *encoded,
                                     size_t encoded_len,
                                     bool finish,
                                     uint8_t *decoded,
                                     size_t decoded_cap,
                                     size_t *decoded_len)
{
    CobsDecoderState &state = decoder_state(decoder);
    if (state.failed) {
        return RQFT_ERR_MALFORMED;
    }

    size_t in_pos = 0u;
    size_t out_len = 0u;
    while (in_pos < encoded_len) {
        if (state.remaining == 0u) {
            if (state.needs_zero) {
                if (out_len >= decoded_cap) {
                    return RQFT_ERR_OUTPUT_TOO_SMALL;
                }
                decoded[out_len] = 0u;
                out_len++;
                state.needs_zero = false;
            }

            uint8_t code = encoded[in_pos];
            in_pos++;
            if (code == 0u) {
                state.failed = true;
                return RQFT_ERR_MALFORMED;
            }
            state.started = true;
            state.remaining = static_cast<uint8_t>(code - 1u);
            state.needs_zero = code != 0xffu;
            continue;
        }

        uint8_t byte = encoded[in_pos];
        if (byte == 0u) {
            state.failed = true;
            return RQFT_ERR_MALFORMED;
        }
        if (out_len >= decoded_cap) {
            return RQFT_ERR_OUTPUT_TOO_SMALL;
        }
        decoded[out_len] = byte;
        out_len++;
        in_pos++;
        state.remaining--;
    }

    if (finish) {
        if (!state.started) {
            state.failed = true;
            return RQFT_ERR_MALFORMED;
        }
        if (state.remaining != 0u) {
            state.failed = true;
            return RQFT_ERR_MALFORMED;
        }
        state.needs_zero = false;
    }

    *decoded_len = out_len;
    return RQFT_OK;
}
