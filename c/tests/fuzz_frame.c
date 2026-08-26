// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* fuzz_frame.c - libFuzzer target for SPEC.md section 3 parser invariants. */
#include "rqft/rqft.h"

#include <stdlib.h>
#include <string.h>

typedef struct fuzz_state {
    size_t valid_ack_count;
} fuzz_state_t;

static void fuzz_emit(void *user, const rqft_frame_event_t *event)
{
    fuzz_state_t *state = (fuzz_state_t *)user;
    if (event->type != RQFT_FRAME_EVENT_FRAME) {
        return;
    }

    uint8_t rebuilt[600];
    size_t rebuilt_len = 0u;
    if (rqft_frame_build(event->frame.type,
                         event->frame.sid,
                         event->frame.seq,
                         event->frame.flags,
                         event->frame.payload,
                         event->frame.payload_len,
                         rebuilt,
                         sizeof(rebuilt),
                         &rebuilt_len) != RQFT_OK ||
        rebuilt_len == 0u) {
        abort();
    }

    if (event->frame.type == RQFT_FRAME_ACK && event->frame.sid == 0x42u &&
        event->frame.seq == 8u && event->frame.flags == 0u && event->frame.payload_len == 0u) {
        state->valid_ack_count++;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    rqft_frame_parser_t parser;
    fuzz_state_t state;
    uint8_t valid_ack[600];
    size_t valid_ack_len = 0u;

    state.valid_ack_count = 0u;
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);

    size_t pos = 0u;
    uint32_t now_ms = 0u;
    while (pos < size) {
        size_t chunk_len = ((size_t)data[pos] % 17u) + 1u;
        if (chunk_len > (size - pos)) {
            chunk_len = size - pos;
        }
        rqft_frame_parser_feed(&parser, data + pos, chunk_len, now_ms, fuzz_emit, &state);
        rqft_frame_parser_flush_idle(&parser, now_ms, fuzz_emit, &state);
        pos += chunk_len;
        now_ms++;
    }

    size_t before = state.valid_ack_count;
    if (rqft_frame_build(RQFT_FRAME_ACK, 0x42u, 8u, 0u, NULL, 0u, valid_ack, sizeof(valid_ack), &valid_ack_len) !=
        RQFT_OK) {
        abort();
    }
    for (size_t i = 0u; i < valid_ack_len; i++) {
        rqft_frame_parser_feed(&parser, valid_ack + i, 1u, now_ms + (uint32_t)i, fuzz_emit, &state);
    }
    if (state.valid_ack_count <= before) {
        abort();
    }

    return 0;
}
