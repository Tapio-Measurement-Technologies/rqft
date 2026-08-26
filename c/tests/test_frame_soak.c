// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_frame_soak.c - deterministic parser soak for SPEC.md section 3.5. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

typedef struct soak_events {
    size_t ack_count;
    size_t frame_count;
} soak_events_t;

static void soak_emit(void *user, const rqft_frame_event_t *event)
{
    soak_events_t *events = (soak_events_t *)user;
    if (event->type != RQFT_FRAME_EVENT_FRAME) {
        return;
    }

    uint8_t rebuilt[600];
    size_t rebuilt_len = 0u;
    CHECK_EQ_INT(rqft_frame_build(event->frame.type,
                                  event->frame.sid,
                                  event->frame.seq,
                                  event->frame.flags,
                                  event->frame.payload,
                                  event->frame.payload_len,
                                  rebuilt,
                                  sizeof(rebuilt),
                                  &rebuilt_len),
                 RQFT_OK);
    CHECK(rebuilt_len > 0u);
    events->frame_count++;

    if (event->frame.type == RQFT_FRAME_ACK && event->frame.sid == 0x42u &&
        event->frame.seq == 8u && event->frame.flags == 0u && event->frame.payload_len == 0u) {
        events->ack_count++;
    }
}

static uint32_t lcg_next(uint32_t *state)
{
    *state = (*state * 1664525u) + 1013904223u;
    return *state;
}

int main(void)
{
    uint8_t valid_ack[600];
    size_t valid_ack_len = 0u;
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ACK, 0x42u, 8u, 0u, NULL, 0u,
                                  valid_ack, sizeof(valid_ack), &valid_ack_len),
                 RQFT_OK);

    uint32_t rng = 0x12345678u;
    for (unsigned int round = 0u; round < 1000u; round++) {
        rqft_frame_parser_t parser;
        soak_events_t events;
        uint8_t random_bytes[96];
        uint32_t now_ms = round;

        memset(&events, 0, sizeof(events));
        rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);

        size_t random_len = (size_t)(lcg_next(&rng) % sizeof(random_bytes));
        for (size_t i = 0u; i < random_len; i++) {
            random_bytes[i] = (uint8_t)(lcg_next(&rng) & 0xffu);
        }

        size_t pos = 0u;
        while (pos < random_len) {
            size_t chunk_len = (size_t)((lcg_next(&rng) % 13u) + 1u);
            if (chunk_len > (random_len - pos)) {
                chunk_len = random_len - pos;
            }
            rqft_frame_parser_feed(&parser, random_bytes + pos, chunk_len, now_ms, soak_emit, &events);
            rqft_frame_parser_flush_idle(&parser, now_ms, soak_emit, &events);
            pos += chunk_len;
            now_ms++;
        }

        size_t before = events.ack_count;
        for (size_t i = 0u; i < valid_ack_len; i++) {
            rqft_frame_parser_feed(&parser, valid_ack + i, 1u, now_ms + (uint32_t)i, soak_emit, &events);
        }
        CHECK(events.ack_count > before);
    }

    TEST_MAIN_END();
}
