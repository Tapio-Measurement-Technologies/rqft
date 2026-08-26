// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_link_loopback.c - lossy in-process loopback for SPEC.md sections 3-4.
 *
 * Two link endpoints exchange frames through a deterministic seeded fault
 * shim (drop, duplicate, corrupt, burst loss) in both directions; every
 * profile must still deliver 100 frames exactly once, in order.
 */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

#define SID 0x42u
#define FRAME_COUNT 100u
#define STEP_MS 5u
#define DEADLINE_MS 600000u
#define OUTBOX_CAP 16384u

typedef struct fault_profile {
    uint32_t drop_permille;
    uint32_t dup_permille;
    uint32_t corrupt_permille;
    size_t burst_len;
    size_t burst_every;
} fault_profile_t;

typedef struct fault_shim {
    fault_profile_t profile;
    uint32_t rng_state;
    size_t seen;
    size_t burst_remaining;
} fault_shim_t;

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static uint32_t roll1000(fault_shim_t *shim)
{
    return xorshift32(&shim->rng_state) % 1000u;
}

static void shim_init(fault_shim_t *shim, const fault_profile_t *profile, uint32_t seed)
{
    memset(shim, 0, sizeof(*shim));
    shim->profile = *profile;
    shim->rng_state = seed;
}

/* Pass bytes through the fault model, returning the survivor count. */
static size_t shim_feed(fault_shim_t *shim,
                        const uint8_t *in,
                        size_t in_len,
                        uint8_t *out,
                        size_t out_cap)
{
    size_t out_len = 0u;
    for (size_t i = 0u; i < in_len; i++) {
        uint8_t byte = in[i];
        shim->seen++;
        if (shim->profile.burst_every != 0u && shim->seen % shim->profile.burst_every == 0u) {
            shim->burst_remaining = shim->profile.burst_len;
        }
        if (shim->burst_remaining > 0u) {
            shim->burst_remaining--;
            continue;
        }
        if (roll1000(shim) < shim->profile.drop_permille) {
            continue;
        }
        if (roll1000(shim) < shim->profile.corrupt_permille) {
            byte = (uint8_t)(byte ^ (1u + xorshift32(&shim->rng_state) % 255u));
        }
        CHECK(out_len < out_cap);
        out[out_len++] = byte;
        if (roll1000(shim) < shim->profile.dup_permille) {
            CHECK(out_len < out_cap);
            out[out_len++] = byte;
        }
    }
    return out_len;
}

/* A distinct payload containing 0x00 and the frame index. */
static size_t make_payload(unsigned int index, uint8_t *out)
{
    out[0] = (uint8_t)index;
    out[1] = 0x00u;
    out[2] = 0xFFu;
    int n = snprintf((char *)out + 3u, 16u, "payload-%03u", index);
    CHECK(n > 0);
    return 3u + (size_t)n;
}

typedef struct endpoint {
    rqft_frame_parser_t parser;
    rqft_link_t link;
    uint8_t outbox[OUTBOX_CAP];
    size_t outbox_len;
    uint32_t now_ms;
    unsigned int delivered;
    unsigned int delivered_offset;
    unsigned int aborts;
} endpoint_t;

static void endpoint_transmit(void *user, const uint8_t *wire, size_t wire_len)
{
    endpoint_t *ep = (endpoint_t *)user;
    CHECK(ep->outbox_len + wire_len <= OUTBOX_CAP);
    memcpy(ep->outbox + ep->outbox_len, wire, wire_len);
    ep->outbox_len += wire_len;
}

static void endpoint_link_event(void *user, const rqft_link_event_t *event)
{
    endpoint_t *ep = (endpoint_t *)user;
    if (event->type == RQFT_LINK_EVENT_ABORT) {
        ep->aborts++;
        return;
    }

    /* Exactly-once, in-order: each delivery must be the next payload. */
    uint8_t expected[32];
    size_t expected_len = make_payload(ep->delivered_offset + ep->delivered, expected);
    CHECK_EQ_INT(event->payload_len, expected_len);
    CHECK(memcmp(event->payload, expected, expected_len) == 0);
    ep->delivered++;
}

static void endpoint_parser_event(void *user, const rqft_frame_event_t *event)
{
    endpoint_t *ep = (endpoint_t *)user;
    if (event->type == RQFT_FRAME_EVENT_FRAME) {
        rqft_link_on_frame(&ep->link, &event->frame, ep->now_ms);
    }
}

static void endpoint_init(endpoint_t *ep, unsigned int delivered_offset)
{
    rqft_link_config_t config;
    memset(ep, 0, sizeof(*ep));
    memset(&config, 0, sizeof(config));
    config.sid = SID;
    config.window = 4u;
    config.max_payload = RQFT_MAX_PAYLOAD;
    config.transmit = endpoint_transmit;
    config.transmit_user = ep;
    config.on_event = endpoint_link_event;
    config.event_user = ep;
    rqft_frame_parser_init(&ep->parser, RQFT_MAX_PAYLOAD);
    CHECK_EQ_INT(rqft_link_init(&ep->link, &config), RQFT_OK);
    ep->delivered_offset = delivered_offset;
}

/* Drain from's outbox through shim into to's parser and link. */
static void pump(endpoint_t *from, endpoint_t *to, fault_shim_t *shim, uint32_t now_ms)
{
    uint8_t faulty[2u * OUTBOX_CAP];
    size_t faulty_len = shim_feed(shim, from->outbox, from->outbox_len, faulty, sizeof(faulty));
    from->outbox_len = 0u;
    to->now_ms = now_ms;
    rqft_frame_parser_feed(&to->parser, faulty, faulty_len, now_ms, endpoint_parser_event, to);
}

static void run_transfer(const fault_profile_t *profile, const char *name)
{
    static endpoint_t a, b;
    fault_shim_t shim_ab, shim_ba;
    uint8_t payload[32];
    unsigned int sent = 0u;
    uint32_t now = 0u;

    endpoint_init(&a, 0u);
    endpoint_init(&b, 0u);
    shim_init(&shim_ab, profile, 0xC0FFEEu);
    shim_init(&shim_ba, profile, 0xBEEFu);

    while (b.delivered < FRAME_COUNT) {
        if (now >= DEADLINE_MS || a.aborts + b.aborts != 0u) {
            fprintf(stderr, "FAIL profile %s: stalled at %u deliveries, %u aborts\n",
                    name, b.delivered, a.aborts + b.aborts);
            rqft_test_failures++;
            return;
        }
        now += STEP_MS;

        while (sent < FRAME_COUNT) {
            size_t payload_len = make_payload(sent, payload);
            if (rqft_link_send(&a.link, payload, payload_len, now) != RQFT_OK) {
                break;
            }
            sent++;
        }

        pump(&a, &b, &shim_ab, now);
        pump(&b, &a, &shim_ba, now);
        rqft_link_poll(&a.link, now);
        rqft_link_poll(&b.link, now);
    }

    CHECK_EQ_INT(b.delivered, FRAME_COUNT);
    CHECK_EQ_INT(a.aborts + b.aborts, 0);
}

static void test_fault_profiles(void)
{
    const fault_profile_t clean = {0u, 0u, 0u, 0u, 0u};
    const fault_profile_t drop = {10u, 0u, 0u, 0u, 0u};
    const fault_profile_t duplicate = {0u, 20u, 0u, 0u, 0u};
    const fault_profile_t corrupt = {0u, 0u, 10u, 0u, 0u};
    const fault_profile_t burst = {0u, 0u, 0u, 48u, 1500u};
    const fault_profile_t mixed = {5u, 5u, 5u, 32u, 3000u};

    run_transfer(&clean, "clean");
    run_transfer(&drop, "drop");
    run_transfer(&duplicate, "duplicate");
    run_transfer(&corrupt, "corrupt");
    run_transfer(&burst, "burst");
    run_transfer(&mixed, "mixed");
}

/* Both directions carry 100 frames at once over a lightly lossy line. */
static void test_bidirectional_streams_are_independent(void)
{
    static endpoint_t a, b;
    const fault_profile_t light = {5u, 0u, 5u, 0u, 0u};
    fault_shim_t shim_ab, shim_ba;
    uint8_t payload[32];
    unsigned int sent_ab = 0u;
    unsigned int sent_ba = 0u;
    uint32_t now = 0u;

    endpoint_init(&a, FRAME_COUNT); /* A receives payloads 100..199 */
    endpoint_init(&b, 0u);
    shim_init(&shim_ab, &light, 1u);
    shim_init(&shim_ba, &light, 2u);

    while (a.delivered < FRAME_COUNT || b.delivered < FRAME_COUNT) {
        CHECK(now < DEADLINE_MS);
        CHECK_EQ_INT(a.aborts + b.aborts, 0);
        if (now >= DEADLINE_MS || a.aborts + b.aborts != 0u) {
            return;
        }
        now += STEP_MS;

        while (sent_ab < FRAME_COUNT) {
            size_t payload_len = make_payload(sent_ab, payload);
            if (rqft_link_send(&a.link, payload, payload_len, now) != RQFT_OK) {
                break;
            }
            sent_ab++;
        }
        while (sent_ba < FRAME_COUNT) {
            size_t payload_len = make_payload(FRAME_COUNT + sent_ba, payload);
            if (rqft_link_send(&b.link, payload, payload_len, now) != RQFT_OK) {
                break;
            }
            sent_ba++;
        }

        pump(&a, &b, &shim_ab, now);
        pump(&b, &a, &shim_ba, now);
        rqft_link_poll(&a.link, now);
        rqft_link_poll(&b.link, now);
    }

    CHECK_EQ_INT(a.delivered, FRAME_COUNT);
    CHECK_EQ_INT(b.delivered, FRAME_COUNT);
}

int main(void)
{
    test_fault_profiles();
    test_bidirectional_streams_are_independent();
    TEST_MAIN_END();
}
