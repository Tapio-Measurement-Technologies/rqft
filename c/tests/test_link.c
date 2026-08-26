// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_link.c - Go-Back-N link layer tests for SPEC.md sections 4.1, 4.3, 4.6. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

#define MAX_CHUNKS 512u
#define WIRE_CAP 32768u
#define MAX_EVENTS 512u
#define EVENT_PAYLOAD_CAP 64u

typedef struct link_log {
    uint8_t wire[WIRE_CAP];
    size_t wire_len;
    size_t chunk_off[MAX_CHUNKS];
    size_t chunk_len[MAX_CHUNKS];
    size_t chunk_count;
    rqft_link_event_type_t event_types[MAX_EVENTS];
    rqft_abort_reason_t event_reasons[MAX_EVENTS];
    bool event_from_peer[MAX_EVENTS];
    uint8_t event_payload[MAX_EVENTS][EVENT_PAYLOAD_CAP];
    size_t event_payload_len[MAX_EVENTS];
    size_t event_count;
} link_log_t;

static void log_transmit(void *user, const uint8_t *wire, size_t wire_len)
{
    link_log_t *log = (link_log_t *)user;
    CHECK(log->chunk_count < MAX_CHUNKS);
    CHECK(log->wire_len + wire_len <= WIRE_CAP);
    memcpy(log->wire + log->wire_len, wire, wire_len);
    log->chunk_off[log->chunk_count] = log->wire_len;
    log->chunk_len[log->chunk_count] = wire_len;
    log->wire_len += wire_len;
    log->chunk_count++;
}

static void log_event(void *user, const rqft_link_event_t *event)
{
    link_log_t *log = (link_log_t *)user;
    CHECK(log->event_count < MAX_EVENTS);
    log->event_types[log->event_count] = event->type;
    log->event_reasons[log->event_count] = event->reason;
    log->event_from_peer[log->event_count] = event->from_peer;
    log->event_payload_len[log->event_count] = event->payload_len;
    if (event->type == RQFT_LINK_EVENT_DELIVER && event->payload_len > 0u) {
        CHECK(event->payload_len <= EVENT_PAYLOAD_CAP);
        memcpy(log->event_payload[log->event_count], event->payload, event->payload_len);
    }
    log->event_count++;
}

/* Decode one logged wire chunk back into header fields for inspection. */
static void chunk_frame(const link_log_t *log,
                        size_t chunk,
                        uint8_t *ftype,
                        uint8_t *sid,
                        uint8_t *seq,
                        uint8_t *flags)
{
    uint8_t decoded[4u + RQFT_MAX_PAYLOAD + 4u];
    size_t decoded_len = 0u;
    const uint8_t *wire = log->wire + log->chunk_off[chunk];
    size_t wire_len = log->chunk_len[chunk];

    CHECK(wire_len >= 2u);
    CHECK_EQ_INT(wire[0], 0);
    CHECK_EQ_INT(wire[wire_len - 1u], 0);
    CHECK_EQ_INT(rqft_cobs_decode(wire + 1u, wire_len - 2u, decoded, sizeof(decoded), &decoded_len),
                 RQFT_OK);
    CHECK(decoded_len >= 8u);
    *ftype = decoded[0];
    *sid = decoded[1];
    *seq = decoded[2];
    *flags = decoded[3];
}

static uint8_t chunk_seq(const link_log_t *log, size_t chunk)
{
    uint8_t ftype = 0u, sid = 0u, seq = 0u, flags = 0u;
    chunk_frame(log, chunk, &ftype, &sid, &seq, &flags);
    return seq;
}

static void link_setup(rqft_link_t *link, link_log_t *log, uint8_t window, uint16_t max_payload)
{
    rqft_link_config_t config;
    memset(log, 0, sizeof(*log));
    memset(&config, 0, sizeof(config));
    config.sid = 0x42u;
    config.window = window;
    config.max_payload = max_payload;
    config.transmit = log_transmit;
    config.transmit_user = log;
    config.on_event = log_event;
    config.event_user = log;
    CHECK_EQ_INT(rqft_link_init(link, &config), RQFT_OK);
}

static void feed_ack(rqft_link_t *link, uint8_t seq, bool nak, uint32_t now_ms)
{
    rqft_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.type = RQFT_FRAME_ACK;
    frame.sid = 0x42u;
    frame.seq = seq;
    frame.flags = nak ? 0x01u : 0x00u;
    rqft_link_on_frame(link, &frame, now_ms);
}

static void test_config_validation(void)
{
    rqft_link_t link;
    link_log_t log;
    rqft_link_config_t config;

    memset(&log, 0, sizeof(log));
    memset(&config, 0, sizeof(config));
    config.sid = 0u;
    config.window = 4u;
    config.max_payload = RQFT_MAX_PAYLOAD;
    config.transmit = log_transmit;
    config.transmit_user = &log;
    config.on_event = log_event;
    config.event_user = &log;
    CHECK_EQ_INT(rqft_link_init(&link, &config), RQFT_ERR_MALFORMED);

    config.sid = 0x42u;
    config.window = 0u;
    CHECK_EQ_INT(rqft_link_init(&link, &config), RQFT_ERR_MALFORMED);
    config.window = RQFT_WINDOW_MAX + 1u;
    CHECK_EQ_INT(rqft_link_init(&link, &config), RQFT_ERR_MALFORMED);

    config.window = 4u;
    config.max_payload = RQFT_MAX_PAYLOAD + 1u;
    CHECK_EQ_INT(rqft_link_init(&link, &config), RQFT_ERR_MALFORMED);

    config.max_payload = RQFT_MAX_PAYLOAD;
    config.transmit = NULL;
    CHECK_EQ_INT(rqft_link_init(&link, &config), RQFT_ERR_MALFORMED);
}

static void test_window_fills_to_w_then_refuses(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    for (uint8_t i = 0u; i < 4u; i++) {
        CHECK_EQ_INT(rqft_link_send(&link, &i, 1u, 0u), RQFT_OK);
    }
    uint8_t extra = 4u;
    CHECK_EQ_INT(rqft_link_send(&link, &extra, 1u, 0u), RQFT_ERR_WINDOW_FULL);

    CHECK_EQ_INT(rqft_link_in_flight(&link), 4);
    CHECK_EQ_INT(log.chunk_count, 4);
    for (size_t i = 0u; i < 4u; i++) {
        uint8_t ftype = 0u, sid = 0u, seq = 0u, flags = 0u;
        chunk_frame(&log, i, &ftype, &sid, &seq, &flags);
        CHECK_EQ_INT(ftype, RQFT_FRAME_DATA);
        CHECK_EQ_INT(sid, 0x42);
        CHECK_EQ_INT(seq, i);
        CHECK_EQ_INT(flags, 0);
    }
}

static void test_cumulative_ack_slides_window(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    for (uint8_t i = 0u; i < 4u; i++) {
        CHECK_EQ_INT(rqft_link_send(&link, &i, 1u, 0u), RQFT_OK);
    }
    feed_ack(&link, 2u, false, 10u);
    CHECK_EQ_INT(rqft_link_in_flight(&link), 2);

    uint8_t byte = 4u;
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 10u), RQFT_OK);
    byte = 5u;
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 10u), RQFT_OK);
    byte = 6u;
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 10u), RQFT_ERR_WINDOW_FULL);

    feed_ack(&link, 6u, false, 20u);
    CHECK_EQ_INT(rqft_link_in_flight(&link), 0);
    CHECK_EQ_INT(log.event_count, 0);
}

static void test_duplicate_and_stale_acks_ignored(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    uint8_t byte = 0u;
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    byte = 1u;
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);

    feed_ack(&link, 2u, false, 10u);
    CHECK_EQ_INT(rqft_link_in_flight(&link), 0);

    feed_ack(&link, 2u, false, 11u);
    feed_ack(&link, 7u, false, 12u);
    CHECK_EQ_INT(rqft_link_in_flight(&link), 0);
    CHECK_EQ_INT(rqft_link_state(&link), RQFT_LINK_ACTIVE);

    byte = 2u;
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 20u), RQFT_OK);
    CHECK_EQ_INT(chunk_seq(&log, log.chunk_count - 1u), 2);
}

static void test_seq_wraps_255_to_0(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 8u, RQFT_MAX_PAYLOAD);

    for (unsigned int i = 0u; i < 300u; i++) {
        uint8_t byte = (uint8_t)i;
        CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, i), RQFT_OK);
        feed_ack(&link, (uint8_t)(i + 1u), false, i);
    }

    CHECK_EQ_INT(log.chunk_count, 300);
    for (size_t i = 0u; i < 300u; i++) {
        CHECK_EQ_INT(chunk_seq(&log, i), (uint8_t)i);
    }
    CHECK_EQ_INT(chunk_seq(&log, 255u), 255);
    CHECK_EQ_INT(chunk_seq(&log, 256u), 0);
}

static void test_wrap_ack_across_boundary(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    for (unsigned int i = 0u; i < 254u; i++) {
        uint8_t byte = 'x';
        CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
        feed_ack(&link, (uint8_t)(i + 1u), false, 0u);
    }

    for (unsigned int i = 0u; i < 4u; i++) {
        uint8_t byte = 'y';
        CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 1u), RQFT_OK);
    }
    CHECK_EQ_INT(rqft_link_in_flight(&link), 4);

    feed_ack(&link, 2u, false, 2u);
    CHECK_EQ_INT(rqft_link_in_flight(&link), 0);
}

static void test_send_payload_size_validation(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t payload[17];
    link_setup(&link, &log, 4u, 16u);

    memset(payload, 'x', sizeof(payload));
    CHECK_EQ_INT(rqft_link_send(&link, payload, 0u, 0u), RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_link_send(&link, payload, 17u, 0u), RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_link_send(&link, payload, 16u, 0u), RQFT_OK);
}

static void test_rto_expiry_retransmits_all_unacked_byte_identical(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    for (uint8_t i = 0u; i < 3u; i++) {
        CHECK_EQ_INT(rqft_link_send(&link, &i, 1u, 0u), RQFT_OK);
    }

    rqft_link_poll(&link, RQFT_RTO_INITIAL_MS - 1u);
    CHECK_EQ_INT(log.chunk_count, 3);

    rqft_link_poll(&link, RQFT_RTO_INITIAL_MS);
    CHECK_EQ_INT(log.chunk_count, 6);
    for (size_t i = 0u; i < 3u; i++) {
        CHECK_EQ_INT(log.chunk_len[i], log.chunk_len[i + 3u]);
        CHECK(memcmp(log.wire + log.chunk_off[i],
                     log.wire + log.chunk_off[i + 3u],
                     log.chunk_len[i]) == 0);
    }
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->frames_retransmitted, 3);
}

static void test_rto_backoff_doubles_then_clamps(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'x';
    const uint32_t expiries[] = {1000u, 3000u, 6000u, 9000u};
    link_setup(&link, &log, 1u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    for (size_t i = 0u; i < sizeof(expiries) / sizeof(expiries[0]); i++) {
        size_t before = log.chunk_count;
        rqft_link_poll(&link, expiries[i] - 1u);
        CHECK_EQ_INT(log.chunk_count, before);
        rqft_link_poll(&link, expiries[i]);
        CHECK_EQ_INT(log.chunk_count, before + 1u);
    }
}

static void test_retry_exhaustion_aborts(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'x';
    uint32_t now = 0u;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    while (log.event_count == 0u && now < 60000u) {
        now += 100u;
        rqft_link_poll(&link, now);
    }

    /* The abort fires at 1000 + 2000 + 6 * 3000 = 21000 ms. */
    CHECK_EQ_INT(now, 21000);
    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_LINK_EVENT_ABORT);
    CHECK_EQ_INT(log.event_reasons[0], RQFT_ABORT_E_TIMEOUT);
    CHECK(!log.event_from_peer[0]);
    CHECK_EQ_INT(rqft_link_state(&link), RQFT_LINK_DEAD);

    /* Original + (N_RETRY - 1) retransmissions + final ABORT frame. */
    CHECK_EQ_INT(log.chunk_count, 1u + (RQFT_N_RETRY - 1u) + 1u);
    uint8_t ftype = 0u, sid = 0u, seq = 0u, flags = 0u;
    chunk_frame(&log, log.chunk_count - 1u, &ftype, &sid, &seq, &flags);
    CHECK_EQ_INT(ftype, RQFT_FRAME_ABORT);
    for (size_t i = 0u; i + 1u < log.chunk_count; i++) {
        chunk_frame(&log, i, &ftype, &sid, &seq, &flags);
        CHECK_EQ_INT(ftype, RQFT_FRAME_DATA);
        CHECK_EQ_INT(seq, 0);
    }

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, now), RQFT_ERR_LINK_DEAD);
    rqft_link_poll(&link, now + 10000u);
    feed_ack(&link, 1u, false, now);
    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.chunk_count, 1u + (RQFT_N_RETRY - 1u) + 1u);
}

static void test_progress_resets_retry_counter(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    uint32_t now = 6100u;
    size_t expiries = 0u;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    byte = 'b';
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);

    rqft_link_poll(&link, 1000u);
    rqft_link_poll(&link, 3000u);
    rqft_link_poll(&link, 6000u);

    feed_ack(&link, 1u, false, 6100u);

    while (log.event_count == 0u && now < 60000u) {
        size_t before = log.chunk_count;
        now += 100u;
        rqft_link_poll(&link, now);
        if (log.chunk_count != before) {
            expiries++;
        }
    }

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_LINK_EVENT_ABORT);
    /* N_RETRY - 1 retransmission expiries + the ABORT transmission. */
    CHECK_EQ_INT(expiries, RQFT_N_RETRY);
}

static void test_timer_restarts_on_progress(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    byte = 'b';
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 200u), RQFT_OK);

    /* The ACK also samples RTT=500 (srtt=500, rttvar=250, RTO=1500);
     * without a restart the timer would fire at 0+1500, restarted at 500
     * it fires at 2000. */
    feed_ack(&link, 1u, false, 500u);

    rqft_link_poll(&link, 1999u);
    CHECK_EQ_INT(log.chunk_count, 2);
    rqft_link_poll(&link, 2000u);
    CHECK_EQ_INT(log.chunk_count, 3);
    CHECK_EQ_INT(chunk_seq(&log, 2u), 1);
}

static void test_ack_rtt_sample_adapts_rto(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    byte = 'b';
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);

    /* 500 ms sample: srtt=500, rttvar=250, RTO=1500; timer restarts at
     * 500 and fires at 2000. */
    feed_ack(&link, 1u, false, 500u);

    rqft_link_poll(&link, 1999u);
    CHECK_EQ_INT(log.chunk_count, 2);
    rqft_link_poll(&link, 2000u);
    CHECK_EQ_INT(log.chunk_count, 3);
}

static void test_rtt_sample_taken_from_newest_covered_frame(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    byte = 'b';
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 400u), RQFT_OK);

    /* The cumulative ACK is triggered by the newest frame it covers, so
     * the sample is 100 ms (frame b), not 500 ms: RTO=300. */
    feed_ack(&link, 2u, false, 500u);

    byte = 'c';
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 600u), RQFT_OK);
    rqft_link_poll(&link, 899u);
    CHECK_EQ_INT(log.chunk_count, 3);
    rqft_link_poll(&link, 900u);
    CHECK_EQ_INT(log.chunk_count, 4);
}

static void test_karn_no_sample_from_retransmitted_frame(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    rqft_link_poll(&link, 1000u); /* retransmit; RTO backs off to 2000 */

    /* Covering ACK after a retransmission: ambiguous timing, no sample,
     * backed-off RTO stays. */
    feed_ack(&link, 1u, false, 1500u);

    byte = 'b';
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 1600u), RQFT_OK);
    rqft_link_poll(&link, 3599u);
    CHECK_EQ_INT(log.chunk_count, 3);
    rqft_link_poll(&link, 3600u);
    CHECK_EQ_INT(log.chunk_count, 4);
}

static void test_clean_sample_reverts_backoff(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    rqft_link_poll(&link, 1000u); /* retransmit; RTO backs off to 2000 */
    feed_ack(&link, 1u, false, 1200u); /* retransmitted: no sample */

    /* A never-retransmitted frame gives a clean 300 ms sample:
     * srtt=300, rttvar=150, RTO=900 replaces the backed-off 2000. */
    byte = 'b';
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 1300u), RQFT_OK);
    feed_ack(&link, 2u, false, 1600u);

    byte = 'c';
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 1700u), RQFT_OK);
    rqft_link_poll(&link, 2599u);
    CHECK_EQ_INT(log.chunk_count, 4);
    rqft_link_poll(&link, 2600u);
    CHECK_EQ_INT(log.chunk_count, 5);
}

static void test_timer_stops_when_window_empties(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    feed_ack(&link, 1u, false, 100u);

    rqft_link_poll(&link, 50000u);
    CHECK_EQ_INT(log.chunk_count, 1);
    CHECK_EQ_INT(rqft_link_state(&link), RQFT_LINK_ACTIVE);
}

static void test_nak_triggers_goback_retransmit_byte_identical(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    for (uint8_t i = 0u; i < 3u; i++) {
        CHECK_EQ_INT(rqft_link_send(&link, &i, 1u, 0u), RQFT_OK);
    }

    feed_ack(&link, 0u, true, 100u);

    CHECK_EQ_INT(log.chunk_count, 6);
    for (size_t i = 0u; i < 3u; i++) {
        CHECK_EQ_INT(log.chunk_len[i], log.chunk_len[i + 3u]);
        CHECK(memcmp(log.wire + log.chunk_off[i],
                     log.wire + log.chunk_off[i + 3u],
                     log.chunk_len[i]) == 0);
    }
    CHECK_EQ_INT(rqft_link_in_flight(&link), 3);
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->frames_retransmitted, 3);
}

static void test_nak_goback_rate_limited_to_one_per_flight(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    for (uint8_t i = 0u; i < 3u; i++) {
        CHECK_EQ_INT(rqft_link_send(&link, &i, 1u, 0u), RQFT_OK);
    }

    feed_ack(&link, 0u, true, 100u);
    CHECK_EQ_INT(log.chunk_count, 6);

    feed_ack(&link, 0u, true, 110u);
    feed_ack(&link, 0u, true, 120u);
    CHECK_EQ_INT(log.chunk_count, 6);
}

static void test_progress_rearms_nak_goback(void)
{
    rqft_link_t link;
    link_log_t log;
    const uint8_t expected_seqs[] = {0u, 1u, 2u, 0u, 1u, 2u, 1u, 2u};
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    for (uint8_t i = 0u; i < 3u; i++) {
        CHECK_EQ_INT(rqft_link_send(&link, &i, 1u, 0u), RQFT_OK);
    }

    feed_ack(&link, 0u, true, 100u);
    feed_ack(&link, 1u, true, 200u);

    CHECK_EQ_INT(rqft_link_in_flight(&link), 2);
    CHECK_EQ_INT(log.chunk_count, sizeof(expected_seqs));
    for (size_t i = 0u; i < sizeof(expected_seqs); i++) {
        CHECK_EQ_INT(chunk_seq(&log, i), expected_seqs[i]);
    }
}

static void test_rto_expiry_rearms_nak_goback(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);

    feed_ack(&link, 0u, true, 100u);
    feed_ack(&link, 0u, true, 200u);
    CHECK_EQ_INT(log.chunk_count, 2);

    rqft_link_poll(&link, 1100u);
    CHECK_EQ_INT(log.chunk_count, 3);

    feed_ack(&link, 0u, true, 1200u);
    CHECK_EQ_INT(log.chunk_count, 4);
}

static void test_nak_goback_restarts_timer(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    feed_ack(&link, 0u, true, 500u);
    CHECK_EQ_INT(log.chunk_count, 2);

    rqft_link_poll(&link, 1499u);
    CHECK_EQ_INT(log.chunk_count, 2);
    rqft_link_poll(&link, 1500u);
    CHECK_EQ_INT(log.chunk_count, 3);
}

static void test_nak_with_empty_window_ignored(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'a';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    feed_ack(&link, 1u, false, 100u);

    feed_ack(&link, 1u, true, 200u);
    CHECK_EQ_INT(log.chunk_count, 1);
    CHECK_EQ_INT(rqft_link_state(&link), RQFT_LINK_ACTIVE);
}

static void feed_data(rqft_link_t *link,
                      uint8_t sid,
                      uint8_t seq,
                      const uint8_t *payload,
                      size_t payload_len,
                      uint32_t now_ms)
{
    rqft_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.type = RQFT_FRAME_DATA;
    frame.sid = sid;
    frame.seq = seq;
    memcpy(frame.payload, payload, payload_len);
    frame.payload_len = payload_len;
    rqft_link_on_frame(link, &frame, now_ms);
}

static void feed_abort(rqft_link_t *link, uint8_t sid, uint8_t reason, uint32_t now_ms)
{
    rqft_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.type = RQFT_FRAME_ABORT;
    frame.sid = sid;
    frame.payload[0] = reason;
    frame.payload_len = 1u;
    rqft_link_on_frame(link, &frame, now_ms);
}

/* Check that logged chunk n is an ACK with the given cumulative seq and NAK
 * flag. */
static void check_ack_chunk(const link_log_t *log, size_t chunk, uint8_t seq, bool nak)
{
    uint8_t ftype = 0u, sid = 0u, ack_seq = 0u, flags = 0u;
    chunk_frame(log, chunk, &ftype, &sid, &ack_seq, &flags);
    CHECK_EQ_INT(ftype, RQFT_FRAME_ACK);
    CHECK_EQ_INT(sid, 0x42);
    CHECK_EQ_INT(ack_seq, seq);
    CHECK_EQ_INT(flags, nak ? 1 : 0);
}

static void test_in_order_delivery_and_ack(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    feed_data(&link, 0x42u, 0u, (const uint8_t *)"one", 3u, 10u);
    feed_data(&link, 0x42u, 1u, (const uint8_t *)"two", 3u, 20u);

    CHECK_EQ_INT(log.event_count, 2);
    CHECK_EQ_INT(log.event_types[0], RQFT_LINK_EVENT_DELIVER);
    CHECK_EQ_INT(log.event_payload_len[0], 3);
    CHECK(memcmp(log.event_payload[0], "one", 3u) == 0);
    CHECK_EQ_INT(log.event_types[1], RQFT_LINK_EVENT_DELIVER);
    CHECK(memcmp(log.event_payload[1], "two", 3u) == 0);

    CHECK_EQ_INT(log.chunk_count, 2);
    check_ack_chunk(&log, 0u, 1u, false);
    check_ack_chunk(&log, 1u, 2u, false);
}

static void test_duplicate_data_acked_with_nak_no_redelivery(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    feed_data(&link, 0x42u, 0u, (const uint8_t *)"one", 3u, 10u);
    feed_data(&link, 0x42u, 0u, (const uint8_t *)"one", 3u, 20u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.chunk_count, 2);
    check_ack_chunk(&log, 1u, 1u, true);
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->naks_sent, 1);
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->duplicate_data_received, 1);
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->out_of_order_data_received, 0);
}

static void test_gap_acked_with_nak(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    feed_data(&link, 0x42u, 0u, (const uint8_t *)"one", 3u, 10u);
    feed_data(&link, 0x42u, 2u, (const uint8_t *)"three", 5u, 20u);

    CHECK_EQ_INT(log.event_count, 1);
    check_ack_chunk(&log, 1u, 1u, true);
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->naks_sent, 1);
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->duplicate_data_received, 0);
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->out_of_order_data_received, 1);

    feed_data(&link, 0x42u, 1u, (const uint8_t *)"two", 3u, 30u);
    CHECK_EQ_INT(log.event_count, 2);
    CHECK(memcmp(log.event_payload[1], "two", 3u) == 0);
    check_ack_chunk(&log, 2u, 2u, false);
}

static void test_wrong_sid_frames_dropped_and_counted(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'x';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);

    feed_data(&link, 0x43u, 0u, (const uint8_t *)"stale", 5u, 10u);
    {
        rqft_frame_t frame;
        memset(&frame, 0, sizeof(frame));
        frame.type = RQFT_FRAME_ACK;
        frame.sid = 0x43u;
        frame.seq = 1u;
        rqft_link_on_frame(&link, &frame, 10u);
    }
    feed_abort(&link, 0x43u, RQFT_ABORT_E_TIMEOUT, 10u);

    CHECK_EQ_INT(rqft_link_diagnostics(&link)->frames_wrong_sid, 3);
    CHECK_EQ_INT(rqft_link_in_flight(&link), 1);
    CHECK_EQ_INT(rqft_link_state(&link), RQFT_LINK_ACTIVE);
    CHECK_EQ_INT(log.event_count, 0);
    CHECK_EQ_INT(log.chunk_count, 1);

    /* HELLO frames belong to the session layer and are not counted here. */
    {
        rqft_frame_t frame;
        memset(&frame, 0, sizeof(frame));
        frame.type = RQFT_FRAME_HELLO;
        frame.sid = 0x99u;
        frame.payload_len = 8u;
        rqft_link_on_frame(&link, &frame, 10u);
    }
    CHECK_EQ_INT(rqft_link_diagnostics(&link)->frames_wrong_sid, 3);
}

static void test_peer_abort_ends_session_immediately(void)
{
    rqft_link_t link;
    link_log_t log;
    uint8_t byte = 'x';
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 0u), RQFT_OK);
    feed_abort(&link, 0x42u, RQFT_ABORT_E_USER, 10u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_LINK_EVENT_ABORT);
    CHECK_EQ_INT(log.event_reasons[0], RQFT_ABORT_E_USER);
    CHECK(log.event_from_peer[0]);
    CHECK_EQ_INT(rqft_link_state(&link), RQFT_LINK_DEAD);
    CHECK_EQ_INT(log.chunk_count, 1);

    feed_data(&link, 0x42u, 0u, (const uint8_t *)"late", 4u, 20u);
    rqft_link_poll(&link, 50000u);
    CHECK_EQ_INT(rqft_link_send(&link, &byte, 1u, 20u), RQFT_ERR_LINK_DEAD);
    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.chunk_count, 1);
}

static void test_unknown_abort_reason_maps_to_e_proto(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    feed_abort(&link, 0x42u, 0x77u, 10u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_reasons[0], RQFT_ABORT_E_PROTO);
    CHECK(log.event_from_peer[0]);
    CHECK_EQ_INT(rqft_link_state(&link), RQFT_LINK_DEAD);
}

static void test_receive_seq_wraps_255_to_0(void)
{
    rqft_link_t link;
    link_log_t log;
    link_setup(&link, &log, 4u, RQFT_MAX_PAYLOAD);

    for (unsigned int i = 0u; i < 300u; i++) {
        uint8_t byte = (uint8_t)i;
        feed_data(&link, 0x42u, (uint8_t)i, &byte, 1u, i);
    }

    CHECK_EQ_INT(log.event_count, 300);
    for (size_t i = 0u; i < 300u; i++) {
        CHECK_EQ_INT(log.event_types[i], RQFT_LINK_EVENT_DELIVER);
        CHECK_EQ_INT(log.event_payload[i][0], (uint8_t)i);
    }
    check_ack_chunk(&log, 254u, 255u, false);
    check_ack_chunk(&log, 255u, 0u, false);
    check_ack_chunk(&log, 256u, 1u, false);
}

int main(void)
{
    test_config_validation();
    test_window_fills_to_w_then_refuses();
    test_cumulative_ack_slides_window();
    test_duplicate_and_stale_acks_ignored();
    test_seq_wraps_255_to_0();
    test_wrap_ack_across_boundary();
    test_send_payload_size_validation();
    test_rto_expiry_retransmits_all_unacked_byte_identical();
    test_rto_backoff_doubles_then_clamps();
    test_retry_exhaustion_aborts();
    test_progress_resets_retry_counter();
    test_timer_restarts_on_progress();
    test_timer_stops_when_window_empties();
    test_nak_triggers_goback_retransmit_byte_identical();
    test_nak_goback_rate_limited_to_one_per_flight();
    test_progress_rearms_nak_goback();
    test_rto_expiry_rearms_nak_goback();
    test_nak_goback_restarts_timer();
    test_nak_with_empty_window_ignored();
    test_ack_rtt_sample_adapts_rto();
    test_rtt_sample_taken_from_newest_covered_frame();
    test_karn_no_sample_from_retransmitted_frame();
    test_clean_sample_reverts_backoff();
    test_in_order_delivery_and_ack();
    test_duplicate_data_acked_with_nak_no_redelivery();
    test_gap_acked_with_nak();
    test_wrong_sid_frames_dropped_and_counted();
    test_peer_abort_ends_session_immediately();
    test_unknown_abort_reason_maps_to_e_proto();
    test_receive_seq_wraps_255_to_0();
    TEST_MAIN_END();
}
