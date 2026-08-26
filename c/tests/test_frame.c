// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_frame.c - frame codec and parser tests for SPEC.md section 3. */
#include "rqft/cobs.h"
#include "rqft/crc32.h"
#include "rqft/frame.h"
#include "test_support.h"

#include <stdint.h>

typedef struct collected_events {
    rqft_frame_t frames[16];
    size_t frame_count;
    uint8_t passthrough[1200];
    size_t passthrough_len;
    size_t passthrough_events;
} collected_events_t;

static void collect_event(void *user, const rqft_frame_event_t *event)
{
    collected_events_t *events = (collected_events_t *)user;
    if (event->type == RQFT_FRAME_EVENT_FRAME) {
        CHECK(events->frame_count < 16u);
        events->frames[events->frame_count] = event->frame;
        events->frame_count++;
        return;
    }

    CHECK(event->type == RQFT_FRAME_EVENT_PASSTHROUGH);
    CHECK(events->passthrough_len + event->passthrough_len <= sizeof(events->passthrough));
    memcpy(events->passthrough + events->passthrough_len, event->passthrough, event->passthrough_len);
    events->passthrough_len += event->passthrough_len;
    events->passthrough_events++;
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static size_t decode_hex(const char *hex, size_t hex_len, uint8_t *out, size_t out_cap)
{
    CHECK((hex_len % 2u) == 0u);
    CHECK((hex_len / 2u) <= out_cap);

    size_t out_len = 0u;
    for (size_t i = 0u; i < hex_len; i += 2u) {
        int hi = hex_value(hex[i]);
        int lo = hex_value(hex[i + 1u]);
        CHECK(hi >= 0);
        CHECK(lo >= 0);
        out[out_len] = (uint8_t)(((unsigned int)hi << 4u) | (unsigned int)lo);
        out_len++;
    }
    return out_len;
}

static const char *field_value(const char *line, const char *field)
{
    const char *key = strstr(line, field);
    CHECK(key != NULL);
    if (key == NULL) {
        return NULL;
    }
    const char *value = strchr(key + strlen(field), '"');
    CHECK(value != NULL);
    if (value == NULL) {
        return NULL;
    }
    return value + 1;
}

static size_t field_hex(const char *line, const char *field, uint8_t *out, size_t out_cap)
{
    const char *begin = field_value(line, field);
    if (begin == NULL) {
        return 0u;
    }
    const char *end = strchr(begin, '"');
    CHECK(end != NULL);
    if (end == NULL) {
        return 0u;
    }
    return decode_hex(begin, (size_t)(end - begin), out, out_cap);
}

static unsigned int field_uint(const char *line, const char *field)
{
    const char *key = strstr(line, field);
    CHECK(key != NULL);
    if (key == NULL) {
        return 0u;
    }
    return (unsigned int)strtoul(key + strlen(field), NULL, 10);
}

static void put_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
}

static size_t build_raw_wire(uint8_t ftype,
                             uint8_t sid,
                             uint8_t seq,
                             uint8_t flags,
                             const uint8_t *payload,
                             size_t payload_len,
                             bool corrupt_crc,
                             uint8_t *wire,
                             size_t wire_cap)
{
    uint8_t decoded[4u + RQFT_MAX_PAYLOAD + 4u];
    uint8_t encoded[RQFT_MAX_ENCODED];
    size_t body_len = 4u + payload_len;
    size_t decoded_len = body_len + 4u;
    size_t encoded_len = 0u;

    decoded[0] = ftype;
    decoded[1] = sid;
    decoded[2] = seq;
    decoded[3] = flags;
    if (payload_len > 0u) {
        memcpy(decoded + 4u, payload, payload_len);
    }
    put_u32_le(decoded + body_len, rqft_crc32(decoded, body_len) ^ (corrupt_crc ? 0x55u : 0u));

    CHECK(wire_cap >= RQFT_MAX_ENCODED + 2u);
    CHECK_EQ_INT(rqft_cobs_encode(decoded, decoded_len, encoded, sizeof(encoded), &encoded_len), RQFT_OK);
    wire[0] = 0u;
    memcpy(wire + 1u, encoded, encoded_len);
    wire[encoded_len + 1u] = 0u;
    return encoded_len + 2u;
}

static void check_frame_eq(const rqft_frame_t *frame,
                           rqft_frame_type_t type,
                           uint8_t sid,
                           uint8_t seq,
                           uint8_t flags,
                           const uint8_t *payload,
                           size_t payload_len)
{
    CHECK_EQ_INT(frame->type, type);
    CHECK_EQ_INT(frame->sid, sid);
    CHECK_EQ_INT(frame->seq, seq);
    CHECK_EQ_INT(frame->flags, flags);
    CHECK_EQ_INT(frame->payload_len, payload_len);
    if (payload_len > 0u) {
        CHECK(memcmp(frame->payload, payload, payload_len) == 0);
    }
}

static void run_vector_line(const char *line, unsigned int *seen)
{
    if (strstr(line, "\"encoded_hex\":") == NULL) {
        return;
    }

    uint8_t payload[RQFT_MAX_PAYLOAD];
    uint8_t expected[600];
    uint8_t actual[600];
    size_t payload_len = field_hex(line, "\"payload_hex\":", payload, sizeof(payload));
    size_t expected_len = field_hex(line, "\"encoded_hex\":", expected, sizeof(expected));
    unsigned int ftype = field_uint(line, "\"ftype\":");
    unsigned int sid = field_uint(line, "\"sid\":");
    unsigned int seq = field_uint(line, "\"seq\":");
    unsigned int flags = field_uint(line, "\"flags\":");

    size_t actual_len = 0u;
    CHECK_EQ_INT(rqft_frame_build((rqft_frame_type_t)ftype,
                                  (uint8_t)sid,
                                  (uint8_t)seq,
                                  (uint8_t)flags,
                                  payload,
                                  payload_len,
                                  actual,
                                  sizeof(actual),
                                  &actual_len),
                 RQFT_OK);
    CHECK_EQ_INT(actual_len, expected_len);
    CHECK(memcmp(actual, expected, expected_len) == 0);

    rqft_frame_parser_t parser;
    collected_events_t events;
    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    for (size_t i = 0u; i < expected_len; i++) {
        rqft_frame_parser_feed(&parser, expected + i, 1u, 1u, collect_event, &events);
    }

    CHECK_EQ_INT(events.frame_count, 1);
    if (events.frame_count == 1u) {
        check_frame_eq(&events.frames[0],
                       (rqft_frame_type_t)ftype,
                       (uint8_t)sid,
                       (uint8_t)seq,
                       (uint8_t)flags,
                       payload,
                       payload_len);
    }
    CHECK_EQ_INT(events.passthrough_len, 0);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->frames_ok, 1);
    (*seen)++;
}

static void test_vectors(void)
{
    FILE *file = fopen(RQFT_REPO_ROOT "/testvectors/frames.json", "r");
    CHECK(file != NULL);
    if (file == NULL) {
        return;
    }

    char line[1400];
    unsigned int seen = 0u;
    while (fgets(line, sizeof(line), file) != NULL) {
        run_vector_line(line, &seen);
    }
    fclose(file);
    CHECK_EQ_INT(seen, 6);
}

static size_t build_ack(uint8_t *wire, size_t wire_cap)
{
    size_t wire_len = 0u;
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ACK, 0x42u, 8u, 0u, NULL, 0u, wire, wire_cap, &wire_len),
                 RQFT_OK);
    return wire_len;
}

static void test_passthrough_before_frame(void)
{
    uint8_t wire[600];
    size_t wire_len = build_ack(wire, sizeof(wire));
    rqft_frame_parser_t parser;
    collected_events_t events;
    const uint8_t junk[] = {'R', 'Q', 'P', '?', '\r', '\n'};

    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, junk, sizeof(junk), 10u, collect_event, &events);
    rqft_frame_parser_feed(&parser, wire, wire_len, 10u, collect_event, &events);

    CHECK_EQ_INT(events.passthrough_len, sizeof(junk));
    CHECK(memcmp(events.passthrough, junk, sizeof(junk)) == 0);
    CHECK_EQ_INT(events.frame_count, 1);
    if (events.frame_count == 1u) {
        check_frame_eq(&events.frames[0], RQFT_FRAME_ACK, 0x42u, 8u, 0u, NULL, 0u);
    }
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->bytes_passthrough, sizeof(junk));
}

static void test_resync_after_junk_inside_frame(void)
{
    uint8_t wire[600];
    uint8_t corrupted[700];
    size_t wire_len = build_ack(wire, sizeof(wire));
    rqft_frame_parser_t parser;
    collected_events_t events;
    const uint8_t junk[] = {'J', 'U', 'N', 'K'};

    memcpy(corrupted, wire, wire_len - 1u);
    memcpy(corrupted + wire_len - 1u, junk, sizeof(junk));
    corrupted[wire_len - 1u + sizeof(junk)] = 0u;

    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, corrupted, wire_len + sizeof(junk), 20u, collect_event, &events);
    rqft_frame_parser_feed(&parser, wire, wire_len, 20u, collect_event, &events);

    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->frames_crc_fail, 1);
    CHECK_EQ_INT(events.frame_count, 1);
    CHECK_EQ_INT(events.passthrough_len, wire_len - 2u + sizeof(junk));
}

static void test_repeated_delimiters(void)
{
    const uint8_t reason[] = {0x02u};
    uint8_t wire[600];
    size_t wire_len = 0u;
    rqft_frame_parser_t parser;
    collected_events_t events;
    const uint8_t zeroes[] = {0u, 0u};

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ABORT,
                                  0x42u,
                                  0u,
                                  0u,
                                  reason,
                                  sizeof(reason),
                                  wire,
                                  sizeof(wire),
                                  &wire_len),
                 RQFT_OK);
    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, zeroes, sizeof(zeroes), 30u, collect_event, &events);
    rqft_frame_parser_feed(&parser, wire, wire_len, 30u, collect_event, &events);

    CHECK_EQ_INT(events.passthrough_len, 0);
    CHECK_EQ_INT(events.frame_count, 1);
    if (events.frame_count == 1u) {
        check_frame_eq(&events.frames[0], RQFT_FRAME_ABORT, 0x42u, 0u, 0u, reason, sizeof(reason));
    }
}

static void test_oversize_flushes_to_hunt(void)
{
    uint8_t wire[600];
    size_t wire_len = build_ack(wire, sizeof(wire));
    rqft_frame_parser_t parser;
    collected_events_t events;
    uint8_t byte = 0x11u;
    uint8_t zero = 0u;

    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, &zero, 1u, 40u, collect_event, &events);
    for (size_t i = 0u; i < RQFT_MAX_ENCODED + 1u; i++) {
        rqft_frame_parser_feed(&parser, &byte, 1u, 40u, collect_event, &events);
    }
    rqft_frame_parser_feed(&parser, wire, wire_len, 40u, collect_event, &events);

    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->frames_oversize, 1);
    CHECK_EQ_INT(events.passthrough_len, RQFT_MAX_ENCODED + 1u);
    CHECK_EQ_INT(events.frame_count, 1);
    CHECK_EQ_INT(rqft_frame_parser_state(&parser), RQFT_FRAME_PARSER_FRAME);
}

static void test_idle_flush(void)
{
    rqft_frame_parser_t parser;
    collected_events_t events;
    const uint8_t partial[] = {0u, 'a', 'b', 'c'};

    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, partial, sizeof(partial), 100u, collect_event, &events);
    rqft_frame_parser_flush_idle(&parser, 149u, collect_event, &events);
    CHECK_EQ_INT(events.passthrough_len, 0);

    rqft_frame_parser_flush_idle(&parser, 150u, collect_event, &events);
    CHECK_EQ_INT(events.passthrough_len, 3);
    CHECK(memcmp(events.passthrough, "abc", 3u) == 0);
    CHECK_EQ_INT(rqft_frame_parser_state(&parser), RQFT_FRAME_PARSER_HUNT);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->candidates_idle_flushed, 1);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->valid_candidates_idle_flushed, 0);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->bytes_idle_flushed, 3);
}

static void test_valid_candidate_missing_trailing_delimiter_diagnosed(void)
{
    rqft_frame_parser_t parser;
    collected_events_t events;
    uint8_t wire[600];
    const uint8_t payload[] = {0x22u, 'd', 'a', 't', 'a'};
    size_t wire_len = 0u;

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_DATA,
                                  0x42u,
                                  7u,
                                  0u,
                                  payload,
                                  sizeof(payload),
                                  wire,
                                  sizeof(wire),
                                  &wire_len),
                 RQFT_OK);
    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);

    rqft_frame_parser_feed(&parser, wire, wire_len - 1u, 100u, collect_event, &events);
    rqft_frame_parser_flush_idle(&parser, 150u, collect_event, &events);

    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->candidates_idle_flushed, 1);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->valid_candidates_idle_flushed, 1);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->bytes_idle_flushed, wire_len - 2u);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->bytes_passthrough, wire_len - 2u);
}

static void test_active_parser_keeps_candidate_across_idle_gap(void)
{
    rqft_frame_parser_t parser;
    collected_events_t events;
    uint8_t wire[600];
    const uint8_t payload[] = {0x22u, 'd', 'a', 't', 'a'};
    size_t wire_len = 0u;
    uint32_t deadline = 0u;

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_DATA,
                                  0x42u,
                                  7u,
                                  0u,
                                  payload,
                                  sizeof(payload),
                                  wire,
                                  sizeof(wire),
                                  &wire_len),
                 RQFT_OK);
    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_set_session_active(&parser, true);

    rqft_frame_parser_feed(&parser, wire, wire_len - 1u, 100u, collect_event, &events);
    rqft_frame_parser_flush_idle(&parser, 150u, collect_event, &events);
    CHECK(!rqft_frame_parser_next_flush(&parser, &deadline));
    rqft_frame_parser_feed(&parser, wire + wire_len - 1u, 1u, 151u, collect_event, &events);

    CHECK_EQ_INT(events.frame_count, 1);
    CHECK_EQ_INT(events.frames[0].type, RQFT_FRAME_DATA);
    CHECK_EQ_INT(events.frames[0].seq, 7u);
    CHECK_EQ_INT(events.frames[0].payload_len, sizeof(payload));
    CHECK(memcmp(events.frames[0].payload, payload, sizeof(payload)) == 0);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->candidates_idle_flushed, 0);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->bytes_idle_flushed, 0);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->bytes_dropped_in_session, 0);
}

static void test_wrong_crc_and_unknown_type_counters(void)
{
    uint8_t bad_crc[600];
    uint8_t unknown[600];
    size_t bad_crc_len = build_raw_wire(0x04u, 0x42u, 8u, 0u, NULL, 0u, true, bad_crc, sizeof(bad_crc));
    size_t unknown_len = build_raw_wire(0x99u, 0x42u, 0u, 0u, NULL, 0u, false, unknown, sizeof(unknown));
    rqft_frame_parser_t parser;
    collected_events_t events;

    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, bad_crc, bad_crc_len, 200u, collect_event, &events);
    rqft_frame_parser_feed(&parser, unknown, unknown_len, 200u, collect_event, &events);

    CHECK_EQ_INT(events.frame_count, 0);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->frames_crc_fail, 1);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->frames_dropped, 1);
}

static void test_session_active_drops_passthrough(void)
{
    rqft_frame_parser_t parser;
    collected_events_t events;
    const uint8_t text[] = {'t', 'e', 'x', 't'};

    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_set_session_active(&parser, true);
    rqft_frame_parser_feed(&parser, text, sizeof(text), 1u, collect_event, &events);

    CHECK_EQ_INT(events.passthrough_len, 0);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->bytes_passthrough, 0);
    CHECK_EQ_INT(rqft_frame_parser_diag(&parser)->bytes_dropped_in_session, sizeof(text));
}

int main(void)
{
    test_vectors();
    test_passthrough_before_frame();
    test_resync_after_junk_inside_frame();
    test_repeated_delimiters();
    test_oversize_flushes_to_hunt();
    test_idle_flush();
    test_valid_candidate_missing_trailing_delimiter_diagnosed();
    test_active_parser_keeps_candidate_across_idle_gap();
    test_wrong_crc_and_unknown_type_counters();
    test_session_active_drops_passthrough();
    TEST_MAIN_END();
}
