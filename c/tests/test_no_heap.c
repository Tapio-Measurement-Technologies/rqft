// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_no_heap.c - poisoned allocator gate for exercised library paths. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

void *__wrap_malloc(size_t size)
{
    (void)size;
    abort();
}

void *__wrap_calloc(size_t count, size_t size)
{
    (void)count;
    (void)size;
    abort();
}

void *__wrap_realloc(void *ptr, size_t size)
{
    (void)ptr;
    (void)size;
    abort();
}

void __wrap_free(void *ptr)
{
    (void)ptr;
    abort();
}

typedef struct no_heap_events {
    size_t frames;
    size_t passthrough;
} no_heap_events_t;

static void no_heap_emit(void *user, const rqft_frame_event_t *event)
{
    no_heap_events_t *events = (no_heap_events_t *)user;
    if (event->type == RQFT_FRAME_EVENT_FRAME) {
        events->frames++;
    } else if (event->type == RQFT_FRAME_EVENT_PASSTHROUGH) {
        events->passthrough += event->passthrough_len;
    }
}

typedef struct no_heap_link_log {
    size_t transmits;
    size_t deliveries;
    size_t aborts;
} no_heap_link_log_t;

typedef struct no_heap_driver_io {
    size_t writes;
    size_t bytes;
} no_heap_driver_io_t;

static ptrdiff_t no_heap_read(void *user, uint8_t *data, size_t cap)
{
    (void)user;
    (void)data;
    (void)cap;
    return 0;
}

static ptrdiff_t no_heap_write(void *user, const uint8_t *data, size_t len)
{
    no_heap_driver_io_t *io = (no_heap_driver_io_t *)user;
    (void)data;
    io->writes++;
    io->bytes += len;
    return (ptrdiff_t)len;
}

static uint8_t no_heap_next_sid(void *user)
{
    (void)user;
    return 0x42u;
}

static void no_heap_session_event(void *user, const rqft_session_event_t *event)
{
    (void)user;
    (void)event;
}

static void no_heap_transmit(void *user, const uint8_t *wire, size_t wire_len)
{
    (void)wire;
    (void)wire_len;
    ((no_heap_link_log_t *)user)->transmits++;
}

static void no_heap_link_event(void *user, const rqft_link_event_t *event)
{
    no_heap_link_log_t *log = (no_heap_link_log_t *)user;
    if (event->type == RQFT_LINK_EVENT_DELIVER) {
        log->deliveries++;
    } else {
        log->aborts++;
    }
}

/* Exercise link send/ACK/DATA/NAK/RTO/abort paths and the RTO estimator
 * under the poisoned allocator. */
static void exercise_link(void)
{
    rqft_link_t link;
    rqft_link_config_t config;
    no_heap_link_log_t log;
    rqft_frame_t frame;
    const uint8_t payload[] = {0x50u, 0x01u, 0x02u, 0x03u, 0x04u};

    memset(&log, 0, sizeof(log));
    memset(&config, 0, sizeof(config));
    config.sid = 0x42u;
    config.window = 4u;
    config.max_payload = RQFT_MAX_PAYLOAD;
    config.transmit = no_heap_transmit;
    config.transmit_user = &log;
    config.on_event = no_heap_link_event;
    config.event_user = &log;
    CHECK_EQ_INT(rqft_link_init(&link, &config), RQFT_OK);

    CHECK_EQ_INT(rqft_link_send(&link, payload, sizeof(payload), 0u), RQFT_OK);
    CHECK_EQ_INT(rqft_link_send(&link, payload, sizeof(payload), 0u), RQFT_OK);

    memset(&frame, 0, sizeof(frame));
    frame.type = RQFT_FRAME_ACK;
    frame.sid = 0x42u;
    frame.seq = 1u;
    frame.flags = 0x01u; /* progress + NAK go-back */
    rqft_link_on_frame(&link, &frame, 10u);

    rqft_link_poll(&link, 5000u); /* RTO expiry retransmission */

    memset(&frame, 0, sizeof(frame));
    frame.type = RQFT_FRAME_DATA;
    frame.sid = 0x42u;
    frame.seq = 0u;
    memcpy(frame.payload, payload, sizeof(payload));
    frame.payload_len = sizeof(payload);
    rqft_link_on_frame(&link, &frame, 20u);

    memset(&frame, 0, sizeof(frame));
    frame.type = RQFT_FRAME_ABORT;
    frame.sid = 0x42u;
    frame.payload[0] = RQFT_ABORT_E_USER;
    frame.payload_len = 1u;
    rqft_link_on_frame(&link, &frame, 30u);

    CHECK(log.transmits >= 5u);
    CHECK_EQ_INT(log.deliveries, 1);
    CHECK_EQ_INT(log.aborts, 1);
    CHECK_EQ_INT(rqft_link_state(&link), RQFT_LINK_DEAD);
}

/* Exercise safe driver construction, transmit, RX drain, and poll paths under
 * the poisoned allocator. */
static void exercise_driver(void)
{
    rqft_session_driver_t driver;
    rqft_session_config_t session_config;
    rqft_session_driver_config_t driver_config;
    no_heap_driver_io_t io;

    memset(&driver, 0, sizeof(driver));
    memset(&session_config, 0, sizeof(session_config));
    memset(&driver_config, 0, sizeof(driver_config));
    memset(&io, 0, sizeof(io));
    session_config.role = RQFT_ROLE_CONTROLLER;
    session_config.ver_min = RQFT_PROTOCOL_VERSION;
    session_config.ver_max = RQFT_PROTOCOL_VERSION;
    session_config.max_payload = RQFT_MAX_PAYLOAD;
    session_config.window = 4u;
    session_config.next_sid = no_heap_next_sid;
    session_config.on_event = no_heap_session_event;
    driver_config.read = no_heap_read;
    driver_config.write = no_heap_write;
    driver_config.user = &io;

    CHECK_EQ_INT(rqft_session_driver_init(&driver, &session_config, &driver_config), RQFT_OK);
    CHECK_EQ_INT(rqft_session_driver_start(&driver, 0u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_driver_poll(&driver, 1u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_driver_status(&driver), RQFT_OK);
    CHECK_EQ_INT(io.writes, 1);
    CHECK(io.bytes > 2u);
}

int main(void)
{
    const uint8_t payload[] = {0x10u, 0x01u, 0x00u};
    uint8_t encoded[600];
    uint8_t decoded[600];
    uint8_t wire[600];
    size_t encoded_len = 0u;
    size_t decoded_len = 0u;
    size_t wire_len = 0u;
    rqft_frame_parser_t parser;
    no_heap_events_t events;

    CHECK_EQ_INT(rqft_crc32(payload, sizeof(payload)), rqft_crc32_update(0u, payload, sizeof(payload)));
    CHECK_EQ_INT(rqft_cobs_encode(payload, sizeof(payload), encoded, sizeof(encoded), &encoded_len), RQFT_OK);
    CHECK_EQ_INT(rqft_cobs_decode(encoded, encoded_len, decoded, sizeof(decoded), &decoded_len), RQFT_OK);
    CHECK_EQ_INT(decoded_len, sizeof(payload));
    CHECK(memcmp(decoded, payload, sizeof(payload)) == 0);

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_DATA, 0x42u, 7u, 0u, payload, sizeof(payload),
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);

    memset(&events, 0, sizeof(events));
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, (const uint8_t *)"text", 4u, 1u, no_heap_emit, &events);
    rqft_frame_parser_feed(&parser, wire, wire_len, 1u, no_heap_emit, &events);
    CHECK_EQ_INT(events.passthrough, 4);
    CHECK_EQ_INT(events.frames, 1);

    exercise_link();
    exercise_driver();

    TEST_MAIN_END();
}
