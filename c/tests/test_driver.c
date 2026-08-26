// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_driver.c - safe transport driver tests for C session integration. */
#include "rqft/driver.h"
#include "rqft/frame.h"
#include "rqft/message.h"
#include "test_support.h"

#include <stdint.h>

#define IO_CAP 8192u

typedef struct fake_io {
    uint8_t rx[IO_CAP];
    size_t rx_len;
    size_t rx_pos;
    size_t max_read;
    bool read_fails;
    size_t read_calls;
    uint8_t tx[IO_CAP];
    size_t tx_len;
    size_t max_write;
    size_t writes_before_stall;
    size_t write_calls;
    bool write_fails;
} fake_io_t;

typedef struct event_log {
    size_t established;
    uint8_t sid;
} event_log_t;

static ptrdiff_t fake_read(void *user, uint8_t *data, size_t cap)
{
    fake_io_t *io = (fake_io_t *)user;
    size_t remaining;
    size_t count;
    io->read_calls++;
    if (io->read_fails) {
        return -1;
    }
    remaining = io->rx_len - io->rx_pos;
    if (remaining == 0u) {
        return 0;
    }
    count = remaining < cap ? remaining : cap;
    if (io->max_read != 0u && count > io->max_read) {
        count = io->max_read;
    }
    memcpy(data, io->rx + io->rx_pos, count);
    io->rx_pos += count;
    return (ptrdiff_t)count;
}

static ptrdiff_t fake_write(void *user, const uint8_t *data, size_t len)
{
    fake_io_t *io = (fake_io_t *)user;
    size_t count = len;
    if (io->write_fails) {
        return -1;
    }
    if (io->write_calls >= io->writes_before_stall) {
        return 0;
    }
    if (io->max_write != 0u && count > io->max_write) {
        count = io->max_write;
    }
    CHECK(io->tx_len + count <= sizeof(io->tx));
    memcpy(io->tx + io->tx_len, data, count);
    io->tx_len += count;
    io->write_calls++;
    return (ptrdiff_t)count;
}

static uint8_t next_sid(void *)
{
    return 0x42u;
}

static void on_event(void *user, const rqft_session_event_t *event)
{
    event_log_t *log = (event_log_t *)user;
    if (event->type == RQFT_SESSION_EVENT_ESTABLISHED) {
        log->established++;
        log->sid = event->u.established.sid;
    }
}

static void count_frames(void *user, const rqft_frame_event_t *event)
{
    size_t *count = (size_t *)user;
    if (event->type == RQFT_FRAME_EVENT_FRAME) {
        (*count)++;
    }
}

static rqft_result_t setup_driver(rqft_session_driver_t *driver,
                                  fake_io_t *io,
                                  event_log_t *events,
                                  rqft_role_t role)
{
    rqft_session_config_t session_config;
    rqft_session_driver_config_t driver_config;
    memset(driver, 0, sizeof(*driver));
    memset(io, 0, sizeof(*io));
    memset(events, 0, sizeof(*events));
    memset(&driver_config, 0, sizeof(driver_config));
    io->writes_before_stall = SIZE_MAX;
    rqft_session_config_init(&session_config, role);
    session_config.next_sid = next_sid;
    session_config.on_event = on_event;
    session_config.event_user = events;
    driver_config.read = fake_read;
    driver_config.write = fake_write;
    driver_config.user = io;
    return rqft_session_driver_init(driver, &session_config, &driver_config);
}

static size_t hello_wire(uint8_t *wire, size_t cap)
{
    rqft_hello_t hello;
    uint8_t body[RQFT_HELLO_BODY_LEN];
    size_t wire_len = 0u;
    hello.ver_min = 1u;
    hello.ver_max = 1u;
    hello.role = RQFT_ROLE_CONTROLLER;
    hello.max_payload = RQFT_MAX_PAYLOAD;
    hello.window = 4u;
    hello.caps = 0u;
    CHECK_EQ_INT(rqft_hello_encode(&hello, body), RQFT_OK);
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_HELLO, 0x37u, 0u, 0u,
                                  body, sizeof(body), wire, cap, &wire_len),
                 RQFT_OK);
    return wire_len;
}

static void test_partial_writes_are_completed(void)
{
    rqft_session_driver_t driver;
    fake_io_t io;
    event_log_t events;
    rqft_frame_parser_t parser;
    size_t frame_count = 0u;

    CHECK_EQ_INT(setup_driver(&driver, &io, &events, RQFT_ROLE_CONTROLLER), RQFT_OK);
    io.max_write = 3u;

    CHECK_EQ_INT(rqft_session_driver_start(&driver, 0u), RQFT_OK);

    CHECK(io.write_calls > 1u);
    CHECK(io.tx_len > 2u);
    CHECK_EQ_INT(io.tx[0], 0);
    CHECK_EQ_INT(io.tx[io.tx_len - 1u], 0);
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, io.tx, io.tx_len, 0u, count_frames, &frame_count);
    CHECK_EQ_INT(frame_count, 1);
    CHECK_EQ_INT(rqft_session_driver_status(&driver), RQFT_OK);
}

static void test_rx_is_drained_before_idle_deadline_poll(void)
{
    rqft_session_driver_t driver;
    fake_io_t io;
    event_log_t events;
    rqft_session_t *session;
    uint8_t wire[64];
    size_t wire_len;

    CHECK_EQ_INT(setup_driver(&driver, &io, &events, RQFT_ROLE_RESPONDER), RQFT_OK);
    session = rqft_session_driver_session(&driver);
    wire_len = hello_wire(wire, sizeof(wire));
    CHECK(wire_len >= 2u);
    rqft_session_receive(session, wire, wire_len - 1u, 0u);
    io.rx[0] = wire[wire_len - 1u];
    io.rx_len = 1u;
    io.max_read = 1u;

    CHECK_EQ_INT(rqft_session_driver_poll(&driver, RQFT_T_FLUSH_MS), RQFT_OK);

    CHECK_EQ_INT(io.read_calls, 2);
    CHECK_EQ_INT(events.established, 1);
    CHECK_EQ_INT(events.sid, 0x37);
    CHECK_EQ_INT(rqft_session_state(session), RQFT_SESSION_ACTIVE);
}

static void test_transport_failures_are_sticky(void)
{
    rqft_session_driver_t driver;
    fake_io_t io;
    event_log_t events;

    CHECK_EQ_INT(setup_driver(&driver, &io, &events, RQFT_ROLE_CONTROLLER), RQFT_OK);
    io.write_fails = true;

    CHECK_EQ_INT(rqft_session_driver_start(&driver, 0u), RQFT_ERR_TRANSPORT);
    CHECK_EQ_INT(io.tx_len, 0);
    CHECK_EQ_INT(rqft_session_driver_status(&driver), RQFT_ERR_TRANSPORT);
    CHECK_EQ_INT(rqft_session_driver_poll(&driver, 1u), RQFT_ERR_TRANSPORT);
}

static void test_would_block_defers_tx_across_polls(void)
{
    rqft_session_driver_t driver;
    fake_io_t io;
    event_log_t events;
    rqft_frame_parser_t parser;
    size_t frame_count = 0u;
    size_t stalled_tx_len;

    CHECK_EQ_INT(setup_driver(&driver, &io, &events, RQFT_ROLE_CONTROLLER), RQFT_OK);
    io.max_write = 2u;
    io.writes_before_stall = 1u;

    /* Transport takes two bytes, then reports would-block. Not a failure. */
    CHECK_EQ_INT(rqft_session_driver_start(&driver, 0u), RQFT_OK);
    CHECK_EQ_INT(io.tx_len, 2);
    CHECK_EQ_INT(rqft_session_driver_status(&driver), RQFT_OK);
    stalled_tx_len = io.tx_len;

    /* Still stalled: polling makes no TX progress and reports no error. */
    CHECK_EQ_INT(rqft_session_driver_poll(&driver, 1u), RQFT_OK);
    CHECK_EQ_INT(io.tx_len, stalled_tx_len);

    /* Stall clears: next poll flushes the parked frame tail. */
    io.writes_before_stall = SIZE_MAX;
    CHECK_EQ_INT(rqft_session_driver_poll(&driver, 2u), RQFT_OK);
    CHECK(io.tx_len > stalled_tx_len);
    CHECK_EQ_INT(io.tx[0], 0);
    CHECK_EQ_INT(io.tx[io.tx_len - 1u], 0);
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, io.tx, io.tx_len, 0u, count_frames, &frame_count);
    CHECK_EQ_INT(frame_count, 1);
    CHECK_EQ_INT(rqft_session_driver_status(&driver), RQFT_OK);
}

static void test_backlog_overflow_drops_whole_frames(void)
{
    rqft_session_driver_t driver;
    fake_io_t io;
    event_log_t events;
    rqft_frame_parser_t parser;
    size_t frame_count = 0u;
    uint8_t wire[64];
    size_t wire_len;
    size_t round;

    CHECK_EQ_INT(setup_driver(&driver, &io, &events, RQFT_ROLE_RESPONDER), RQFT_OK);
    io.writes_before_stall = 0u;
    wire_len = hello_wire(wire, sizeof(wire));

    /* Stalled transport: every duplicate HELLO parks one more cached
     * HELLO_OK retransmission until the TX backlog overflows. */
    for (round = 0u; round < 16u && rqft_session_driver_tx_dropped(&driver) == 0u; round++) {
        size_t fed = 0u;
        io.rx_pos = 0u;
        io.rx_len = 0u;
        while (io.rx_len + wire_len <= sizeof(io.rx)) {
            memcpy(io.rx + io.rx_len, wire, wire_len);
            io.rx_len += wire_len;
            fed++;
        }
        CHECK(fed > 0u);
        CHECK_EQ_INT(rqft_session_driver_poll(&driver, 1u), RQFT_OK);
    }

    CHECK(rqft_session_driver_tx_dropped(&driver) > 0u);
    CHECK(rqft_session_driver_tx_pending(&driver) > 0u);
    CHECK_EQ_INT(rqft_session_driver_status(&driver), RQFT_OK);
    CHECK_EQ_INT(events.established, 1);

    /* Stall clears: backlog drains completely and every surviving frame is
     * intact, so overflow never put a truncated frame on the wire. */
    io.writes_before_stall = SIZE_MAX;
    io.rx_pos = 0u;
    io.rx_len = 0u;
    CHECK_EQ_INT(rqft_session_driver_poll(&driver, 2u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_driver_tx_pending(&driver), 0);
    rqft_frame_parser_init(&parser, RQFT_MAX_PAYLOAD);
    rqft_frame_parser_feed(&parser, io.tx, io.tx_len, 0u, count_frames, &frame_count);
    CHECK(frame_count > 0u);
    CHECK_EQ_INT(frame_count * (io.tx_len / frame_count), io.tx_len);
}

static void test_read_failure_stops_before_poll(void)
{
    rqft_session_driver_t driver;
    fake_io_t io;
    event_log_t events;

    CHECK_EQ_INT(setup_driver(&driver, &io, &events, RQFT_ROLE_RESPONDER), RQFT_OK);
    io.read_fails = true;

    CHECK_EQ_INT(rqft_session_driver_poll(&driver, 0u), RQFT_ERR_TRANSPORT);
    CHECK_EQ_INT(rqft_session_driver_status(&driver), RQFT_ERR_TRANSPORT);
}

int main(void)
{
    test_partial_writes_are_completed();
    test_rx_is_drained_before_idle_deadline_poll();
    test_transport_failures_are_sticky();
    test_would_block_defers_tx_across_polls();
    test_backlog_overflow_drops_whole_frames();
    test_read_failure_stops_before_poll();
    TEST_MAIN_END();
}
