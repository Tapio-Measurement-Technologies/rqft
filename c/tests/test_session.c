// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session.c - session handshake tests for SPEC.md sections 4.2, 5.1, 5.2. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

#define WIRE_CAP 8192u
#define MAX_CHUNKS 64u
#define MAX_EVENTS 64u
#define PASSTHROUGH_CAP 256u

typedef struct session_log {
    uint8_t wire[WIRE_CAP];
    size_t wire_len;
    size_t chunk_off[MAX_CHUNKS];
    size_t chunk_len[MAX_CHUNKS];
    size_t chunk_count;
    rqft_session_event_type_t event_types[MAX_EVENTS];
    rqft_session_established_t established[MAX_EVENTS];
    rqft_session_ended_t ended[MAX_EVENTS];
    uint32_t notify_flags[MAX_EVENTS];
    size_t event_count;
    uint8_t passthrough[PASSTHROUGH_CAP];
    size_t passthrough_len;
} session_log_t;

static void log_transmit(void *user, const uint8_t *wire, size_t wire_len)
{
    session_log_t *log = (session_log_t *)user;
    CHECK(log->chunk_count < MAX_CHUNKS);
    CHECK(log->wire_len + wire_len <= WIRE_CAP);
    memcpy(log->wire + log->wire_len, wire, wire_len);
    log->chunk_off[log->chunk_count] = log->wire_len;
    log->chunk_len[log->chunk_count] = wire_len;
    log->wire_len += wire_len;
    log->chunk_count++;
}

static void log_event(void *user, const rqft_session_event_t *event)
{
    session_log_t *log = (session_log_t *)user;
    CHECK(log->event_count < MAX_EVENTS);
    log->event_types[log->event_count] = event->type;
    if (event->type == RQFT_SESSION_EVENT_ESTABLISHED) {
        log->established[log->event_count] = event->u.established;
    } else if (event->type == RQFT_SESSION_EVENT_ENDED) {
        log->ended[log->event_count] = event->u.ended;
    } else if (event->type == RQFT_SESSION_EVENT_NOTIFY) {
        log->notify_flags[log->event_count] = event->u.notify.flags;
    } else {
        CHECK(log->passthrough_len + event->u.passthrough.len <= PASSTHROUGH_CAP);
        memcpy(log->passthrough + log->passthrough_len,
               event->u.passthrough.data, event->u.passthrough.len);
        log->passthrough_len += event->u.passthrough.len;
    }
    log->event_count++;
}

/* Sid source yielding successive values from a caller array. */
typedef struct sid_seq {
    uint8_t values[4];
    size_t next;
} sid_seq_t;

static uint8_t next_sid(void *user)
{
    sid_seq_t *seq = (sid_seq_t *)user;
    CHECK(seq->next < 4u);
    return seq->values[seq->next++];
}

static void session_setup(rqft_session_t *session,
                          session_log_t *log,
                          sid_seq_t *sids,
                          rqft_role_t role,
                          uint8_t ver_min,
                          uint8_t ver_max,
                          uint16_t max_payload,
                          uint8_t window,
                          uint8_t caps)
{
    rqft_session_config_t config;
    memset(log, 0, sizeof(*log));
    memset(&config, 0, sizeof(config));
    config.role = role;
    config.ver_min = ver_min;
    config.ver_max = ver_max;
    config.max_payload = max_payload;
    config.window = window;
    config.caps = caps;
    config.next_sid = next_sid;
    config.sid_user = sids;
    config.transmit = log_transmit;
    config.transmit_user = log;
    config.on_event = log_event;
    config.event_user = log;
    CHECK_EQ_INT(rqft_session_init(session, &config), RQFT_OK);
}

/* Decode one logged wire chunk back into a frame for inspection. */
static void chunk_frame(const session_log_t *log, size_t chunk, rqft_frame_t *frame)
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
    frame->type = (rqft_frame_type_t)decoded[0];
    frame->sid = decoded[1];
    frame->seq = decoded[2];
    frame->flags = decoded[3];
    frame->payload_len = decoded_len - 8u;
    memcpy(frame->payload, decoded + 4u, frame->payload_len);
}

static size_t hello_wire(uint8_t sid,
                         rqft_role_t role,
                         uint8_t ver_min,
                         uint8_t ver_max,
                         uint16_t max_payload,
                         uint8_t window,
                         uint8_t caps,
                         uint8_t *out,
                         size_t out_cap)
{
    rqft_hello_t hello;
    uint8_t body[RQFT_HELLO_BODY_LEN];
    size_t wire_len = 0u;
    hello.ver_min = ver_min;
    hello.ver_max = ver_max;
    hello.role = role;
    hello.max_payload = max_payload;
    hello.window = window;
    hello.caps = caps;
    CHECK_EQ_INT(rqft_hello_encode(&hello, body), RQFT_OK);
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_HELLO, sid, 0u, 0u, body, sizeof(body),
                                  out, out_cap, &wire_len),
                 RQFT_OK);
    return wire_len;
}

static size_t hello_ok_wire(uint8_t sid,
                            rqft_role_t role,
                            uint8_t ver,
                            uint16_t max_payload,
                            uint8_t window,
                            uint8_t caps,
                            uint8_t *out,
                            size_t out_cap)
{
    rqft_hello_ok_t ok;
    uint8_t body[RQFT_HELLO_BODY_LEN];
    size_t wire_len = 0u;
    ok.ver = ver;
    ok.role = role;
    ok.max_payload = max_payload;
    ok.window = window;
    ok.caps = caps;
    CHECK_EQ_INT(rqft_hello_ok_encode(&ok, body), RQFT_OK);
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_HELLO_OK, sid, 0u, 0u, body, sizeof(body),
                                  out, out_cap, &wire_len),
                 RQFT_OK);
    return wire_len;
}

static size_t abort_wire(uint8_t sid, rqft_abort_reason_t reason, uint8_t *out, size_t out_cap)
{
    uint8_t payload = (uint8_t)reason;
    size_t wire_len = 0u;
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ABORT, sid, 0u, 0u, &payload, 1u,
                                  out, out_cap, &wire_len),
                 RQFT_OK);
    return wire_len;
}

static void default_setup(rqft_session_t *session,
                          session_log_t *log,
                          sid_seq_t *sids,
                          rqft_role_t role)
{
    session_setup(session, log, sids, role, 1u, 1u, 512u, 4u, 0u);
}

static void test_config_initializer_defaults(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    rqft_session_config_t config;

    memset(&config, 0xa5, sizeof(config));
    rqft_session_config_init(&config, RQFT_ROLE_RESPONDER);

    CHECK_EQ_INT(config.role, RQFT_ROLE_RESPONDER);
    CHECK_EQ_INT(config.ver_min, RQFT_PROTOCOL_VERSION);
    CHECK_EQ_INT(config.ver_max, RQFT_PROTOCOL_VERSION);
    CHECK_EQ_INT(config.max_payload, RQFT_MAX_PAYLOAD);
    CHECK_EQ_INT(config.window, RQFT_WINDOW_MAX);
    CHECK_EQ_INT(config.caps, 0);
    CHECK(config.next_sid == NULL);
    CHECK(config.sid_user == NULL);
    CHECK(config.transmit == NULL);
    CHECK(config.transmit_user == NULL);
    CHECK(config.on_event == NULL);
    CHECK(config.event_user == NULL);
    CHECK(config.fs == NULL);
    CHECK(config.fs_user == NULL);

    memset(&log, 0, sizeof(log));
    config.next_sid = next_sid;
    config.sid_user = &sids;
    config.transmit = log_transmit;
    config.transmit_user = &log;
    config.on_event = log_event;
    config.event_user = &log;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_OK);
}

static void test_config_validation(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    rqft_session_config_t config;

    memset(&log, 0, sizeof(log));
    memset(&config, 0, sizeof(config));
    config.role = RQFT_ROLE_CONTROLLER;
    config.ver_min = 1u;
    config.ver_max = 1u;
    config.max_payload = 512u;
    config.window = 4u;
    config.next_sid = next_sid;
    config.sid_user = &sids;
    config.transmit = log_transmit;
    config.transmit_user = &log;
    config.on_event = log_event;
    config.event_user = &log;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_OK);

    config.ver_min = 2u;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
    config.ver_min = 1u;

    config.max_payload = 0u;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
    config.max_payload = 513u;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
    config.max_payload = 512u;

    config.window = 0u;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
    config.window = 9u;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
    config.window = 4u;

    config.caps = 0x02u;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
    config.caps = 0u;

    config.next_sid = NULL;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
    config.next_sid = next_sid;

    config.transmit = NULL;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
    config.transmit = log_transmit;

    config.on_event = NULL;
    CHECK_EQ_INT(rqft_session_init(&session, &config), RQFT_ERR_MALFORMED);
}

static void test_zero_sid_source_fails_start(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0u, 0u, 0u, 0u}, 0u};

    default_setup(&session, &log, &sids, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(rqft_session_start(&session, 0u), RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_IDLE);
}

static void test_transmit_callback_receives_complete_wire_frame(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t expected[64];
    size_t expected_len;

    default_setup(&session, &log, &sids, RQFT_ROLE_CONTROLLER);
    expected_len = hello_wire(0x42u, RQFT_ROLE_CONTROLLER, 1u, 1u, 512u, 4u,
                              0u, expected, sizeof(expected));

    CHECK_EQ_INT(rqft_session_start(&session, 0u), RQFT_OK);

    CHECK_EQ_INT(log.chunk_count, 1);
    CHECK_EQ_INT(log.chunk_len[0], expected_len);
    CHECK_EQ_INT(log.wire[0], 0);
    CHECK_EQ_INT(log.wire[expected_len - 1u], 0);
    CHECK(memcmp(log.wire, expected, expected_len) == 0);
}

static void test_initiator_happy_path_negotiates_minimums(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;
    rqft_frame_t frame;
    rqft_hello_t hello;

    default_setup(&session, &log, &sids, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(rqft_session_start(&session, 0u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_HELLO_SENT);

    CHECK_EQ_INT(log.chunk_count, 1);
    chunk_frame(&log, 0u, &frame);
    CHECK_EQ_INT(frame.type, RQFT_FRAME_HELLO);
    CHECK_EQ_INT(frame.sid, 0x42);
    CHECK_EQ_INT(rqft_hello_decode(frame.payload, frame.payload_len, &hello), RQFT_OK);
    CHECK_EQ_INT(hello.role, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(hello.max_payload, 512);
    CHECK_EQ_INT(hello.window, 4);

    wire_len = hello_ok_wire(0x42u, RQFT_ROLE_RESPONDER, 1u, 256u, 2u, 1u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 200u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_SESSION_EVENT_ESTABLISHED);
    CHECK_EQ_INT(log.established[0].sid, 0x42);
    CHECK_EQ_INT(log.established[0].version, 1);
    CHECK_EQ_INT(log.established[0].role, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(log.established[0].max_payload, 256);
    CHECK_EQ_INT(log.established[0].window, 2);
    CHECK_EQ_INT(log.established[0].peer_caps, 1);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_ACTIVE);
    CHECK(rqft_session_active(&session));

    CHECK_EQ_INT(rqft_session_start(&session, 300u), RQFT_ERR_MALFORMED);
}

static void test_replier_happy_path_answers_hello_ok(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;
    rqft_frame_t frame;
    rqft_hello_ok_t ok;

    session_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER, 1u, 1u, 512u, 4u,
                  RQFT_CAP_ALLOW_DELETE);
    wire_len = hello_wire(0x37u, RQFT_ROLE_CONTROLLER, 1u, 1u, 128u, 8u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 10u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_SESSION_EVENT_ESTABLISHED);
    CHECK_EQ_INT(log.established[0].sid, 0x37);
    CHECK_EQ_INT(log.established[0].role, RQFT_ROLE_RESPONDER);
    CHECK_EQ_INT(log.established[0].max_payload, 128);
    CHECK_EQ_INT(log.established[0].window, 4);
    CHECK_EQ_INT(log.established[0].peer_caps, 0);

    CHECK_EQ_INT(log.chunk_count, 1);
    chunk_frame(&log, 0u, &frame);
    CHECK_EQ_INT(frame.type, RQFT_FRAME_HELLO_OK);
    CHECK_EQ_INT(frame.sid, 0x37);
    CHECK_EQ_INT(rqft_hello_ok_decode(frame.payload, frame.payload_len, &ok), RQFT_OK);
    CHECK_EQ_INT(ok.role, RQFT_ROLE_RESPONDER);
    CHECK_EQ_INT(ok.max_payload, 512);
    CHECK_EQ_INT(ok.caps, RQFT_CAP_ALLOW_DELETE);
}

static void test_doorbell_roles_and_steady_state(void)
{
    rqft_session_t device;
    rqft_session_t host;
    session_log_t device_log;
    session_log_t host_log;
    sid_seq_t device_sids = {{0x51u, 0u, 0u, 0u}, 0u};
    sid_seq_t host_sids = {{0x99u, 0u, 0u, 0u}, 0u};

    session_setup(&device, &device_log, &device_sids, RQFT_ROLE_RESPONDER, 1u, 1u, 512u, 4u,
                  RQFT_CAP_ALLOW_DELETE);
    default_setup(&host, &host_log, &host_sids, RQFT_ROLE_CONTROLLER);

    CHECK_EQ_INT(rqft_session_start(&device, 0u), RQFT_OK);
    rqft_session_receive(&host, device_log.wire, device_log.wire_len, 5u);
    rqft_session_receive(&device, host_log.wire, host_log.wire_len, 10u);

    CHECK_EQ_INT(host_log.event_count, 1);
    CHECK_EQ_INT(host_log.event_types[0], RQFT_SESSION_EVENT_ESTABLISHED);
    CHECK_EQ_INT(host_log.established[0].sid, 0x51);
    CHECK_EQ_INT(host_log.established[0].role, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(host_log.established[0].peer_caps, RQFT_CAP_ALLOW_DELETE);

    CHECK_EQ_INT(device_log.event_count, 1);
    CHECK_EQ_INT(device_log.established[0].sid, 0x51);
    CHECK_EQ_INT(device_log.established[0].role, RQFT_ROLE_RESPONDER);
    CHECK(rqft_session_active(&device));
    CHECK(rqft_session_active(&host));
}

static void test_doorbell_then_notify(void)
{
    rqft_session_t device;
    rqft_session_t host;
    session_log_t device_log;
    session_log_t host_log;
    sid_seq_t device_sids = {{0x51u, 0u, 0u, 0u}, 0u};
    sid_seq_t host_sids = {{0x99u, 0u, 0u, 0u}, 0u};
    size_t wire_mark;

    session_setup(&device, &device_log, &device_sids, RQFT_ROLE_RESPONDER, 1u, 1u, 512u, 4u,
                  RQFT_CAP_ALLOW_DELETE);
    default_setup(&host, &host_log, &host_sids, RQFT_ROLE_CONTROLLER);

    CHECK_EQ_INT(rqft_session_start(&device, 0u), RQFT_OK);
    rqft_session_receive(&host, device_log.wire, device_log.wire_len, 5u);
    rqft_session_receive(&device, host_log.wire, host_log.wire_len, 10u);
    CHECK(rqft_session_active(&device));
    CHECK(rqft_session_active(&host));

    /* The established responder asks for an incremental pull mid-session. */
    wire_mark = device_log.wire_len;
    CHECK_EQ_INT(rqft_session_send_notify(&device, RQFT_NOTIFY_SYNC_INCREMENTAL, 20u),
                 RQFT_OK);
    rqft_session_receive(&host, device_log.wire + wire_mark,
                         device_log.wire_len - wire_mark, 20u);

    CHECK_EQ_INT(host_log.event_count, 2);
    CHECK_EQ_INT(host_log.event_types[1], RQFT_SESSION_EVENT_NOTIFY);
    CHECK_EQ_INT(host_log.notify_flags[1], RQFT_NOTIFY_SYNC_INCREMENTAL);
    CHECK(rqft_session_active(&device));
    CHECK(rqft_session_active(&host));
}

static void test_send_notify_rejects_misuse(void)
{
    rqft_session_t device;
    rqft_session_t host;
    session_log_t device_log;
    session_log_t host_log;
    sid_seq_t device_sids = {{0x51u, 0u, 0u, 0u}, 0u};
    sid_seq_t host_sids = {{0x99u, 0u, 0u, 0u}, 0u};

    session_setup(&device, &device_log, &device_sids, RQFT_ROLE_RESPONDER, 1u, 1u, 512u, 4u,
                  0u);
    default_setup(&host, &host_log, &host_sids, RQFT_ROLE_CONTROLLER);

    /* Not active yet. */
    CHECK_EQ_INT(rqft_session_send_notify(&device, 0u, 0u), RQFT_ERR_MALFORMED);

    CHECK_EQ_INT(rqft_session_start(&device, 0u), RQFT_OK);
    rqft_session_receive(&host, device_log.wire, device_log.wire_len, 5u);
    rqft_session_receive(&device, host_log.wire, host_log.wire_len, 10u);
    CHECK(rqft_session_active(&device));

    /* Controllers do not send NOTIFY. */
    CHECK_EQ_INT(rqft_session_send_notify(&host, 0u, 20u), RQFT_ERR_MALFORMED);

    /* Senders must zero undefined NOTIFY flag bits. */
    CHECK_EQ_INT(rqft_session_send_notify(&device, 0x04u, 20u), RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_send_notify(&device, 0x80000000u, 20u), RQFT_ERR_MALFORMED);
}

static void test_version_negotiation_picks_highest_common(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;
    rqft_frame_t frame;
    rqft_hello_ok_t ok;

    session_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER, 2u, 5u, 512u, 4u, 0u);
    wire_len = hello_wire(0x37u, RQFT_ROLE_CONTROLLER, 1u, 3u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 0u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.established[0].version, 3);
    chunk_frame(&log, 0u, &frame);
    CHECK_EQ_INT(rqft_hello_ok_decode(frame.payload, frame.payload_len, &ok), RQFT_OK);
    CHECK_EQ_INT(ok.ver, 3);
}

static void test_version_no_overlap_aborts_and_stays_idle(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;
    rqft_frame_t frame;

    session_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER, 2u, 3u, 512u, 4u, 0u);
    wire_len = hello_wire(0x37u, RQFT_ROLE_CONTROLLER, 1u, 1u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 0u);

    CHECK_EQ_INT(log.event_count, 0);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_IDLE);
    CHECK_EQ_INT(log.chunk_count, 1);
    chunk_frame(&log, 0u, &frame);
    CHECK_EQ_INT(frame.type, RQFT_FRAME_ABORT);
    CHECK_EQ_INT(frame.sid, 0x37);
    CHECK_EQ_INT(frame.payload[0], RQFT_ABORT_E_VERSION);

    /* The endpoint still accepts a compatible HELLO afterwards. */
    wire_len = hello_wire(0x38u, RQFT_ROLE_CONTROLLER, 2u, 2u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 10u);
    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_SESSION_EVENT_ESTABLISHED);
}

static void test_initiator_rejects_version_outside_range(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;
    rqft_frame_t frame;

    default_setup(&session, &log, &sids, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(rqft_session_start(&session, 0u), RQFT_OK);
    wire_len = hello_ok_wire(0x42u, RQFT_ROLE_RESPONDER, 7u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 10u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_SESSION_EVENT_ENDED);
    CHECK_EQ_INT(log.ended[0].reason, RQFT_ABORT_E_VERSION);
    CHECK(!log.ended[0].from_peer);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_ENDED);
    chunk_frame(&log, 1u, &frame);
    CHECK_EQ_INT(frame.type, RQFT_FRAME_ABORT);
    CHECK_EQ_INT(frame.payload[0], RQFT_ABORT_E_VERSION);
}

static void test_same_role_hello_rejected_with_e_proto(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;
    rqft_frame_t frame;

    default_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER);
    wire_len = hello_wire(0x37u, RQFT_ROLE_RESPONDER, 1u, 1u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 0u);

    CHECK_EQ_INT(log.event_count, 0);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_IDLE);
    chunk_frame(&log, 0u, &frame);
    CHECK_EQ_INT(frame.type, RQFT_FRAME_ABORT);
    CHECK_EQ_INT(frame.payload[0], RQFT_ABORT_E_PROTO);
}

static void test_initiator_abort_reply_ends_handshake(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;

    default_setup(&session, &log, &sids, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(rqft_session_start(&session, 0u), RQFT_OK);
    wire_len = abort_wire(0x42u, RQFT_ABORT_E_BUSY, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 10u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_SESSION_EVENT_ENDED);
    CHECK_EQ_INT(log.ended[0].reason, RQFT_ABORT_E_BUSY);
    CHECK(log.ended[0].from_peer);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_ENDED);
}

static void test_handshake_ignores_foreign_sid_replies(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;

    default_setup(&session, &log, &sids, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(rqft_session_start(&session, 0u), RQFT_OK);

    wire_len = hello_ok_wire(0x99u, RQFT_ROLE_RESPONDER, 1u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 10u);
    wire_len = abort_wire(0x99u, RQFT_ABORT_E_BUSY, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 11u);

    CHECK_EQ_INT(log.event_count, 0);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_HELLO_SENT);
}

static void test_hello_retry_schedule_and_giveup(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint32_t deadline = 0u;
    uint32_t now = 0u;
    size_t i;
    rqft_frame_t frame;

    default_setup(&session, &log, &sids, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(rqft_session_start(&session, 0u), RQFT_OK);
    CHECK(rqft_session_next_timeout(&session, &deadline));
    CHECK_EQ_INT(deadline, RQFT_T_HELLO_MS);

    while (log.event_count == 0u && now < 10000u) {
        now += RQFT_T_HELLO_MS;
        rqft_session_poll(&session, now - 1u);
        CHECK_EQ_INT(log.event_count, 0);
        rqft_session_poll(&session, now);
    }

    CHECK_EQ_INT(now, RQFT_N_HELLO * RQFT_T_HELLO_MS);
    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_SESSION_EVENT_ENDED);
    CHECK_EQ_INT(log.ended[0].reason, RQFT_ABORT_E_TIMEOUT);
    CHECK(!log.ended[0].from_peer);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_ENDED);

    /* Five HELLO attempts total and no ABORT frame: the failure is local. */
    CHECK_EQ_INT(log.chunk_count, RQFT_N_HELLO);
    for (i = 0u; i < log.chunk_count; i++) {
        chunk_frame(&log, i, &frame);
        CHECK_EQ_INT(frame.type, RQFT_FRAME_HELLO);
        CHECK_EQ_INT(frame.sid, 0x42);
    }
}

static void test_idempotent_hello_ok_resend(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;

    default_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER);
    wire_len = hello_wire(0x37u, RQFT_ROLE_CONTROLLER, 1u, 1u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 0u);
    CHECK_EQ_INT(log.chunk_count, 1);

    rqft_session_receive(&session, wire, wire_len, 600u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.chunk_count, 2);
    CHECK_EQ_INT(log.chunk_len[0], log.chunk_len[1]);
    CHECK(memcmp(log.wire + log.chunk_off[0], log.wire + log.chunk_off[1],
                 log.chunk_len[0]) == 0);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_ACTIVE);
}

static void test_busy_endpoint_aborts_new_sid_only(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;
    rqft_frame_t frame;

    default_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER);
    wire_len = hello_wire(0x37u, RQFT_ROLE_CONTROLLER, 1u, 1u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 0u);

    wire_len = hello_wire(0x99u, RQFT_ROLE_CONTROLLER, 1u, 1u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 10u);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_ACTIVE);
    CHECK_EQ_INT(log.chunk_count, 2);
    chunk_frame(&log, 1u, &frame);
    CHECK_EQ_INT(frame.type, RQFT_FRAME_ABORT);
    CHECK_EQ_INT(frame.sid, 0x99);
    CHECK_EQ_INT(frame.payload[0], RQFT_ABORT_E_BUSY);
}

static void test_collision_lower_sid_wins(void)
{
    rqft_session_t low;
    rqft_session_t high;
    session_log_t low_log;
    session_log_t high_log;
    sid_seq_t low_sids = {{0x10u, 0u, 0u, 0u}, 0u};
    sid_seq_t high_sids = {{0x20u, 0u, 0u, 0u}, 0u};
    uint8_t low_hello[64];
    size_t low_hello_len;

    default_setup(&low, &low_log, &low_sids, RQFT_ROLE_CONTROLLER);
    default_setup(&high, &high_log, &high_sids, RQFT_ROLE_RESPONDER);
    CHECK_EQ_INT(rqft_session_start(&low, 0u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_start(&high, 0u), RQFT_OK);
    low_hello_len = low_log.wire_len;
    memcpy(low_hello, low_log.wire, low_hello_len);

    /* The higher-sid endpoint abandons its own HELLO and answers. */
    rqft_session_receive(&high, low_hello, low_hello_len, 10u);
    CHECK_EQ_INT(high_log.event_count, 1);
    CHECK_EQ_INT(high_log.event_types[0], RQFT_SESSION_EVENT_ESTABLISHED);
    CHECK_EQ_INT(high_log.established[0].sid, 0x10);
    CHECK_EQ_INT(high_log.established[0].role, RQFT_ROLE_RESPONDER);

    /* The lower-sid endpoint ignores the crossing HELLO and wins. */
    rqft_session_receive(&low, high_log.wire, high_log.chunk_off[1], 11u);
    CHECK_EQ_INT(low_log.event_count, 0);
    CHECK_EQ_INT(rqft_session_state(&low), RQFT_SESSION_HELLO_SENT);
    rqft_session_receive(&low, high_log.wire + high_log.chunk_off[1],
                         high_log.chunk_len[1], 12u);
    CHECK_EQ_INT(low_log.event_count, 1);
    CHECK_EQ_INT(low_log.established[0].sid, 0x10);
    CHECK_EQ_INT(low_log.established[0].role, RQFT_ROLE_CONTROLLER);
}

static void test_collision_equal_sids_rerandomize_after_t_hello(void)
{
    rqft_session_t a;
    rqft_session_t b;
    session_log_t a_log;
    session_log_t b_log;
    sid_seq_t a_sids = {{0x42u, 0x11u, 0u, 0u}, 0u};
    sid_seq_t b_sids = {{0x42u, 0x33u, 0u, 0u}, 0u};
    uint8_t a_hello[64];
    uint8_t b_hello[64];
    size_t a_hello_len;
    size_t b_hello_len;
    uint32_t deadline = 0u;
    rqft_frame_t frame;

    default_setup(&a, &a_log, &a_sids, RQFT_ROLE_CONTROLLER);
    default_setup(&b, &b_log, &b_sids, RQFT_ROLE_RESPONDER);
    CHECK_EQ_INT(rqft_session_start(&a, 0u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_start(&b, 0u), RQFT_OK);
    a_hello_len = a_log.wire_len;
    memcpy(a_hello, a_log.wire, a_hello_len);
    b_hello_len = b_log.wire_len;
    memcpy(b_hello, b_log.wire, b_hello_len);

    /* Both abandon silently and stay quiet until T_HELLO passes. */
    rqft_session_receive(&a, b_hello, b_hello_len, 10u);
    rqft_session_receive(&b, a_hello, a_hello_len, 10u);
    CHECK_EQ_INT(a_log.chunk_count, 1);
    CHECK_EQ_INT(b_log.chunk_count, 1);
    CHECK(rqft_session_next_timeout(&a, &deadline));
    CHECK_EQ_INT(deadline, 10u + RQFT_T_HELLO_MS);

    rqft_session_poll(&a, 10u + RQFT_T_HELLO_MS);
    rqft_session_poll(&b, 10u + RQFT_T_HELLO_MS);
    CHECK_EQ_INT(a_log.chunk_count, 2);
    CHECK_EQ_INT(b_log.chunk_count, 2);
    chunk_frame(&a_log, 1u, &frame);
    CHECK_EQ_INT(frame.sid, 0x11);
    chunk_frame(&b_log, 1u, &frame);
    CHECK_EQ_INT(frame.sid, 0x33);

    /* The re-randomized handshake completes; 0x11 < 0x33 wins. */
    rqft_session_receive(&b, a_log.wire + a_log.chunk_off[1], a_log.chunk_len[1], 520u);
    CHECK_EQ_INT(b_log.event_count, 1);
    CHECK_EQ_INT(b_log.established[0].sid, 0x11);
    rqft_session_receive(&a, b_log.wire + b_log.chunk_off[2], b_log.chunk_len[2], 530u);
    CHECK_EQ_INT(a_log.event_count, 1);
    CHECK_EQ_INT(a_log.established[0].sid, 0x11);
    CHECK_EQ_INT(a_log.established[0].role, RQFT_ROLE_CONTROLLER);
}

static void test_passthrough_inactive_and_dropped_when_active(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;
    const char *text = "STATUS?\r\n";

    default_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER);
    rqft_session_receive(&session, (const uint8_t *)text, strlen(text), 0u);
    CHECK_EQ_INT(log.passthrough_len, strlen(text));
    CHECK(memcmp(log.passthrough, text, strlen(text)) == 0);

    wire_len = hello_wire(0x37u, RQFT_ROLE_CONTROLLER, 1u, 1u, 512u, 4u, 0u, wire, sizeof(wire));
    rqft_session_receive(&session, wire, wire_len, 10u);
    rqft_session_receive(&session, (const uint8_t *)text, strlen(text), 20u);
    CHECK_EQ_INT(log.passthrough_len, strlen(text));
}

static void test_receive_drains_pending_delimiter_before_poll(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t wire[64];
    size_t wire_len;

    default_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER);
    wire_len = hello_wire(0x37u, RQFT_ROLE_CONTROLLER, 1u, 1u, 512u, 4u, 0u,
                          wire, sizeof(wire));
    CHECK(wire_len >= 2u);

    rqft_session_receive(&session, wire, wire_len - 1u, 0u);
    CHECK_EQ_INT(log.event_count, 0);

    /* Transport RX must be drained before polling at the idle deadline. */
    rqft_session_receive(&session, wire + wire_len - 1u, 1u, RQFT_T_FLUSH_MS);
    rqft_session_poll(&session, RQFT_T_FLUSH_MS);

    CHECK_EQ_INT(log.event_count, 1);
    CHECK_EQ_INT(log.event_types[0], RQFT_SESSION_EVENT_ESTABLISHED);
    CHECK_EQ_INT(log.established[0].sid, 0x37);
    CHECK_EQ_INT(log.passthrough_len, 0);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_ACTIVE);
}

static void test_malformed_hello_body_dropped_silently(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint8_t body[RQFT_HELLO_BODY_LEN] = {1u, 1u, 7u, 0u, 2u, 4u, 0u, 0u};
    uint8_t wire[64];
    size_t wire_len = 0u;

    default_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER);
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_HELLO, 0x37u, 0u, 0u, body, sizeof(body),
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);
    rqft_session_receive(&session, wire, wire_len, 0u);

    CHECK_EQ_INT(log.event_count, 0);
    CHECK_EQ_INT(log.chunk_count, 0);
    CHECK_EQ_INT(rqft_session_state(&session), RQFT_SESSION_IDLE);
}

static void test_next_timeout_idle_is_none(void)
{
    rqft_session_t session;
    session_log_t log;
    sid_seq_t sids = {{0x42u, 0u, 0u, 0u}, 0u};
    uint32_t deadline = 0u;

    default_setup(&session, &log, &sids, RQFT_ROLE_RESPONDER);
    CHECK(!rqft_session_next_timeout(&session, &deadline));
}

int main(void)
{
    test_config_initializer_defaults();
    test_config_validation();
    test_zero_sid_source_fails_start();
    test_transmit_callback_receives_complete_wire_frame();
    test_initiator_happy_path_negotiates_minimums();
    test_replier_happy_path_answers_hello_ok();
    test_doorbell_roles_and_steady_state();
    test_doorbell_then_notify();
    test_send_notify_rejects_misuse();
    test_version_negotiation_picks_highest_common();
    test_version_no_overlap_aborts_and_stays_idle();
    test_initiator_rejects_version_outside_range();
    test_same_role_hello_rejected_with_e_proto();
    test_initiator_abort_reply_ends_handshake();
    test_handshake_ignores_foreign_sid_replies();
    test_hello_retry_schedule_and_giveup();
    test_idempotent_hello_ok_resend();
    test_busy_endpoint_aborts_new_sid_only();
    test_collision_lower_sid_wins();
    test_collision_equal_sids_rerandomize_after_t_hello();
    test_passthrough_inactive_and_dropped_when_active();
    test_receive_drains_pending_delimiter_before_poll();
    test_malformed_hello_body_dropped_silently();
    test_next_timeout_idle_is_none();
    TEST_MAIN_END();
}
