// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session_misc.c - PLAN, NOTIFY, and forward-compatibility message
 * tests for SPEC.md sections 5.3-5.4. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

#define WIRE_CAP 4096u
#define SID 0x42u

/* ------------------------------------------------------------------ */
/* Event and wire logging                                              */

typedef struct session_log {
    uint8_t wire[WIRE_CAP];
    size_t wire_len;
    size_t consumed;
    size_t plan_events;
    uint16_t plan_nfiles;
    uint32_t plan_nbytes;
    size_t notify_events;
    uint32_t notify_flags;
    size_t ended_events;
} session_log_t;

static void log_transmit(void *user, const uint8_t *wire, size_t wire_len)
{
    session_log_t *log = (session_log_t *)user;
    CHECK(log->wire_len + wire_len <= WIRE_CAP);
    memcpy(log->wire + log->wire_len, wire, wire_len);
    log->wire_len += wire_len;
}

static void log_event(void *user, const rqft_session_event_t *event)
{
    session_log_t *log = (session_log_t *)user;
    switch (event->type) {
    case RQFT_SESSION_EVENT_PLAN:
        log->plan_events++;
        log->plan_nfiles = event->u.plan.nfiles;
        log->plan_nbytes = event->u.plan.nbytes;
        break;
    case RQFT_SESSION_EVENT_NOTIFY:
        log->notify_events++;
        log->notify_flags = event->u.notify.flags;
        break;
    case RQFT_SESSION_EVENT_ENDED:
        log->ended_events++;
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Session pair plumbing                                               */

static uint8_t fixed_sid(void *user)
{
    (void)user;
    return SID;
}

static void setup_endpoint(rqft_session_t *session,
                           session_log_t *log,
                           rqft_role_t role)
{
    rqft_session_config_t config;
    memset(log, 0, sizeof(*log));
    memset(&config, 0, sizeof(config));
    config.role = role;
    config.ver_min = 1u;
    config.ver_max = 1u;
    config.max_payload = 512u;
    config.window = 4u;
    config.next_sid = fixed_sid;
    config.transmit = log_transmit;
    config.transmit_user = log;
    config.on_event = log_event;
    config.event_user = log;
    CHECK_EQ_INT(rqft_session_init(session, &config), RQFT_OK);
}

static void establish_pair(rqft_session_t *ctrl,
                           session_log_t *ctrl_log,
                           rqft_session_t *resp,
                           session_log_t *resp_log)
{
    setup_endpoint(ctrl, ctrl_log, RQFT_ROLE_CONTROLLER);
    setup_endpoint(resp, resp_log, RQFT_ROLE_RESPONDER);
    CHECK_EQ_INT(rqft_session_start(ctrl, 0u), RQFT_OK);
    rqft_session_receive(resp, ctrl_log->wire, ctrl_log->wire_len, 0u);
    ctrl_log->consumed = ctrl_log->wire_len;
    rqft_session_receive(ctrl, resp_log->wire, resp_log->wire_len, 0u);
    resp_log->consumed = resp_log->wire_len;
    CHECK(rqft_session_active(ctrl));
    CHECK(rqft_session_active(resp));
}

/* Shuttle bytes and pending work until both endpoints go quiet. */
static void shuttle(rqft_session_t *ctrl,
                    session_log_t *ctrl_log,
                    rqft_session_t *resp,
                    session_log_t *resp_log,
                    uint32_t now_ms)
{
    for (int i = 0; i < 400; i++) {
        bool progressed = false;
        if (rqft_session_work_pending(ctrl)) {
            rqft_session_poll(ctrl, now_ms);
            progressed = true;
        }
        if (ctrl_log->wire_len > ctrl_log->consumed) {
            size_t len = ctrl_log->wire_len - ctrl_log->consumed;
            rqft_session_receive(resp, ctrl_log->wire + ctrl_log->consumed, len, now_ms);
            ctrl_log->consumed = ctrl_log->wire_len;
            progressed = true;
        }
        if (rqft_session_work_pending(resp)) {
            rqft_session_poll(resp, now_ms);
            progressed = true;
        }
        if (resp_log->wire_len > resp_log->consumed) {
            size_t len = resp_log->wire_len - resp_log->consumed;
            rqft_session_receive(ctrl, resp_log->wire + resp_log->consumed, len, now_ms);
            resp_log->consumed = resp_log->wire_len;
            progressed = true;
        }
        if (!progressed) {
            return;
        }
    }
    CHECK(false);
}

/* Craft one DATA frame carrying a raw payload, as a byte-exact peer would. */
static size_t raw_data_frame(uint8_t seq, const uint8_t *payload, size_t payload_len,
                             uint8_t *out, size_t out_cap)
{
    size_t wire_len = 0u;
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_DATA, SID, seq, 0u, payload, payload_len,
                                  out, out_cap, &wire_len),
                 RQFT_OK);
    return wire_len;
}

/* Decode DATA frame number index from a wire capture into a message;
 * false when the capture holds fewer DATA frames. */
static bool nth_data_message(const uint8_t *wire, size_t wire_len, size_t index, rqft_msg_t *msg)
{
    size_t seen = 0u;
    size_t pos = 0u;
    while (pos < wire_len) {
        size_t start = pos;
        while (pos < wire_len && wire[pos] == 0u) {
            pos++;
        }
        start = pos;
        while (pos < wire_len && wire[pos] != 0u) {
            pos++;
        }
        if (pos == start) {
            continue;
        }
        uint8_t decoded[4u + RQFT_MAX_PAYLOAD + 4u];
        size_t decoded_len = 0u;
        if (rqft_cobs_decode(wire + start, pos - start, decoded, sizeof(decoded),
                             &decoded_len) != RQFT_OK ||
            decoded_len < 8u || decoded[0] != RQFT_FRAME_DATA) {
            continue;
        }
        if (seen == index) {
            return rqft_msg_decode(decoded + 4u, decoded_len - 8u, msg) == RQFT_OK;
        }
        seen++;
    }
    return false;
}

/* Count DATA frames in a wire capture. */
static size_t count_data_messages(const uint8_t *wire, size_t wire_len)
{
    rqft_msg_t msg;
    size_t count = 0u;
    while (nth_data_message(wire, wire_len, count, &msg)) {
        count++;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */

static void test_plan_surfaces_totals_on_responder(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    size_t stream_start;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);
    stream_start = resp_log.consumed;

    CHECK_EQ_INT(rqft_session_send_plan(&ctrl, 3u, 12345u, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(resp_log.plan_events, 1);
    CHECK_EQ_INT(resp_log.plan_nfiles, 3);
    CHECK_EQ_INT(resp_log.plan_nbytes, 12345);
    /* PLAN is informative: the responder answers nothing. */
    CHECK_EQ_INT(count_data_messages(resp_log.wire + stream_start,
                                     resp_log.wire_len - stream_start),
                 0);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_plan_does_not_occupy_the_operation_slot(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    CHECK_EQ_INT(rqft_session_send_plan(&ctrl, 1u, 5u, 10u), RQFT_OK);
    /* The very next request must be accepted: PLAN holds no slot. */
    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(resp_log.plan_events, 1);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_plan_to_controller_answers_bad_state(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint8_t plan_payload[7] = {RQFT_MSG_PLAN, 1u, 0u, 2u, 0u, 0u, 0u};
    uint8_t wire[64];
    size_t wire_len;
    size_t stream_start;
    rqft_msg_t msg;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);
    stream_start = ctrl_log.consumed;

    wire_len = raw_data_frame(0u, plan_payload, sizeof(plan_payload), wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 10u);

    CHECK(nth_data_message(ctrl_log.wire + stream_start,
                           ctrl_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_BAD_STATE);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_PLAN);
    CHECK(rqft_session_active(&ctrl));
}

static void test_send_plan_validates_role_state_and_op(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    CHECK_EQ_INT(rqft_session_send_plan(&resp, 1u, 1u, 10u), RQFT_ERR_MALFORMED);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 10u),
                 RQFT_OK);
    CHECK_EQ_INT(rqft_session_send_plan(&ctrl, 1u, 1u, 11u), RQFT_ERR_MALFORMED);

    /* An idle endpoint refuses PLAN. */
    setup_endpoint(&ctrl, &ctrl_log, RQFT_ROLE_CONTROLLER);
    CHECK_EQ_INT(rqft_session_send_plan(&ctrl, 1u, 1u, 0u), RQFT_ERR_MALFORMED);
}

/* One endpoint fed an unknown msg_type between operations must answer
 * ERR(E_UNSUPPORTED, ref=that type) and stay active. */
static void check_unknown_answers_unsupported(rqft_session_t *session,
                                              session_log_t *log,
                                              const uint8_t *payload,
                                              size_t payload_len)
{
    uint8_t wire[64];
    size_t wire_len;
    size_t stream_start = log->wire_len;
    rqft_msg_t msg;

    wire_len = raw_data_frame(0u, payload, payload_len, wire, sizeof(wire));
    rqft_session_receive(session, wire, wire_len, 10u);

    CHECK(nth_data_message(log->wire + stream_start,
                           log->wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_UNSUPPORTED);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, payload[0]);
    CHECK(rqft_session_active(session));
}

static void test_unknown_msg_type_between_ops_answers_unsupported(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint8_t with_body[4] = {0x60u, 1u, 2u, 3u};
    uint8_t bare[1] = {0x61u};

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    check_unknown_answers_unsupported(&resp, &resp_log, with_body, sizeof(with_body));
    check_unknown_answers_unsupported(&ctrl, &ctrl_log, bare, sizeof(bare));
}

static void test_session_lives_after_unknown_msg_and_keeps_serving(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint8_t unknown[1] = {0x60u};
    uint8_t ping[5] = {RQFT_MSG_PING, 7u, 0u, 0u, 0u};
    uint8_t wire[64];
    size_t wire_len;
    size_t stream_start;
    rqft_msg_t msg;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    wire_len = raw_data_frame(0u, unknown, sizeof(unknown), wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 10u);
    stream_start = resp_log.wire_len;

    /* The next message on the stream is still served: PING echoes PONG. */
    wire_len = raw_data_frame(1u, ping, sizeof(ping), wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 11u);

    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PONG);
    CHECK_EQ_INT(msg.u.token.token, 7);
    CHECK(rqft_session_active(&resp));
}

static void test_notify_surfaces_flags_on_controller(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    size_t stream_start;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);
    stream_start = ctrl_log.consumed;

    CHECK_EQ_INT(rqft_session_send_notify(&resp, RQFT_NOTIFY_SYNC_INCREMENTAL, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.notify_events, 1);
    CHECK_EQ_INT(ctrl_log.notify_flags, RQFT_NOTIFY_SYNC_INCREMENTAL);
    /* NOTIFY is informative: the controller answers nothing. */
    CHECK_EQ_INT(count_data_messages(ctrl_log.wire + stream_start,
                                     ctrl_log.wire_len - stream_start),
                 0);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_notify_while_awaiting_op_reply_is_accepted(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint8_t notify_payload[5] = {RQFT_MSG_NOTIFY, 1u, 0u, 0u, 0u};
    uint8_t wire[64];
    size_t wire_len;
    size_t stream_start;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    /* The controller's LIST is in flight; NOTIFY must still surface
     * without an ERR and without disturbing the operation slot. */
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 10u), RQFT_OK);
    stream_start = ctrl_log.wire_len;
    wire_len = raw_data_frame(0u, notify_payload, sizeof(notify_payload), wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 11u);

    CHECK_EQ_INT(ctrl_log.notify_events, 1);
    CHECK_EQ_INT(ctrl_log.notify_flags, RQFT_NOTIFY_SYNC_INCREMENTAL);
    CHECK_EQ_INT(count_data_messages(ctrl_log.wire + stream_start,
                                     ctrl_log.wire_len - stream_start),
                 0);
    /* The operation slot is still held by the LIST. */
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 12u),
                 RQFT_ERR_MALFORMED);
    CHECK(rqft_session_active(&ctrl));
}

static void test_notify_to_responder_answers_bad_state(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint8_t notify_payload[5] = {RQFT_MSG_NOTIFY, 1u, 0u, 0u, 0u};
    uint8_t wire[64];
    size_t wire_len;
    size_t stream_start;
    rqft_msg_t msg;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);
    stream_start = resp_log.consumed;

    wire_len = raw_data_frame(0u, notify_payload, sizeof(notify_payload), wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 10u);

    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_BAD_STATE);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_NOTIFY);
    CHECK_EQ_INT(resp_log.notify_events, 0);
    CHECK(rqft_session_active(&resp));
}

int main(void)
{
    test_plan_surfaces_totals_on_responder();
    test_plan_does_not_occupy_the_operation_slot();
    test_plan_to_controller_answers_bad_state();
    test_send_plan_validates_role_state_and_op();
    test_unknown_msg_type_between_ops_answers_unsupported();
    test_session_lives_after_unknown_msg_and_keeps_serving();
    test_notify_surfaces_flags_on_controller();
    test_notify_while_awaiting_op_reply_is_accepted();
    test_notify_to_responder_answers_bad_state();
    TEST_MAIN_END();
}
