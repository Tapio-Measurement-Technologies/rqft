// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session_abort.c - host-initiated session abort (SPEC.md section
 * 4.6): either role terminates with a best-effort ABORT frame. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

#define WIRE_CAP 8192u
#define SID 0x42u

/* ------------------------------------------------------------------ */
/* Event and wire logging                                              */

typedef struct session_log {
    uint8_t wire[WIRE_CAP];
    size_t wire_len;
    size_t consumed;
    size_t ended_events;
    rqft_abort_reason_t ended_reason;
    bool ended_from_peer;
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
    if (event->type == RQFT_SESSION_EVENT_ENDED) {
        log->ended_events++;
        log->ended_reason = event->u.ended.reason;
        log->ended_from_peer = event->u.ended.from_peer;
    }
}

/* ------------------------------------------------------------------ */
/* Minimal write-side fake filesystem                                  */

typedef struct fake_fs {
    bool writing;
    size_t discarded;
    size_t committed;
} fake_fs_t;

static bool fake_list_begin(void *user, const uint8_t *root, size_t root_len)
{
    (void)user;
    (void)root;
    (void)root_len;
    return false;
}

static int fake_list_next(void *user, rqft_fs_entry_t *entry)
{
    (void)user;
    (void)entry;
    return 0;
}

static void fake_list_close(void *user)
{
    (void)user;
}

static bool fake_open_read(void *user, const uint8_t *path, size_t path_len, uint32_t *size)
{
    (void)user;
    (void)path;
    (void)path_len;
    (void)size;
    return false;
}

static int fake_read(void *user, uint8_t *buf, size_t cap)
{
    (void)user;
    (void)buf;
    (void)cap;
    return -1;
}

static void fake_close_read(void *user)
{
    (void)user;
}

static bool fake_open_write(void *user, const uint8_t *path, size_t path_len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    (void)path;
    (void)path_len;
    fs->writing = true;
    return true;
}

static bool fake_write(void *user, const uint8_t *data, size_t len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    (void)data;
    (void)len;
    CHECK(fs->writing);
    return true;
}

static bool fake_commit(void *user)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    CHECK(fs->writing);
    fs->writing = false;
    fs->committed++;
    return true;
}

static void fake_discard(void *user)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    fs->writing = false;
    fs->discarded++;
}

static bool fake_remove_file(void *user, const uint8_t *path, size_t path_len)
{
    (void)user;
    (void)path;
    (void)path_len;
    return false;
}

static bool fake_remove_dir(void *user, const uint8_t *path, size_t path_len)
{
    (void)user;
    (void)path;
    (void)path_len;
    return false;
}

static bool fake_allow_delete(void *user, const uint8_t *path, size_t path_len)
{
    (void)user;
    (void)path;
    (void)path_len;
    return false;
}

static const rqft_fs_ops_t fake_ops = {
    fake_list_begin, fake_list_next, fake_list_close,
    fake_open_read, fake_read, fake_close_read,
    fake_open_write, fake_write, fake_commit, fake_discard,
    fake_remove_file, fake_remove_dir, fake_allow_delete,
};

/* ------------------------------------------------------------------ */
/* Session pair plumbing                                               */

static uint8_t fixed_sid(void *user)
{
    (void)user;
    return SID;
}

static void setup_endpoint(rqft_session_t *session,
                           session_log_t *log,
                           rqft_role_t role,
                           fake_fs_t *fs)
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
    if (fs != NULL) {
        config.fs = &fake_ops;
        config.fs_user = fs;
    }
    CHECK_EQ_INT(rqft_session_init(session, &config), RQFT_OK);
}

static void establish_pair(rqft_session_t *ctrl,
                           session_log_t *ctrl_log,
                           rqft_session_t *resp,
                           session_log_t *resp_log,
                           fake_fs_t *resp_fs)
{
    setup_endpoint(ctrl, ctrl_log, RQFT_ROLE_CONTROLLER, NULL);
    setup_endpoint(resp, resp_log, RQFT_ROLE_RESPONDER, resp_fs);
    CHECK_EQ_INT(rqft_session_start(ctrl, 0u), RQFT_OK);
    rqft_session_receive(resp, ctrl_log->wire, ctrl_log->wire_len, 0u);
    ctrl_log->consumed = ctrl_log->wire_len;
    rqft_session_receive(ctrl, resp_log->wire, resp_log->wire_len, 0u);
    resp_log->consumed = resp_log->wire_len;
    CHECK(rqft_session_active(ctrl));
    CHECK(rqft_session_active(resp));
}

/* Deliver everything an endpoint emitted since its last drain. */
static void drain_to(rqft_session_t *peer, session_log_t *src_log, uint32_t now_ms)
{
    size_t len = src_log->wire_len - src_log->consumed;
    if (len > 0u) {
        rqft_session_receive(peer, src_log->wire + src_log->consumed, len, now_ms);
        src_log->consumed = src_log->wire_len;
    }
}

/* Decode frame number index of the given type from a wire capture;
 * false when the capture holds fewer such frames. */
static bool nth_frame_of_type(const uint8_t *wire,
                              size_t wire_len,
                              rqft_frame_type_t type,
                              size_t index,
                              uint8_t *sid,
                              uint8_t *payload,
                              size_t *payload_len)
{
    size_t seen = 0u;
    size_t pos = 0u;
    while (pos < wire_len) {
        size_t start;
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
            decoded_len < 8u || decoded[0] != (uint8_t)type) {
            continue;
        }
        if (seen == index) {
            *sid = decoded[1];
            *payload_len = decoded_len - 8u;
            memcpy(payload, decoded + 4u, *payload_len);
            return true;
        }
        seen++;
    }
    return false;
}

/* Expect exactly one ABORT frame with the given reason since stream_start. */
static void check_single_abort_frame(const session_log_t *log,
                                     size_t stream_start,
                                     rqft_abort_reason_t reason)
{
    uint8_t sid = 0u;
    uint8_t payload[RQFT_MAX_PAYLOAD];
    size_t payload_len = 0u;
    CHECK(nth_frame_of_type(log->wire + stream_start, log->wire_len - stream_start,
                            RQFT_FRAME_ABORT, 0u, &sid, payload, &payload_len));
    CHECK_EQ_INT(sid, SID);
    CHECK_EQ_INT(payload_len, 1);
    CHECK_EQ_INT(payload[0], (uint8_t)reason);
    CHECK(!nth_frame_of_type(log->wire + stream_start, log->wire_len - stream_start,
                             RQFT_FRAME_ABORT, 1u, &sid, payload, &payload_len));
}

/* Craft one DATA frame carrying a session message, as a byte-exact peer
 * would. */
static size_t raw_msg_frame(uint8_t seq, const rqft_msg_t *msg, uint8_t *out, size_t out_cap)
{
    uint8_t payload[RQFT_MAX_PAYLOAD];
    size_t payload_len = 0u;
    size_t wire_len = 0u;
    CHECK_EQ_INT(rqft_msg_encode(msg, payload, sizeof(payload), &payload_len), RQFT_OK);
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_DATA, SID, seq, 0u, payload, payload_len,
                                  out, out_cap, &wire_len),
                 RQFT_OK);
    return wire_len;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */

static void test_responder_abort_sends_frame_and_ends_both_sides(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    size_t stream_start;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, NULL);
    stream_start = resp_log.consumed;

    rqft_session_abort(&resp, RQFT_ABORT_E_USER, 10u);

    check_single_abort_frame(&resp_log, stream_start, RQFT_ABORT_E_USER);
    CHECK_EQ_INT(rqft_session_state(&resp), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(!resp_log.ended_from_peer);

    drain_to(&ctrl, &resp_log, 10u);
    CHECK_EQ_INT(rqft_session_state(&ctrl), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(ctrl_log.ended_from_peer);
}

static void test_controller_abort_closes_cleanly(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    size_t stream_start;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, NULL);
    stream_start = ctrl_log.consumed;

    rqft_session_abort(&ctrl, RQFT_ABORT_CLOSE, 10u);

    check_single_abort_frame(&ctrl_log, stream_start, RQFT_ABORT_CLOSE);
    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_CLOSE);
    CHECK(!ctrl_log.ended_from_peer);

    drain_to(&resp, &ctrl_log, 10u);
    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_CLOSE);
    CHECK(resp_log.ended_from_peer);
}

static void test_abort_mid_put_discards_temp_file(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    rqft_msg_t msg;
    uint8_t wire[1024];
    size_t wire_len;
    uint8_t chunk[64];

    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &resp_fs);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PUT_REQ;
    msg.u.put_req.size = 1000u;
    msg.u.put_req.crc32 = 0xDEADBEEFu;
    msg.u.put_req.path = (const uint8_t *)"upload.bin";
    msg.u.put_req.path_len = 10u;
    wire_len = raw_msg_frame(0u, &msg, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 10u);
    CHECK(resp_fs.writing);

    memset(chunk, 0xA5, sizeof(chunk));
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_FILE_DATA;
    msg.u.file_data.data = chunk;
    msg.u.file_data.len = sizeof(chunk);
    wire_len = raw_msg_frame(1u, &msg, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 11u);
    CHECK(resp_fs.writing);

    rqft_session_abort(&resp, RQFT_ABORT_E_USER, 12u);

    CHECK(!resp_fs.writing);
    CHECK_EQ_INT(resp_fs.discarded, 1);
    CHECK_EQ_INT(resp_fs.committed, 0);
    CHECK_EQ_INT(rqft_session_state(&resp), RQFT_SESSION_ENDED);
}

static void test_abort_in_hello_sent_uses_offered_sid(void)
{
    rqft_session_t ctrl;
    session_log_t ctrl_log;
    size_t stream_start;

    setup_endpoint(&ctrl, &ctrl_log, RQFT_ROLE_CONTROLLER, NULL);
    CHECK_EQ_INT(rqft_session_start(&ctrl, 0u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_state(&ctrl), RQFT_SESSION_HELLO_SENT);
    stream_start = ctrl_log.wire_len;

    rqft_session_abort(&ctrl, RQFT_ABORT_E_USER, 5u);

    check_single_abort_frame(&ctrl_log, stream_start, RQFT_ABORT_E_USER);
    CHECK_EQ_INT(rqft_session_state(&ctrl), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(!ctrl_log.ended_from_peer);
}

static void test_abort_when_idle_or_ended_is_a_noop(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;

    setup_endpoint(&resp, &resp_log, RQFT_ROLE_RESPONDER, NULL);
    rqft_session_abort(&resp, RQFT_ABORT_E_USER, 0u);
    CHECK_EQ_INT(resp_log.wire_len, 0);
    CHECK_EQ_INT(resp_log.ended_events, 0);
    CHECK_EQ_INT(rqft_session_state(&resp), RQFT_SESSION_IDLE);

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, NULL);
    rqft_session_abort(&resp, RQFT_ABORT_E_USER, 10u);
    resp_log.consumed = resp_log.wire_len;

    rqft_session_abort(&resp, RQFT_ABORT_CLOSE, 11u);
    CHECK_EQ_INT(resp_log.wire_len, resp_log.consumed);
    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_USER);
}

static void test_aborted_session_refuses_further_traffic(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    rqft_msg_t msg;
    uint8_t wire[64];
    size_t wire_len;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, NULL);
    rqft_session_abort(&ctrl, RQFT_ABORT_E_USER, 10u);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 11u),
                 RQFT_ERR_MALFORMED);
    CHECK(!rqft_session_work_pending(&ctrl));

    /* A late peer frame must produce no reply from the dead endpoint. */
    ctrl_log.consumed = ctrl_log.wire_len;
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PING;
    msg.u.token.token = 7u;
    wire_len = raw_msg_frame(0u, &msg, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 12u);
    CHECK_EQ_INT(ctrl_log.wire_len, ctrl_log.consumed);
}

int main(void)
{
    test_responder_abort_sends_frame_and_ends_both_sides();
    test_controller_abort_closes_cleanly();
    test_abort_mid_put_discards_temp_file();
    test_abort_in_hello_sent_uses_offered_sid();
    test_abort_when_idle_or_ended_is_a_noop();
    test_aborted_session_refuses_further_traffic();
    TEST_MAIN_END();
}
