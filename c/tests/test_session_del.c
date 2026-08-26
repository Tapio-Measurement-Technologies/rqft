// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session_del.c - DEL operation tests for SPEC.md section 5.4. */
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
    size_t del_done_events;
    uint8_t del_done_path[RQFT_MAX_PATH];
    size_t del_done_path_len;
    bool del_done_is_dir;
    size_t op_failed_events;
    uint8_t op_failed_request;
    rqft_err_code_t op_failed_code;
    uint8_t op_failed_path[RQFT_MAX_PATH];
    size_t op_failed_path_len;
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
    case RQFT_SESSION_EVENT_DEL_DONE:
        log->del_done_events++;
        CHECK(event->u.del_done.path_len <= RQFT_MAX_PATH);
        memcpy(log->del_done_path, event->u.del_done.path, event->u.del_done.path_len);
        log->del_done_path_len = event->u.del_done.path_len;
        log->del_done_is_dir = event->u.del_done.is_dir;
        break;
    case RQFT_SESSION_EVENT_OP_FAILED:
        log->op_failed_events++;
        log->op_failed_request = event->u.op_failed.request;
        log->op_failed_code = event->u.op_failed.code;
        CHECK(event->u.op_failed.path_len <= RQFT_MAX_PATH);
        memcpy(log->op_failed_path, event->u.op_failed.path, event->u.op_failed.path_len);
        log->op_failed_path_len = event->u.op_failed.path_len;
        break;
    case RQFT_SESSION_EVENT_ENDED:
        log->ended_events++;
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* In-memory fake filesystem exposing only the delete callbacks        */

#define FAKE_MAX_FILES 8u

typedef struct fake_fs {
    char paths[FAKE_MAX_FILES][RQFT_MAX_PATH + 1u];
    size_t file_count;
    char deny_delete[RQFT_MAX_PATH + 1u];
    char fail_remove[RQFT_MAX_PATH + 1u];
} fake_fs_t;

static void fake_add(fake_fs_t *fs, const char *path)
{
    CHECK(fs->file_count < FAKE_MAX_FILES);
    strcpy(fs->paths[fs->file_count++], path);
}

static bool fake_has(const fake_fs_t *fs, const char *path)
{
    for (size_t i = 0u; i < fs->file_count; i++) {
        if (strcmp(fs->paths[i], path) == 0) {
            return true;
        }
    }
    return false;
}

static void fake_erase(fake_fs_t *fs, size_t index)
{
    fs->paths[index][0] = '\0';
    for (size_t i = index; i + 1u < fs->file_count; i++) {
        strcpy(fs->paths[i], fs->paths[i + 1u]);
    }
    fs->file_count--;
}

static bool path_matches(const char *stored, const uint8_t *path, size_t path_len)
{
    return strlen(stored) == path_len && memcmp(stored, path, path_len) == 0;
}

static bool fake_remove_file(void *user, const uint8_t *path, size_t path_len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    if (path_matches(fs->fail_remove, path, path_len)) {
        return false;
    }
    for (size_t i = 0u; i < fs->file_count; i++) {
        if (path_matches(fs->paths[i], path, path_len)) {
            fake_erase(fs, i);
            return true;
        }
    }
    return false;
}

static bool fake_remove_dir(void *user, const uint8_t *path, size_t path_len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    bool removed = false;
    if (path_matches(fs->fail_remove, path, path_len)) {
        return false;
    }
    for (size_t i = fs->file_count; i > 0u; i--) {
        const char *stored = fs->paths[i - 1u];
        if (strlen(stored) > path_len + 1u &&
            memcmp(stored, path, path_len) == 0 && stored[path_len] == '/') {
            fake_erase(fs, i - 1u);
            removed = true;
        }
    }
    return removed;
}

static bool fake_allow_delete(void *user, const uint8_t *path, size_t path_len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    return !path_matches(fs->deny_delete, path, path_len);
}

static const rqft_fs_ops_t fake_ops = {
    NULL, NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    fake_remove_file, fake_remove_dir, fake_allow_delete,
};

/* Same table with the delete callbacks missing. */
static const rqft_fs_ops_t deleteless_ops = {
    NULL, NULL, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
};

static void fake_fs_files(fake_fs_t *fs)
{
    memset(fs, 0, sizeof(*fs));
    fake_add(fs, "a.data");
    fake_add(fs, "logs/2025/run1.data");
    fake_add(fs, "logs/2025/run2.data");
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
                           rqft_role_t role,
                           const rqft_fs_ops_t *fs_ops,
                           void *fs_user,
                           uint8_t caps)
{
    rqft_session_config_t config;
    memset(log, 0, sizeof(*log));
    memset(&config, 0, sizeof(config));
    config.role = role;
    config.ver_min = 1u;
    config.ver_max = 1u;
    config.max_payload = 512u;
    config.window = 4u;
    config.caps = caps;
    config.next_sid = fixed_sid;
    config.transmit = log_transmit;
    config.transmit_user = log;
    config.on_event = log_event;
    config.event_user = log;
    config.fs = fs_ops;
    config.fs_user = fs_user;
    CHECK_EQ_INT(rqft_session_init(session, &config), RQFT_OK);
}

static void establish_pair(rqft_session_t *ctrl,
                           session_log_t *ctrl_log,
                           rqft_session_t *resp,
                           session_log_t *resp_log,
                           const rqft_fs_ops_t *resp_ops,
                           fake_fs_t *resp_fs,
                           uint8_t resp_caps)
{
    setup_endpoint(ctrl, ctrl_log, RQFT_ROLE_CONTROLLER, NULL, NULL, 0u);
    setup_endpoint(resp, resp_log, RQFT_ROLE_RESPONDER, resp_ops, resp_fs, resp_caps);
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

/* Craft one DATA frame carrying a message, as a byte-exact peer would. */
static size_t data_frame(uint8_t seq, const rqft_msg_t *msg, uint8_t *out, size_t out_cap)
{
    uint8_t payload[1u + RQFT_MAX_PAYLOAD];
    size_t payload_len = 0u;
    size_t wire_len = 0u;
    CHECK_EQ_INT(rqft_msg_encode(msg, payload, sizeof(payload), &payload_len), RQFT_OK);
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

/* The first reply after the capture offset must be ERR(code, ref). */
static void check_err_reply(const session_log_t *log, size_t stream_start,
                            rqft_err_code_t code, uint8_t ref)
{
    rqft_msg_t msg;
    CHECK(nth_data_message(log->wire + stream_start, log->wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, code);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, ref);
}

/* Feed the responder one crafted DEL_FILE or DEL_DIR. */
static void feed_del(rqft_session_t *resp, uint8_t seq, bool is_dir, const char *path,
                     uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    memset(&msg, 0, sizeof(msg));
    msg.type = is_dir ? RQFT_MSG_DEL_DIR : RQFT_MSG_DEL_FILE;
    msg.u.del_path.path = (const uint8_t *)path;
    msg.u.del_path.path_len = strlen(path);
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(resp, wire, wire_len, now_ms);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */

static void test_del_file_removes_file_and_reports_del_done(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    size_t stream_start;
    rqft_msg_t msg;

    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs,
                   RQFT_CAP_ALLOW_DELETE);
    stream_start = resp_log.consumed;

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.del_done_events, 1);
    CHECK_EQ_INT(ctrl_log.del_done_path_len, 6);
    CHECK(memcmp(ctrl_log.del_done_path, "a.data", 6u) == 0);
    CHECK(!ctrl_log.del_done_is_dir);
    CHECK(!fake_has(&resp_fs, "a.data"));
    CHECK(fake_has(&resp_fs, "logs/2025/run1.data"));
    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_DEL_OK);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_del_dir_removes_tree_recursively(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;

    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs,
                   RQFT_CAP_ALLOW_DELETE);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"logs", 4u, true, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.del_done_events, 1);
    CHECK(ctrl_log.del_done_is_dir);
    CHECK_EQ_INT(resp_fs.file_count, 1);
    CHECK(fake_has(&resp_fs, "a.data"));
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_del_denied_without_caps_bit(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;

    /* First gate: the responder never advertised ALLOW_DELETE, so even
     * a permissive per-request callback must not be consulted. */
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs, 0u);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request, RQFT_MSG_DEL_FILE);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_DENIED);
    CHECK_EQ_INT(ctrl_log.op_failed_path_len, 6);
    CHECK(memcmp(ctrl_log.op_failed_path, "a.data", 6u) == 0);
    CHECK(fake_has(&resp_fs, "a.data"));
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_del_denied_by_per_request_callback(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;

    /* Second gate: caps advertised, but the host refuses this path. */
    fake_fs_files(&resp_fs);
    strcpy(resp_fs.deny_delete, "logs");
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs,
                   RQFT_CAP_ALLOW_DELETE);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"logs", 4u, true, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request, RQFT_MSG_DEL_DIR);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_DENIED);
    CHECK_EQ_INT(resp_fs.file_count, 3);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

/* One remove failure must answer ERR(E_FS_REMOVE); the session lives. */
static void check_del_remove_failure(const char *path, bool is_dir)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;

    fake_fs_files(&resp_fs);
    strcpy(resp_fs.fail_remove, "a.data");
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs,
                   RQFT_CAP_ALLOW_DELETE);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)path, strlen(path),
                                          is_dir, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request,
                 is_dir ? RQFT_MSG_DEL_DIR : RQFT_MSG_DEL_FILE);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_REMOVE);
    CHECK_EQ_INT(resp_fs.file_count, 3);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_del_remove_failure_answers_fs_remove(void)
{
    check_del_remove_failure("a.data", false);
    check_del_remove_failure("nosuch.bin", false);
    check_del_remove_failure("nosuch", true);
}

static void test_failed_del_releases_slot_and_batch_continues(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;

    fake_fs_files(&resp_fs);
    strcpy(resp_fs.deny_delete, "a.data");
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs,
                   RQFT_CAP_ALLOW_DELETE);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);
    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_DENIED);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"logs", 4u, true, 20u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 20u);
    CHECK_EQ_INT(ctrl_log.del_done_events, 1);
    CHECK_EQ_INT(resp_fs.file_count, 1);
    CHECK(fake_has(&resp_fs, "a.data"));
}

static void test_responder_rejects_invalid_del_path_with_e_path(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    size_t stream_start;

    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs,
                   RQFT_CAP_ALLOW_DELETE);
    stream_start = resp_log.consumed;

    feed_del(&resp, 0u, false, "../up", 10u);

    check_err_reply(&resp_log, stream_start, RQFT_E_PATH, RQFT_MSG_DEL_FILE);
    CHECK(rqft_session_active(&resp));
}

static void test_responder_without_delete_callbacks_answers_unsupported(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    size_t stream_start;

    /* No filesystem table at all. */
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, NULL, NULL,
                   RQFT_CAP_ALLOW_DELETE);
    stream_start = resp_log.consumed;
    feed_del(&resp, 0u, false, "a.data", 10u);
    check_err_reply(&resp_log, stream_start, RQFT_E_UNSUPPORTED, RQFT_MSG_DEL_FILE);
    CHECK(rqft_session_active(&resp));

    /* A table missing the delete callbacks. */
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &deleteless_ops, NULL,
                   RQFT_CAP_ALLOW_DELETE);
    stream_start = resp_log.consumed;
    feed_del(&resp, 0u, true, "logs", 10u);
    check_err_reply(&resp_log, stream_start, RQFT_E_UNSUPPORTED, RQFT_MSG_DEL_DIR);
    CHECK(rqft_session_active(&resp));
}

static void test_wrong_message_while_awaiting_del_ok_answers_bad_state(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    size_t stream_start;

    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs,
                   RQFT_CAP_ALLOW_DELETE);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 10u),
                 RQFT_OK);
    stream_start = ctrl_log.wire_len;

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_END;
    msg.u.list_end.count = 0u;
    wire_len = data_frame(0u, &msg, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 10u);

    check_err_reply(&ctrl_log, stream_start, RQFT_E_BAD_STATE, RQFT_MSG_LIST_END);
    /* The operation is still in flight. */
    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"logs", 4u, true, 11u),
                 RQFT_ERR_MALFORMED);
}

static void test_request_del_validates_role_state_and_path(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;

    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fake_ops, &resp_fs,
                   RQFT_CAP_ALLOW_DELETE);

    CHECK_EQ_INT(rqft_session_request_del(&resp, (const uint8_t *)"a.data", 6u, false, 10u),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"../up", 5u, false, 10u),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_request_del(&ctrl, NULL, 0u, true, 10u), RQFT_ERR_MALFORMED);

    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 10u),
                 RQFT_OK);
    CHECK_EQ_INT(rqft_session_request_del(&ctrl, (const uint8_t *)"a.data", 6u, false, 11u),
                 RQFT_ERR_MALFORMED);
}

int main(void)
{
    test_del_file_removes_file_and_reports_del_done();
    test_del_dir_removes_tree_recursively();
    test_del_denied_without_caps_bit();
    test_del_denied_by_per_request_callback();
    test_del_remove_failure_answers_fs_remove();
    test_failed_del_releases_slot_and_batch_continues();
    test_responder_rejects_invalid_del_path_with_e_path();
    test_responder_without_delete_callbacks_answers_unsupported();
    test_wrong_message_while_awaiting_del_ok_answers_bad_state();
    test_request_del_validates_role_state_and_path();
    TEST_MAIN_END();
}
