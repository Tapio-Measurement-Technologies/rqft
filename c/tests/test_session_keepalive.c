// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session_keepalive.c - keepalive and idle-death tests for
 * SPEC.md section 4.5. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

#define WIRE_CAP 16384u
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
    size_t list_entries;
    uint32_t entry_size;
    uint32_t entry_crc;
    bool entry_has_crc;
    size_t list_done_events;
    size_t put_done_events;
    uint32_t put_done_size;
    uint32_t put_done_crc;
    size_t op_failed_events;
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
    case RQFT_SESSION_EVENT_ENDED:
        log->ended_events++;
        log->ended_reason = event->u.ended.reason;
        log->ended_from_peer = event->u.ended.from_peer;
        break;
    case RQFT_SESSION_EVENT_LIST_ENTRY:
        log->list_entries++;
        log->entry_size = event->u.list_entry.size;
        log->entry_crc = event->u.list_entry.crc32;
        log->entry_has_crc = event->u.list_entry.has_crc;
        break;
    case RQFT_SESSION_EVENT_LIST_DONE:
        log->list_done_events++;
        break;
    case RQFT_SESSION_EVENT_PUT_DONE:
        log->put_done_events++;
        log->put_done_size = event->u.put_done.size;
        log->put_done_crc = event->u.put_done.crc32;
        break;
    case RQFT_SESSION_EVENT_OP_FAILED:
        log->op_failed_events++;
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
                           rqft_role_t role,
                           const rqft_fs_ops_t *fs_ops,
                           void *fs_user)
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
    config.fs = fs_ops;
    config.fs_user = fs_user;
    CHECK_EQ_INT(rqft_session_init(session, &config), RQFT_OK);
}

static void establish_pair(rqft_session_t *ctrl,
                           session_log_t *ctrl_log,
                           rqft_session_t *resp,
                           session_log_t *resp_log)
{
    setup_endpoint(ctrl, ctrl_log, RQFT_ROLE_CONTROLLER, NULL, NULL);
    setup_endpoint(resp, resp_log, RQFT_ROLE_RESPONDER, NULL, NULL);
    CHECK_EQ_INT(rqft_session_start(ctrl, 0u), RQFT_OK);
    rqft_session_receive(resp, ctrl_log->wire, ctrl_log->wire_len, 0u);
    ctrl_log->consumed = ctrl_log->wire_len;
    rqft_session_receive(ctrl, resp_log->wire, resp_log->wire_len, 0u);
    resp_log->consumed = resp_log->wire_len;
    CHECK(rqft_session_active(ctrl));
    CHECK(rqft_session_active(resp));
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

/* Feed one plain cumulative ACK with the given next-expected seq. */
static void feed_ack(rqft_session_t *session, uint8_t next_expected, uint32_t now_ms)
{
    uint8_t wire[16];
    size_t wire_len = 0u;
    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ACK, SID, next_expected, 0u, NULL, 0u,
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);
    rqft_session_receive(session, wire, wire_len, now_ms);
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

/* The next unconsumed DATA message must be a PING with the token. */
static void check_ping(session_log_t *log, uint32_t token)
{
    rqft_msg_t msg;
    CHECK(nth_data_message(log->wire + log->consumed,
                           log->wire_len - log->consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PING);
    CHECK_EQ_INT(msg.u.token.token, token);
    log->consumed = log->wire_len;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */

static void test_ping_pong_token_echo_both_roles(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint8_t ping[5] = {RQFT_MSG_PING, 0xEFu, 0xBEu, 0xADu, 0xDEu};
    uint8_t wire[64];
    size_t wire_len;
    rqft_msg_t msg;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    wire_len = raw_data_frame(0u, ping, sizeof(ping), wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 10u);
    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PONG);
    CHECK_EQ_INT(msg.u.token.token, 0xDEADBEEFu);

    rqft_session_receive(&ctrl, wire, wire_len, 10u);
    CHECK(nth_data_message(ctrl_log.wire + ctrl_log.consumed,
                           ctrl_log.wire_len - ctrl_log.consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PONG);
    CHECK_EQ_INT(msg.u.token.token, 0xDEADBEEFu);

    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_controller_pings_after_t_ping_of_silence(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    size_t ping_start, ping_end;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    rqft_session_poll(&ctrl, RQFT_T_PING_MS - 1u);
    CHECK_EQ_INT(ctrl_log.wire_len, ctrl_log.consumed);

    ping_start = ctrl_log.consumed;
    rqft_session_poll(&ctrl, RQFT_T_PING_MS);
    ping_end = ctrl_log.wire_len;
    check_ping(&ctrl_log, 1u);

    /* The exchange makes both directions quiet again; the next silence
     * window ends with the next token. */
    rqft_session_receive(&resp, ctrl_log.wire + ping_start, ping_end - ping_start,
                         RQFT_T_PING_MS);
    rqft_session_receive(&ctrl, resp_log.wire + resp_log.consumed,
                         resp_log.wire_len - resp_log.consumed, RQFT_T_PING_MS);
    resp_log.consumed = resp_log.wire_len;
    ctrl_log.consumed = ctrl_log.wire_len;

    rqft_session_poll(&ctrl, 2u * RQFT_T_PING_MS);
    check_ping(&ctrl_log, 2u);
}

static void test_any_transmission_defers_the_ping(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    /* A PLAN at 1500 restarts the silence window: no ping at 2000. The
     * PLAN is ACKed so no retransmission timer interferes. */
    CHECK_EQ_INT(rqft_session_send_plan(&ctrl, 1u, 1u, 1500u), RQFT_OK);
    ctrl_log.consumed = ctrl_log.wire_len;
    feed_ack(&ctrl, 1u, 1500u);

    rqft_session_poll(&ctrl, RQFT_T_PING_MS);
    CHECK_EQ_INT(ctrl_log.wire_len, ctrl_log.consumed);

    rqft_session_poll(&ctrl, 1500u + RQFT_T_PING_MS);
    check_ping(&ctrl_log, 1u);
}

static void test_responder_never_auto_pings(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    rqft_session_poll(&resp, 3u * RQFT_T_PING_MS);
    CHECK_EQ_INT(resp_log.wire_len, resp_log.consumed);
    CHECK(rqft_session_active(&resp));
}

/* ------------------------------------------------------------------ */
/* Synthetic one-file filesystem                                       */

/* "big.bin" of a configurable size whose byte i is synth_byte(i), so a
 * file of megabytes needs no storage. Serves the listing and reads for
 * a responder LIST or a controller PUT source, and a write sink that
 * only counts and hashes for a responder PUT. */
typedef struct synth_fs {
    uint32_t size;
    bool listed;
    uint32_t read_pos;
    uint32_t written;
    uint32_t written_crc;
    bool committed;
} synth_fs_t;

static const char kBigName[] = "big.bin";

static uint8_t synth_byte(uint32_t i)
{
    return (uint8_t)(i * 31u % 251u);
}

static uint32_t synth_crc(uint32_t size)
{
    uint8_t buf[512];
    uint32_t crc = 0u;
    for (uint32_t pos = 0u; pos < size;) {
        size_t n = 0u;
        while (n < sizeof(buf) && pos < size) {
            buf[n++] = synth_byte(pos++);
        }
        crc = rqft_crc32_update(crc, buf, n);
    }
    return crc;
}

static bool sf_is_big(const uint8_t *path, size_t path_len)
{
    return path_len == sizeof(kBigName) - 1u && memcmp(path, kBigName, path_len) == 0;
}

static bool sf_list_begin(void *user, const uint8_t *root, size_t root_len)
{
    (void)root;
    ((synth_fs_t *)user)->listed = false;
    return root_len == 0u;
}

static int sf_list_next(void *user, rqft_fs_entry_t *entry)
{
    synth_fs_t *fs = (synth_fs_t *)user;
    if (fs->listed) {
        return 0;
    }
    fs->listed = true;
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->path, kBigName, sizeof(kBigName) - 1u);
    entry->path_len = sizeof(kBigName) - 1u;
    entry->size = fs->size;
    return 1;
}

static void sf_list_close(void *user)
{
    (void)user;
}

static bool sf_open_read(void *user, const uint8_t *path, size_t path_len, uint32_t *size)
{
    synth_fs_t *fs = (synth_fs_t *)user;
    if (!sf_is_big(path, path_len)) {
        return false;
    }
    fs->read_pos = 0u;
    *size = fs->size;
    return true;
}

static int sf_read(void *user, uint8_t *buf, size_t cap)
{
    synth_fs_t *fs = (synth_fs_t *)user;
    size_t n = 0u;
    while (n < cap && fs->read_pos < fs->size) {
        buf[n++] = synth_byte(fs->read_pos++);
    }
    return (int)n;
}

static void sf_close_read(void *user)
{
    (void)user;
}

static bool sf_open_write(void *user, const uint8_t *path, size_t path_len)
{
    synth_fs_t *fs = (synth_fs_t *)user;
    fs->written = 0u;
    fs->written_crc = 0u;
    return sf_is_big(path, path_len);
}

static bool sf_write(void *user, const uint8_t *data, size_t len)
{
    synth_fs_t *fs = (synth_fs_t *)user;
    fs->written += (uint32_t)len;
    fs->written_crc = rqft_crc32_update(fs->written_crc, data, len);
    return true;
}

static bool sf_commit(void *user)
{
    ((synth_fs_t *)user)->committed = true;
    return true;
}

static void sf_discard(void *user)
{
    (void)user;
}

static const rqft_fs_ops_t synth_ops = {
    sf_list_begin, sf_list_next, sf_list_close,
    sf_open_read, sf_read, sf_close_read,
    sf_open_write, sf_write, sf_commit, sf_discard,
    NULL, NULL, NULL,
};

static void establish_pair_with_fs(rqft_session_t *ctrl,
                                   session_log_t *ctrl_log,
                                   synth_fs_t *ctrl_fs,
                                   rqft_session_t *resp,
                                   session_log_t *resp_log,
                                   synth_fs_t *resp_fs)
{
    setup_endpoint(ctrl, ctrl_log, RQFT_ROLE_CONTROLLER, &synth_ops, ctrl_fs);
    setup_endpoint(resp, resp_log, RQFT_ROLE_RESPONDER, &synth_ops, resp_fs);
    CHECK_EQ_INT(rqft_session_start(ctrl, 0u), RQFT_OK);
    rqft_session_receive(resp, ctrl_log->wire, ctrl_log->wire_len, 0u);
    ctrl_log->consumed = ctrl_log->wire_len;
    rqft_session_receive(ctrl, resp_log->wire, resp_log->wire_len, 0u);
    resp_log->consumed = resp_log->wire_len;
    CHECK(rqft_session_active(ctrl));
    CHECK(rqft_session_active(resp));
}

/* ------------------------------------------------------------------ */
/* Keepalive across operation phases                                   */

typedef enum request_kind {
    REQUEST_LIST,
    REQUEST_DEL,
    REQUEST_GET,
    REQUEST_PUT,
} request_kind_t;

/* Leave the controller awaiting the reply to one request. The request
 * frame is ACKed at once so no retransmission timer interferes; the
 * reply itself never arrives. A PUT source of 100 bytes hashes in one
 * poll, so PUT_REQ goes out and PUT_OK is awaited. */
static void start_request(rqft_session_t *ctrl, session_log_t *ctrl_log, request_kind_t kind)
{
    const uint8_t *path = (const uint8_t *)kBigName;
    size_t path_len = sizeof(kBigName) - 1u;
    switch (kind) {
    case REQUEST_LIST:
        CHECK_EQ_INT(rqft_session_request_list(ctrl, NULL, 0u, true, 0u), RQFT_OK);
        break;
    case REQUEST_DEL:
        CHECK_EQ_INT(rqft_session_request_del(ctrl, path, path_len, false, 0u), RQFT_OK);
        break;
    case REQUEST_GET:
        CHECK_EQ_INT(rqft_session_request_get(ctrl, path, path_len, 0u), RQFT_OK);
        break;
    case REQUEST_PUT:
        CHECK_EQ_INT(rqft_session_request_put(ctrl, path, path_len, 0u), RQFT_OK);
        rqft_session_poll(ctrl, 0u);
        break;
    }
    ctrl_log->consumed = ctrl_log->wire_len;
    feed_ack(ctrl, 1u, 0u);
}

/* A responder hashing a large file for LIST want_crc sends nothing
 * until the entry is ready; only the keepalive keeps both sides short
 * of T_DEAD (SPEC.md section 4.5). */
static void check_pings_while_awaiting(request_kind_t kind)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    synth_fs_t ctrl_fs = {0};
    synth_fs_t resp_fs = {0};
    uint32_t deadline = 0u;

    establish_pair_with_fs(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs);
    start_request(&ctrl, &ctrl_log, kind);

    CHECK(rqft_session_next_timeout(&ctrl, &deadline));
    CHECK_EQ_INT(deadline, RQFT_T_PING_MS);
    rqft_session_poll(&ctrl, RQFT_T_PING_MS);
    check_ping(&ctrl_log, 1u);
    CHECK(rqft_session_active(&ctrl));
}

static void test_controller_pings_while_awaiting_list_or_del(void)
{
    check_pings_while_awaiting(REQUEST_LIST);
    check_pings_while_awaiting(REQUEST_DEL);
}

/* After GET_REQ the responder may already be streaming FILE_DATA, and
 * after PUT_REQ it treats anything but FILE_DATA, FILE_END or ERR as
 * fatal (SPEC.md section 5.3). */
static void check_no_ping_once_stream_may_be_open(request_kind_t kind)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    synth_fs_t ctrl_fs = {100u, false, 0u, 0u, 0u, false};
    synth_fs_t resp_fs = {0};
    uint32_t deadline = 0u;

    establish_pair_with_fs(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs);
    start_request(&ctrl, &ctrl_log, kind);

    CHECK(rqft_session_next_timeout(&ctrl, &deadline));
    CHECK_EQ_INT(deadline, RQFT_T_DEAD_MS);
    rqft_session_poll(&ctrl, RQFT_T_PING_MS);
    CHECK_EQ_INT(ctrl_log.wire_len, ctrl_log.consumed);
    CHECK(rqft_session_active(&ctrl));
}

static void test_no_ping_once_a_file_stream_may_be_open(void)
{
    check_no_ping_once_stream_may_be_open(REQUEST_GET);
    check_no_ping_once_stream_may_be_open(REQUEST_PUT);
}

static void test_controller_pings_while_hashing_put_source(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    synth_fs_t ctrl_fs = {4u * RQFT_CRC_BUDGET_PER_POLL, false, 0u, 0u, 0u, false};
    synth_fs_t resp_fs = {0};

    establish_pair_with_fs(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs);
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)kBigName,
                                          sizeof(kBigName) - 1u, 0u),
                 RQFT_OK);

    rqft_session_poll(&ctrl, RQFT_T_PING_MS);

    /* The PING goes out ahead of PUT_REQ, which waits for the hash. */
    rqft_msg_t msg;
    CHECK(!nth_data_message(ctrl_log.wire + ctrl_log.consumed,
                            ctrl_log.wire_len - ctrl_log.consumed, 1u, &msg));
    check_ping(&ctrl_log, 1u);
    CHECK(rqft_session_work_pending(&ctrl));
}

static void test_controller_pings_while_awaiting_put_done(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    synth_fs_t ctrl_fs = {5u, false, 0u, 0u, 0u, false};
    synth_fs_t resp_fs = {0};
    uint8_t put_ok[1] = {RQFT_MSG_PUT_OK};
    uint8_t wire[64];
    size_t wire_len;
    rqft_msg_t msg;

    establish_pair_with_fs(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs);
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)kBigName,
                                          sizeof(kBigName) - 1u, 0u),
                 RQFT_OK);
    rqft_session_poll(&ctrl, 0u);
    wire_len = raw_data_frame(0u, put_ok, sizeof(put_ok), wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 0u);
    rqft_session_poll(&ctrl, 0u);
    CHECK(nth_data_message(ctrl_log.wire + ctrl_log.consumed,
                           ctrl_log.wire_len - ctrl_log.consumed, 2u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_END);
    ctrl_log.consumed = ctrl_log.wire_len;
    feed_ack(&ctrl, 3u, 0u);

    /* FILE_END closed our stream, so a slow commit before PUT_DONE no
     * longer holds the keepalive back. */
    rqft_session_poll(&ctrl, RQFT_T_PING_MS);
    check_ping(&ctrl_log, 1u);
}

/* ------------------------------------------------------------------ */
/* Slow hashing on a shared simulated clock                            */

/* A 1 MiB file at about one CRC budget per 200 ms host loop turn takes
 * about 50 s of simulated time to hash, five times T_DEAD. */
#define BIG_SIZE (1u << 20)
#define SLOW_STEP_MS 200u

/* Count the PINGs in one wire capture; stop at the first PUT_REQ when
 * seen_put_req is given, and record whether one was found. */
static size_t count_pings(const uint8_t *wire, size_t wire_len, bool *seen_put_req)
{
    size_t pings = 0u;
    rqft_msg_t msg;
    for (size_t i = 0u; nth_data_message(wire, wire_len, i, &msg); i++) {
        if (msg.type == RQFT_MSG_PUT_REQ) {
            *seen_put_req = true;
        }
        if (msg.type == RQFT_MSG_PING && !*seen_put_req) {
            pings++;
        }
    }
    return pings;
}

/* Hand one side's pending wire to its peer and empty the log, so long
 * runs fit WIRE_CAP. */
static void deliver(session_log_t *from, rqft_session_t *to, uint32_t now_ms)
{
    if (from->wire_len > from->consumed) {
        rqft_session_receive(to, from->wire + from->consumed, from->wire_len - from->consumed,
                             now_ms);
    }
    from->wire_len = 0u;
    from->consumed = 0u;
}

/* Drive both endpoints like host superloops sharing one clock: each
 * step gives each side one timer poll (one bounded work slice) plus
 * delivery of whatever its peer sent. Stops when the controller's
 * operation finishes or either side ends. Returns the PINGs the
 * controller sent before any PUT_REQ. */
static size_t run_clocked(rqft_session_t *ctrl,
                          session_log_t *ctrl_log,
                          rqft_session_t *resp,
                          session_log_t *resp_log)
{
    size_t pings = 0u;
    bool seen_put_req = false;
    uint32_t now_ms = 0u;
    for (unsigned step = 0u; step < 5000u; step++) {
        rqft_session_poll(ctrl, now_ms);
        pings += count_pings(ctrl_log->wire + ctrl_log->consumed,
                             ctrl_log->wire_len - ctrl_log->consumed, &seen_put_req);
        deliver(ctrl_log, resp, now_ms);
        rqft_session_poll(resp, now_ms);
        deliver(resp_log, ctrl, now_ms);
        if (!rqft_session_active(ctrl) || !rqft_session_active(resp)) {
            break;
        }
        if (ctrl_log->list_done_events + ctrl_log->put_done_events +
                ctrl_log->op_failed_events > 0u) {
            break;
        }
        now_ms += SLOW_STEP_MS;
    }
    return pings;
}

static void test_list_want_crc_outlives_t_dead_on_slow_responder_hash(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    synth_fs_t ctrl_fs = {0};
    synth_fs_t resp_fs = {BIG_SIZE, false, 0u, 0u, 0u, false};
    size_t pings;

    establish_pair_with_fs(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 0u), RQFT_OK);

    pings = run_clocked(&ctrl, &ctrl_log, &resp, &resp_log);

    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
    CHECK_EQ_INT(ctrl_log.list_entries, 1);
    CHECK(ctrl_log.entry_has_crc);
    CHECK_EQ_INT(ctrl_log.entry_size, BIG_SIZE);
    CHECK_EQ_INT(ctrl_log.entry_crc, synth_crc(BIG_SIZE));
    CHECK_EQ_INT(ctrl_log.list_done_events, 1);
    CHECK(pings >= RQFT_T_DEAD_MS / RQFT_T_PING_MS);
}

static void test_put_outlives_t_dead_on_slow_controller_hash(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    synth_fs_t ctrl_fs = {BIG_SIZE, false, 0u, 0u, 0u, false};
    synth_fs_t resp_fs = {0};
    size_t pings;

    establish_pair_with_fs(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs);
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)kBigName,
                                          sizeof(kBigName) - 1u, 0u),
                 RQFT_OK);

    pings = run_clocked(&ctrl, &ctrl_log, &resp, &resp_log);

    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    CHECK_EQ_INT(ctrl_log.put_done_size, BIG_SIZE);
    CHECK_EQ_INT(ctrl_log.put_done_crc, synth_crc(BIG_SIZE));
    CHECK(resp_fs.committed);
    CHECK_EQ_INT(resp_fs.written, BIG_SIZE);
    CHECK_EQ_INT(resp_fs.written_crc, synth_crc(BIG_SIZE));
    CHECK(pings >= RQFT_T_DEAD_MS / RQFT_T_PING_MS);
}

static void test_next_timeout_includes_ping_deadline(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint32_t deadline = 0u;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    CHECK(rqft_session_next_timeout(&ctrl, &deadline));
    CHECK_EQ_INT(deadline, RQFT_T_PING_MS);
}

/* The last outbound frame in a capture must be ABORT with the reason. */
static void check_last_frame_abort(const uint8_t *wire, size_t wire_len,
                                   rqft_abort_reason_t reason)
{
    size_t pos = wire_len;
    size_t end;
    uint8_t decoded[16];
    size_t decoded_len = 0u;
    while (pos > 0u && wire[pos - 1u] == 0u) {
        pos--;
    }
    end = pos;
    while (pos > 0u && wire[pos - 1u] != 0u) {
        pos--;
    }
    CHECK_EQ_INT(rqft_cobs_decode(wire + pos, end - pos, decoded, sizeof(decoded),
                                  &decoded_len),
                 RQFT_OK);
    CHECK_EQ_INT(decoded[0], RQFT_FRAME_ABORT);
    CHECK_EQ_INT(decoded[4], reason);
}

/* One silent endpoint of either role must die at T_DEAD with a
 * best-effort ABORT(E_TIMEOUT). */
static void check_t_dead_kills_a_silent_session(rqft_role_t role)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    rqft_session_t *session = role == RQFT_ROLE_CONTROLLER ? &ctrl : &resp;
    session_log_t *log = role == RQFT_ROLE_CONTROLLER ? &ctrl_log : &resp_log;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    rqft_session_poll(session, RQFT_T_DEAD_MS);

    CHECK_EQ_INT(log->ended_events, 1);
    CHECK_EQ_INT(log->ended_reason, RQFT_ABORT_E_TIMEOUT);
    CHECK(!log->ended_from_peer);
    CHECK_EQ_INT(rqft_session_state(session), RQFT_SESSION_ENDED);
    check_last_frame_abort(log->wire, log->wire_len, RQFT_ABORT_E_TIMEOUT);
}

static void test_t_dead_kills_a_silent_session_in_both_roles(void)
{
    check_t_dead_kills_a_silent_session(RQFT_ROLE_CONTROLLER);
    check_t_dead_kills_a_silent_session(RQFT_ROLE_RESPONDER);
}

static void test_valid_in_session_frame_resets_t_dead(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint8_t ping[5] = {RQFT_MSG_PING, 1u, 0u, 0u, 0u};
    uint8_t wire[64];
    size_t wire_len;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    wire_len = raw_data_frame(0u, ping, sizeof(ping), wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 9000u);

    rqft_session_poll(&resp, RQFT_T_DEAD_MS);
    CHECK_EQ_INT(resp_log.ended_events, 0);
    CHECK(rqft_session_active(&resp));

    rqft_session_poll(&resp, 9000u + RQFT_T_DEAD_MS);
    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_TIMEOUT);
}

static void test_wrong_sid_frames_do_not_reset_t_dead(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint8_t ping[5] = {RQFT_MSG_PING, 1u, 0u, 0u, 0u};
    uint8_t wire[64];
    size_t wire_len = 0u;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_DATA, SID + 1u, 0u, 0u, ping, sizeof(ping),
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);
    rqft_session_receive(&resp, wire, wire_len, 9000u);

    rqft_session_poll(&resp, RQFT_T_DEAD_MS);
    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_TIMEOUT);
}

static void test_keepalive_pings_hold_off_peer_t_dead(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;

    /* An idle but healthy pair outlives T_DEAD: the controller's pings
     * and their PONG/ACK answers keep both receive clocks fresh. */
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    for (uint32_t now_ms = RQFT_T_PING_MS; now_ms <= 6u * RQFT_T_PING_MS;
         now_ms += RQFT_T_PING_MS) {
        rqft_session_poll(&ctrl, now_ms);
        rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                             ctrl_log.wire_len - ctrl_log.consumed, now_ms);
        ctrl_log.consumed = ctrl_log.wire_len;
        rqft_session_poll(&resp, now_ms);
        rqft_session_receive(&ctrl, resp_log.wire + resp_log.consumed,
                             resp_log.wire_len - resp_log.consumed, now_ms);
        resp_log.consumed = resp_log.wire_len;
    }

    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

/* Write-cursor fake tracking only the temp-file lifecycle. */
typedef struct write_fake {
    bool writing;
    size_t discarded;
} write_fake_t;

static bool wf_open_write(void *user, const uint8_t *path, size_t path_len)
{
    (void)path;
    (void)path_len;
    ((write_fake_t *)user)->writing = true;
    return true;
}

static bool wf_write(void *user, const uint8_t *data, size_t len)
{
    (void)user;
    (void)data;
    (void)len;
    return true;
}

static bool wf_commit(void *user)
{
    ((write_fake_t *)user)->writing = false;
    return true;
}

static void wf_discard(void *user)
{
    write_fake_t *fs = (write_fake_t *)user;
    if (fs->writing) {
        fs->writing = false;
        fs->discarded++;
    }
}

static const rqft_fs_ops_t write_ops = {
    NULL, NULL, NULL,
    NULL, NULL, NULL,
    wf_open_write, wf_write, wf_commit, wf_discard,
    NULL, NULL, NULL,
};

static void test_t_dead_mid_put_discards_responder_temp(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    write_fake_t fs = {false, 0u};
    uint8_t put_req[15] = {RQFT_MSG_PUT_REQ, 9u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
                           5u, 'f', '.', 'b', 'i', 'n'};
    uint8_t file_data[4] = {RQFT_MSG_FILE_DATA, 'a', 'b', 'c'};
    uint8_t wire[64];
    size_t wire_len;

    setup_endpoint(&ctrl, &ctrl_log, RQFT_ROLE_CONTROLLER, NULL, NULL);
    setup_endpoint(&resp, &resp_log, RQFT_ROLE_RESPONDER, &write_ops, &fs);
    CHECK_EQ_INT(rqft_session_start(&ctrl, 0u), RQFT_OK);
    rqft_session_receive(&resp, ctrl_log.wire, ctrl_log.wire_len, 0u);
    rqft_session_receive(&ctrl, resp_log.wire, resp_log.wire_len, 0u);
    CHECK(rqft_session_active(&resp));

    wire_len = raw_data_frame(0u, put_req, sizeof(put_req), wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 0u);
    wire_len = raw_data_frame(1u, file_data, sizeof(file_data), wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 0u);
    CHECK(fs.writing);

    rqft_session_poll(&resp, RQFT_T_DEAD_MS);

    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_TIMEOUT);
    CHECK(!fs.writing);
    CHECK_EQ_INT(fs.discarded, 1);
}

static void test_next_timeout_includes_t_dead_deadline(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    uint32_t deadline = 0u;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log);

    CHECK(rqft_session_next_timeout(&resp, &deadline));
    CHECK_EQ_INT(deadline, RQFT_T_DEAD_MS);
}

int main(void)
{
    test_ping_pong_token_echo_both_roles();
    test_controller_pings_after_t_ping_of_silence();
    test_any_transmission_defers_the_ping();
    test_responder_never_auto_pings();
    test_controller_pings_while_awaiting_list_or_del();
    test_no_ping_once_a_file_stream_may_be_open();
    test_controller_pings_while_hashing_put_source();
    test_controller_pings_while_awaiting_put_done();
    test_next_timeout_includes_ping_deadline();
    test_t_dead_kills_a_silent_session_in_both_roles();
    test_valid_in_session_frame_resets_t_dead();
    test_wrong_sid_frames_do_not_reset_t_dead();
    test_keepalive_pings_hold_off_peer_t_dead();
    test_t_dead_mid_put_discards_responder_temp();
    test_next_timeout_includes_t_dead_deadline();
    test_list_want_crc_outlives_t_dead_on_slow_responder_hash();
    test_put_outlives_t_dead_on_slow_controller_hash();
    TEST_MAIN_END();
}
