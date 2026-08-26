// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session_put.c - PUT operation tests for SPEC.md section 5.4. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

#define WIRE_CAP 32768u
#define SID 0x42u

/* ------------------------------------------------------------------ */
/* Event and wire logging                                              */

typedef struct session_log {
    uint8_t wire[WIRE_CAP];
    size_t wire_len;
    size_t consumed;
    size_t put_done_events;
    uint8_t put_done_path[RQFT_MAX_PATH];
    size_t put_done_path_len;
    uint32_t put_done_size;
    uint32_t put_done_crc;
    size_t op_failed_events;
    uint8_t op_failed_request;
    rqft_err_code_t op_failed_code;
    uint8_t op_failed_path[RQFT_MAX_PATH];
    size_t op_failed_path_len;
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
    switch (event->type) {
    case RQFT_SESSION_EVENT_PUT_DONE:
        log->put_done_events++;
        CHECK(event->u.put_done.path_len <= RQFT_MAX_PATH);
        memcpy(log->put_done_path, event->u.put_done.path, event->u.put_done.path_len);
        log->put_done_path_len = event->u.put_done.path_len;
        log->put_done_size = event->u.put_done.size;
        log->put_done_crc = event->u.put_done.crc32;
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
        log->ended_reason = event->u.ended.reason;
        log->ended_from_peer = event->u.ended.from_peer;
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* In-memory fake filesystem with a temp-write-then-commit side        */

#define FAKE_MAX_FILES 8u
#define FAKE_FILE_CAP 12288u

typedef struct fake_file {
    char path[RQFT_MAX_PATH + 1u];
    uint8_t data[FAKE_FILE_CAP];
    size_t size;
} fake_file_t;

typedef struct fake_fs {
    fake_file_t files[FAKE_MAX_FILES];
    size_t file_count;
    size_t list_pos;
    int read_index;
    size_t read_pos;
    size_t bytes_read;
    size_t max_read_len;
    char fail_open_read[RQFT_MAX_PATH + 1u];
    char fail_read_path[RQFT_MAX_PATH + 1u];
    size_t fail_read_at;
    size_t fail_read_total; /* cumulative bytes; 0 disables the fault */
    char write_path[RQFT_MAX_PATH + 1u];
    uint8_t write_buf[FAKE_FILE_CAP];
    size_t write_len;
    bool writing;
    size_t discarded;
    bool fail_write;
    bool fail_commit;
    char fail_open_write[RQFT_MAX_PATH + 1u];
} fake_fs_t;

static void fake_add(fake_fs_t *fs, const char *path, const uint8_t *data, size_t size)
{
    fake_file_t *file = &fs->files[fs->file_count++];
    CHECK(fs->file_count <= FAKE_MAX_FILES);
    CHECK(size <= FAKE_FILE_CAP);
    strcpy(file->path, path);
    if (size > 0u) {
        memcpy(file->data, data, size);
    }
    file->size = size;
}

static int fake_find(fake_fs_t *fs, const uint8_t *path, size_t path_len)
{
    for (size_t i = 0u; i < fs->file_count; i++) {
        if (strlen(fs->files[i].path) == path_len &&
            memcmp(fs->files[i].path, path, path_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static bool fake_list_begin(void *user, const uint8_t *root, size_t root_len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    (void)root;
    (void)root_len;
    fs->list_pos = 0u;
    return true;
}

static int fake_list_next(void *user, rqft_fs_entry_t *entry)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    if (fs->list_pos >= fs->file_count) {
        return 0;
    }
    const fake_file_t *file = &fs->files[fs->list_pos++];
    memset(entry, 0, sizeof(*entry));
    entry->path_len = strlen(file->path);
    memcpy(entry->path, file->path, entry->path_len);
    entry->size = (uint32_t)file->size;
    return 1;
}

static void fake_list_close(void *user)
{
    (void)user;
}

static bool fake_open_read(void *user, const uint8_t *path, size_t path_len, uint32_t *size)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    int index;
    if (strlen(fs->fail_open_read) == path_len &&
        memcmp(fs->fail_open_read, path, path_len) == 0) {
        return false;
    }
    index = fake_find(fs, path, path_len);
    if (index < 0) {
        return false;
    }
    fs->read_index = index;
    fs->read_pos = 0u;
    *size = (uint32_t)fs->files[index].size;
    return true;
}

static int fake_read(void *user, uint8_t *buf, size_t cap)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    const fake_file_t *file = &fs->files[fs->read_index];
    if (fs->fail_read_total > 0u && fs->bytes_read >= fs->fail_read_total) {
        return -1;
    }
    if (strlen(fs->fail_read_path) == strlen(file->path) &&
        strcmp(fs->fail_read_path, file->path) == 0 &&
        fs->read_pos >= fs->fail_read_at) {
        return -1;
    }
    size_t remaining = file->size - fs->read_pos;
    size_t chunk = remaining < cap ? remaining : cap;
    if (chunk > 0u) {
        memcpy(buf, file->data + fs->read_pos, chunk);
    }
    fs->read_pos += chunk;
    fs->bytes_read += chunk;
    if (chunk > fs->max_read_len) {
        fs->max_read_len = chunk;
    }
    return (int)chunk;
}

static void fake_close_read(void *user)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    fs->read_index = -1;
}

static bool fake_open_write(void *user, const uint8_t *path, size_t path_len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    CHECK(path_len <= RQFT_MAX_PATH);
    if (strlen(fs->fail_open_write) == path_len &&
        memcmp(fs->fail_open_write, path, path_len) == 0) {
        return false;
    }
    memcpy(fs->write_path, path, path_len);
    fs->write_path[path_len] = '\0';
    fs->write_len = 0u;
    fs->writing = true;
    return true;
}

static bool fake_write(void *user, const uint8_t *data, size_t len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    CHECK(fs->writing);
    if (fs->fail_write) {
        return false;
    }
    CHECK(fs->write_len + len <= FAKE_FILE_CAP);
    memcpy(fs->write_buf + fs->write_len, data, len);
    fs->write_len += len;
    return true;
}

static bool fake_commit(void *user)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    int index;
    CHECK(fs->writing);
    fs->writing = false;
    if (fs->fail_commit) {
        fs->discarded++;
        return false;
    }
    index = fake_find(fs, (const uint8_t *)fs->write_path, strlen(fs->write_path));
    if (index < 0) {
        fake_add(fs, fs->write_path, fs->write_buf, fs->write_len);
    } else {
        memcpy(fs->files[index].data, fs->write_buf, fs->write_len);
        fs->files[index].size = fs->write_len;
    }
    return true;
}

static void fake_discard(void *user)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    if (fs->writing) {
        fs->writing = false;
        fs->discarded++;
    }
}

static const rqft_fs_ops_t fake_ops = {
    fake_list_begin, fake_list_next, fake_list_close,
    fake_open_read, fake_read, fake_close_read,
    fake_open_write, fake_write, fake_commit, fake_discard,
    NULL, NULL, NULL,
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
                           fake_fs_t *fs,
                           uint8_t window)
{
    rqft_session_config_t config;
    memset(log, 0, sizeof(*log));
    memset(&config, 0, sizeof(config));
    config.role = role;
    config.ver_min = 1u;
    config.ver_max = 1u;
    config.max_payload = 512u;
    config.window = window;
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
                           fake_fs_t *ctrl_fs,
                           rqft_session_t *resp,
                           session_log_t *resp_log,
                           fake_fs_t *resp_fs,
                           uint8_t window)
{
    setup_endpoint(ctrl, ctrl_log, RQFT_ROLE_CONTROLLER, ctrl_fs, 4u);
    setup_endpoint(resp, resp_log, RQFT_ROLE_RESPONDER, resp_fs, window);
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

/* Count DATA frames in a wire capture whose message has the given type. */
static size_t count_messages(const uint8_t *wire, size_t wire_len, rqft_msg_type_t type)
{
    rqft_msg_t msg;
    size_t count = 0u;
    for (size_t index = 0u; nth_data_message(wire, wire_len, index, &msg); index++) {
        if (msg.type == type) {
            count++;
        }
    }
    return count;
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

static void check_committed(fake_fs_t *fs, const char *path, const uint8_t *data, size_t size)
{
    int index = fake_find(fs, (const uint8_t *)path, strlen(path));
    CHECK(index >= 0);
    if (index >= 0) {
        CHECK_EQ_INT(fs->files[index].size, size);
        if (size > 0u) {
            CHECK(memcmp(fs->files[index].data, data, size) == 0);
        }
    }
}

static void fake_fs_files(fake_fs_t *fs)
{
    memset(fs, 0, sizeof(*fs));
    fake_add(fs, "a.data", (const uint8_t *)"alpha", 5u);
    fake_add(fs, "logs/2025/run1.data", (const uint8_t *)"first run", 9u);
}

/* Feed the responder one crafted PUT_REQ / FILE_DATA / FILE_END. */
static void feed_put_req(rqft_session_t *resp, uint8_t seq, uint32_t size, uint32_t crc,
                         const char *path, uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PUT_REQ;
    msg.u.put_req.size = size;
    msg.u.put_req.crc32 = crc;
    msg.u.put_req.path = (const uint8_t *)path;
    msg.u.put_req.path_len = strlen(path);
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(resp, wire, wire_len, now_ms);
}

static void feed_file_data(rqft_session_t *session, uint8_t seq, const char *data,
                           uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_FILE_DATA;
    msg.u.file_data.data = (const uint8_t *)data;
    msg.u.file_data.len = strlen(data);
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(session, wire, wire_len, now_ms);
}

static void feed_file_end(rqft_session_t *session, uint8_t seq, uint32_t crc, uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_FILE_END;
    msg.u.file_end.crc32 = crc;
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(session, wire, wire_len, now_ms);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */

static void test_put_transfers_whole_file(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    fake_fs_files(&ctrl_fs);
    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"logs/2025/run1.data",
                                          19u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    CHECK_EQ_INT(ctrl_log.put_done_path_len, 19);
    CHECK(memcmp(ctrl_log.put_done_path, "logs/2025/run1.data", 19u) == 0);
    CHECK_EQ_INT(ctrl_log.put_done_size, 9);
    CHECK_EQ_INT(ctrl_log.put_done_crc, rqft_crc32((const uint8_t *)"first run", 9u));
    check_committed(&resp_fs, "logs/2025/run1.data", (const uint8_t *)"first run", 9u);
    CHECK(!resp_fs.writing);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_put_streams_full_chunks_after_hashing(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t big[1536];
    size_t stream_start;
    rqft_msg_t msg;

    for (size_t i = 0u; i < sizeof(big); i++) {
        big[i] = (uint8_t)i;
    }
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&ctrl_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    stream_start = ctrl_log.consumed;

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    CHECK_EQ_INT(ctrl_log.put_done_size, 1536);
    CHECK_EQ_INT(ctrl_log.put_done_crc, rqft_crc32(big, sizeof(big)));
    check_committed(&resp_fs, "big.bin", big, sizeof(big));

    /* 1536 bytes at a 511-byte chunk: PUT_REQ, 511+511+511+3, FILE_END. */
    CHECK(nth_data_message(ctrl_log.wire + stream_start,
                           ctrl_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PUT_REQ);
    CHECK_EQ_INT(msg.u.put_req.size, 1536);
    CHECK_EQ_INT(msg.u.put_req.crc32, rqft_crc32(big, sizeof(big)));
    for (size_t i = 0u; i < 4u; i++) {
        CHECK(nth_data_message(ctrl_log.wire + stream_start,
                               ctrl_log.wire_len - stream_start, 1u + i, &msg));
        CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_DATA);
        CHECK_EQ_INT(msg.u.file_data.len, i < 3u ? 511u : 3u);
    }
    CHECK(nth_data_message(ctrl_log.wire + stream_start,
                           ctrl_log.wire_len - stream_start, 5u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_END);
    CHECK_EQ_INT(msg.u.file_end.crc32, rqft_crc32(big, sizeof(big)));

    /* The controller hashed and streamed in bounded reads. */
    CHECK(ctrl_fs.max_read_len <= 512u);
}

static void test_put_hash_work_bounded_per_poll(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t big[10240];
    size_t stream_start;
    int polls = 0;
    rqft_msg_t msg;

    for (size_t i = 0u; i < sizeof(big); i++) {
        big[i] = (uint8_t)i;
    }
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&ctrl_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    stream_start = ctrl_log.consumed;

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    while (rqft_session_work_pending(&ctrl) && polls < 50) {
        size_t before = ctrl_fs.bytes_read;
        rqft_session_poll(&ctrl, 10u);
        CHECK(ctrl_fs.bytes_read - before <= RQFT_CRC_BUDGET_PER_POLL);
        polls++;
    }

    /* 10240 bytes at 4096 per poll: three polls to finish the hash. */
    CHECK(polls >= 3);
    CHECK(nth_data_message(ctrl_log.wire + stream_start,
                           ctrl_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PUT_REQ);
    CHECK_EQ_INT(msg.u.put_req.size, 10240);
    CHECK_EQ_INT(msg.u.put_req.crc32, rqft_crc32(big, sizeof(big)));
}

static void test_put_zero_byte_file(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    size_t stream_start;
    rqft_msg_t msg;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&ctrl_fs, "empty.bin", NULL, 0u);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    stream_start = ctrl_log.consumed;

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"empty.bin", 9u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    CHECK_EQ_INT(ctrl_log.put_done_size, 0);
    CHECK_EQ_INT(ctrl_log.put_done_crc, 0);
    check_committed(&resp_fs, "empty.bin", NULL, 0u);
    CHECK(nth_data_message(ctrl_log.wire + stream_start,
                           ctrl_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PUT_REQ);
    CHECK_EQ_INT(msg.u.put_req.size, 0);
    CHECK(nth_data_message(ctrl_log.wire + stream_start,
                           ctrl_log.wire_len - stream_start, 1u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_END);
    CHECK_EQ_INT(msg.u.file_end.crc32, 0);
    CHECK_EQ_INT(count_messages(ctrl_log.wire + stream_start,
                                ctrl_log.wire_len - stream_start, RQFT_MSG_FILE_DATA),
                 0);
}

static void test_put_writes_temp_then_commits_on_file_end(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    rqft_msg_t msg;

    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, &resp_fs, 4u);

    feed_put_req(&resp, 0u, 3u, rqft_crc32((const uint8_t *)"abc", 3u), "f.bin", 10u);
    feed_file_data(&resp, 1u, "ab", 10u);
    CHECK(resp_fs.writing);
    CHECK(fake_find(&resp_fs, (const uint8_t *)"f.bin", 5u) < 0);

    feed_file_data(&resp, 2u, "c", 10u);
    feed_file_end(&resp, 3u, rqft_crc32((const uint8_t *)"abc", 3u), 10u);

    check_committed(&resp_fs, "f.bin", (const uint8_t *)"abc", 3u);
    CHECK(!resp_fs.writing);
    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PUT_OK);
    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 1u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PUT_DONE);
    CHECK_EQ_INT(msg.u.put_done.status, 0);
    CHECK(rqft_session_active(&resp));
}

/* One verification mismatch (wrong bytes or short count) must discard
 * the temp and answer PUT_DONE(E_CRC_FILE); the session lives. */
static void check_put_verification_mismatch(uint32_t size, const char *body)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    uint32_t crc = rqft_crc32((const uint8_t *)"abc", 3u);
    rqft_msg_t msg;

    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, &resp_fs, 4u);

    feed_put_req(&resp, 0u, size, crc, "f.bin", 10u);
    feed_file_data(&resp, 1u, body, 10u);
    feed_file_end(&resp, 2u, crc, 10u);

    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 1u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_PUT_DONE);
    CHECK_EQ_INT(msg.u.put_done.status, RQFT_E_CRC_FILE);
    CHECK_EQ_INT(resp_fs.discarded, 1);
    CHECK(fake_find(&resp_fs, (const uint8_t *)"f.bin", 5u) < 0);
    CHECK(rqft_session_active(&resp));
}

static void test_put_verification_mismatch_answers_put_done_crc_err(void)
{
    check_put_verification_mismatch(3u, "abX");
    check_put_verification_mismatch(5u, "abc");
}

static void test_file_end_crc_mismatching_put_req_aborts(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;

    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, &resp_fs, 4u);

    feed_put_req(&resp, 0u, 3u, rqft_crc32((const uint8_t *)"abc", 3u), "f.bin", 10u);
    feed_file_data(&resp, 1u, "abc", 10u);
    feed_file_end(&resp, 2u, 0xDEADBEEFu, 10u);

    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_PROTO);
    CHECK(!resp_log.ended_from_peer);
    CHECK_EQ_INT(rqft_session_state(&resp), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(resp_fs.discarded, 1);
    check_last_frame_abort(resp_log.wire, resp_log.wire_len, RQFT_ABORT_E_PROTO);
}

static void test_put_write_failure_discards_temp_and_answers_put_done_err(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    fake_fs_files(&ctrl_fs);
    memset(&resp_fs, 0, sizeof(resp_fs));
    resp_fs.fail_write = true;
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request, RQFT_MSG_PUT_REQ);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_WRITE);
    CHECK_EQ_INT(ctrl_log.op_failed_path_len, 6);
    CHECK(memcmp(ctrl_log.op_failed_path, "a.data", 6u) == 0);
    CHECK_EQ_INT(resp_fs.discarded, 1);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));

    /* The failed operation releases the slot; the next PUT commits. */
    resp_fs.fail_write = false;
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 20u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 20u);
    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    check_committed(&resp_fs, "a.data", (const uint8_t *)"alpha", 5u);
}

static void test_put_commit_failure_answers_put_done_err(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    fake_fs_files(&ctrl_fs);
    memset(&resp_fs, 0, sizeof(resp_fs));
    resp_fs.fail_commit = true;
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_WRITE);
    CHECK_EQ_INT(resp_fs.discarded, 1);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_put_err_on_open_write_fails_op_and_batch_continues(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    fake_fs_files(&ctrl_fs);
    memset(&resp_fs, 0, sizeof(resp_fs));
    strcpy(resp_fs.fail_open_write, "a.data");
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request, RQFT_MSG_PUT_REQ);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_OPEN);
    CHECK_EQ_INT(resp_fs.discarded, 0);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"logs/2025/run1.data",
                                          19u, 20u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 20u);
    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    check_committed(&resp_fs, "logs/2025/run1.data", (const uint8_t *)"first run", 9u);
}

static void test_responder_rejects_invalid_put_path_and_missing_fs(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    rqft_msg_t msg;

    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, &resp_fs, 4u);

    feed_put_req(&resp, 0u, 3u, 0u, "../up", 10u);

    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_PATH);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_PUT_REQ);
    CHECK(rqft_session_active(&resp));

    /* A responder without filesystem callbacks answers E_UNSUPPORTED. */
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, NULL, 4u);
    feed_put_req(&resp, 0u, 3u, 0u, "f.bin", 10u);
    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_UNSUPPORTED);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_PUT_REQ);
    CHECK(rqft_session_active(&resp));
}

/* One unexpected mid-stream message must abort E_PROTO with the temp
 * discarded; run for both a wrong op message and a PING. */
static void check_resp_mid_stream_abort(const rqft_msg_t *unexpected)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    uint8_t wire[600];
    size_t wire_len;

    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, &resp_fs, 4u);

    feed_put_req(&resp, 0u, 9u, 0u, "f.bin", 10u);
    feed_file_data(&resp, 1u, "abc", 10u);
    wire_len = data_frame(2u, unexpected, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 10u);

    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_PROTO);
    CHECK(!resp_log.ended_from_peer);
    CHECK_EQ_INT(rqft_session_state(&resp), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(resp_fs.discarded, 1);
    check_last_frame_abort(resp_log.wire, resp_log.wire_len, RQFT_ABORT_E_PROTO);
}

static void test_unexpected_message_mid_stream_aborts_responder(void)
{
    rqft_msg_t msg;

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_REQ;
    msg.u.list_req.root_len = 0u;
    check_resp_mid_stream_abort(&msg);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PING;
    msg.u.token.token = 7u;
    check_resp_mid_stream_abort(&msg);
}

static void test_message_mid_put_stream_aborts_controller(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t big[1536];
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    /* window=1 wedges the controller mid-stream: FILE_DATA stays unacked. */
    memset(big, 0, sizeof(big));
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&ctrl_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 1u);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    while (rqft_session_work_pending(&ctrl)) {
        rqft_session_poll(&ctrl, 10u);
    }
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    rqft_session_receive(&ctrl, resp_log.wire + resp_log.consumed,
                         resp_log.wire_len - resp_log.consumed, 10u);
    resp_log.consumed = resp_log.wire_len;
    CHECK(ctrl_fs.read_index >= 0);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PING;
    msg.u.token.token = 7u;
    wire_len = data_frame(1u, &msg, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 11u);

    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_PROTO);
    CHECK(!ctrl_log.ended_from_peer);
    CHECK_EQ_INT(rqft_session_state(&ctrl), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(ctrl_fs.read_index, -1);
}

static void test_put_open_read_failure_fails_op_without_wire_traffic(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    size_t stream_start;

    fake_fs_files(&ctrl_fs);
    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    stream_start = ctrl_log.consumed;

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"nosuch.bin", 10u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request, RQFT_MSG_PUT_REQ);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_OPEN);
    CHECK_EQ_INT(ctrl_log.wire_len - stream_start, 0);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 20u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 20u);
    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    check_committed(&resp_fs, "a.data", (const uint8_t *)"alpha", 5u);
}

static void test_put_read_error_during_hash_fails_op_without_wire_traffic(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    size_t stream_start;

    fake_fs_files(&ctrl_fs);
    strcpy(ctrl_fs.fail_read_path, "a.data");
    ctrl_fs.fail_read_at = 2u;
    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    stream_start = ctrl_log.consumed;

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_READ);
    CHECK_EQ_INT(ctrl_log.wire_len - stream_start, 0);
    CHECK_EQ_INT(ctrl_fs.read_index, -1);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_put_read_error_mid_stream_sends_err_and_fails_file(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t big[1536];

    /* The hash pass reads the whole file; the stream pass fails at 600. */
    memset(big, 0, sizeof(big));
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&ctrl_fs, "big.bin", big, sizeof(big));
    ctrl_fs.fail_read_total = sizeof(big) + 600u;
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_READ);
    CHECK_EQ_INT(resp_fs.discarded, 1);
    CHECK(fake_find(&resp_fs, (const uint8_t *)"big.bin", 7u) < 0);
    CHECK_EQ_INT(ctrl_fs.read_index, -1);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_put_reopen_failure_after_put_ok_sends_err(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    fake_fs_files(&ctrl_fs);
    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_OK);
    while (rqft_session_work_pending(&ctrl)) {
        rqft_session_poll(&ctrl, 10u);
    }
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    strcpy(ctrl_fs.fail_open_read, "a.data");

    rqft_session_receive(&ctrl, resp_log.wire + resp_log.consumed,
                         resp_log.wire_len - resp_log.consumed, 10u);
    resp_log.consumed = resp_log.wire_len;
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_OPEN);
    CHECK_EQ_INT(resp_fs.discarded, 1);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_session_end_mid_put_discards_responder_temp(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;
    uint8_t reason = RQFT_ABORT_E_USER;
    uint8_t wire[16];
    size_t wire_len = 0u;

    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, &resp_fs, 4u);
    feed_put_req(&resp, 0u, 9u, 0u, "f.bin", 10u);
    feed_file_data(&resp, 1u, "abc", 10u);
    CHECK(resp_fs.writing);

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ABORT, SID, 0u, 0u, &reason, 1u,
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);
    rqft_session_receive(&resp, wire, wire_len, 11u);

    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(resp_log.ended_from_peer);
    CHECK(!resp_fs.writing);
    CHECK_EQ_INT(resp_fs.discarded, 1);
}

static void test_session_end_mid_hash_releases_read_cursor(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t big[1536];
    uint8_t reason = RQFT_ABORT_E_USER;
    uint8_t wire[16];
    size_t wire_len = 0u;

    memset(big, 0, sizeof(big));
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&ctrl_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    CHECK(ctrl_fs.read_index >= 0);

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ABORT, SID, 0u, 0u, &reason, 1u,
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);
    rqft_session_receive(&ctrl, wire, wire_len, 11u);

    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(ctrl_log.ended_from_peer);
    CHECK_EQ_INT(ctrl_fs.read_index, -1);
}

static void test_request_put_validates_role_state_path_and_fs(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    fake_fs_files(&ctrl_fs);
    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_put(&resp, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"../up", 5u, 10u),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, NULL, 0u, 10u), RQFT_ERR_MALFORMED);

    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 10u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 11u),
                 RQFT_ERR_MALFORMED);

    /* A controller without filesystem callbacks cannot source the file. */
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, &resp_fs, 4u);
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_ERR_MALFORMED);
}

static void test_progress_reports_put_hash_then_stream_on_both_sides(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    rqft_transfer_progress_t progress;
    uint8_t big[6144]; /* more than one RQFT_CRC_BUDGET_PER_POLL hash slice */

    for (size_t i = 0u; i < sizeof(big); i++) {
        big[i] = (uint8_t)(i * 3u);
    }
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&ctrl_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    CHECK(!rqft_session_progress(&ctrl, &progress));
    CHECK(!rqft_session_progress(&resp, &progress));

    /* Hash phase totals come from the filesystem's open_read size. */
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    CHECK(rqft_session_progress(&ctrl, &progress));
    CHECK_EQ_INT(progress.request, RQFT_MSG_PUT_REQ);
    CHECK_EQ_INT(progress.phase, RQFT_PROGRESS_HASH);
    CHECK_EQ_INT(progress.done, 0);
    CHECK(progress.has_total);
    CHECK_EQ_INT(progress.total, sizeof(big));

    rqft_session_poll(&ctrl, 10u); /* one bounded hash slice */
    CHECK(rqft_session_progress(&ctrl, &progress));
    CHECK_EQ_INT(progress.phase, RQFT_PROGRESS_HASH);
    CHECK_EQ_INT(progress.done, RQFT_CRC_BUDGET_PER_POLL);
    CHECK_EQ_INT(progress.total, sizeof(big));

    rqft_session_poll(&ctrl, 10u); /* hash finishes; PUT_REQ goes out */
    CHECK(rqft_session_progress(&ctrl, &progress));
    CHECK_EQ_INT(progress.phase, RQFT_PROGRESS_STREAM);
    CHECK_EQ_INT(progress.done, 0);
    CHECK(progress.has_total);
    CHECK_EQ_INT(progress.total, sizeof(big));

    /* PUT_REQ -> PUT_OK; the responder now expects the promised size. */
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    CHECK(rqft_session_progress(&resp, &progress));
    CHECK_EQ_INT(progress.request, RQFT_MSG_PUT_REQ);
    CHECK_EQ_INT(progress.phase, RQFT_PROGRESS_STREAM);
    CHECK_EQ_INT(progress.done, 0);
    CHECK(progress.has_total);
    CHECK_EQ_INT(progress.total, sizeof(big));

    /* PUT_OK opens the stream; the first window of chunks goes out. */
    rqft_session_receive(&ctrl, resp_log.wire + resp_log.consumed,
                         resp_log.wire_len - resp_log.consumed, 10u);
    resp_log.consumed = resp_log.wire_len;
    CHECK(rqft_session_progress(&ctrl, &progress));
    CHECK_EQ_INT(progress.phase, RQFT_PROGRESS_STREAM);
    CHECK(progress.done > 0u && progress.done < sizeof(big));
    CHECK_EQ_INT(progress.total, sizeof(big));

    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    CHECK(rqft_session_progress(&resp, &progress));
    CHECK(progress.done > 0u && progress.done < sizeof(big));
    CHECK_EQ_INT(progress.total, sizeof(big));

    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);
    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    CHECK(!rqft_session_progress(&ctrl, &progress));
    CHECK(!rqft_session_progress(&resp, &progress));
}

static void test_progress_put_open_failure_reports_no_total(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    rqft_transfer_progress_t progress;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    /* Missing source: the open failure surfaces at the next poll. */
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_OK);
    CHECK(rqft_session_progress(&ctrl, &progress));
    CHECK_EQ_INT(progress.phase, RQFT_PROGRESS_HASH);
    CHECK_EQ_INT(progress.done, 0);
    CHECK(!progress.has_total);

    rqft_session_poll(&ctrl, 10u);
    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK(!rqft_session_progress(&ctrl, &progress));
}

int main(void)
{
    test_put_transfers_whole_file();
    test_put_streams_full_chunks_after_hashing();
    test_put_hash_work_bounded_per_poll();
    test_put_zero_byte_file();
    test_put_writes_temp_then_commits_on_file_end();
    test_put_verification_mismatch_answers_put_done_crc_err();
    test_file_end_crc_mismatching_put_req_aborts();
    test_put_write_failure_discards_temp_and_answers_put_done_err();
    test_put_commit_failure_answers_put_done_err();
    test_put_err_on_open_write_fails_op_and_batch_continues();
    test_responder_rejects_invalid_put_path_and_missing_fs();
    test_unexpected_message_mid_stream_aborts_responder();
    test_message_mid_put_stream_aborts_controller();
    test_put_open_read_failure_fails_op_without_wire_traffic();
    test_put_read_error_during_hash_fails_op_without_wire_traffic();
    test_put_read_error_mid_stream_sends_err_and_fails_file();
    test_put_reopen_failure_after_put_ok_sends_err();
    test_session_end_mid_put_discards_responder_temp();
    test_session_end_mid_hash_releases_read_cursor();
    test_request_put_validates_role_state_path_and_fs();
    test_progress_reports_put_hash_then_stream_on_both_sides();
    test_progress_put_open_failure_reports_no_total();
    TEST_MAIN_END();
}
