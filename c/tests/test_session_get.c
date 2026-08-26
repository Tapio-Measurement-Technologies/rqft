// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session_get.c - GET operation tests for SPEC.md section 5.4. */
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
    size_t get_done_events;
    uint8_t get_done_path[RQFT_MAX_PATH];
    size_t get_done_path_len;
    uint32_t get_done_size;
    uint32_t get_done_crc;
    size_t get_served_events;
    uint8_t get_served_path[RQFT_MAX_PATH];
    size_t get_served_path_len;
    uint32_t get_served_size;
    uint32_t get_served_crc;
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
    case RQFT_SESSION_EVENT_GET_DONE:
        log->get_done_events++;
        CHECK(event->u.get_done.path_len <= RQFT_MAX_PATH);
        memcpy(log->get_done_path, event->u.get_done.path, event->u.get_done.path_len);
        log->get_done_path_len = event->u.get_done.path_len;
        log->get_done_size = event->u.get_done.size;
        log->get_done_crc = event->u.get_done.crc32;
        break;
    case RQFT_SESSION_EVENT_GET_SERVED:
        log->get_served_events++;
        CHECK(event->u.get_served.path_len <= RQFT_MAX_PATH);
        memcpy(log->get_served_path, event->u.get_served.path, event->u.get_served.path_len);
        log->get_served_path_len = event->u.get_served.path_len;
        log->get_served_size = event->u.get_served.size;
        log->get_served_crc = event->u.get_served.crc32;
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
#define FAKE_FILE_CAP 4096u

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
    char fail_read_path[RQFT_MAX_PATH + 1u];
    size_t fail_read_at;
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
    int index = fake_find(fs, path, path_len);
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
    CHECK(fs->writing);
    fs->writing = false;
    if (fs->fail_commit) {
        fs->discarded++;
        return false;
    }
    int index = fake_find(fs, (const uint8_t *)fs->write_path, strlen(fs->write_path));
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
        if (rqft_session_work_pending(ctrl)) {
            rqft_session_poll(ctrl, now_ms);
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

static void check_committed(fake_fs_t *fs, const char *path, const uint8_t *data, size_t size)
{
    int index = fake_find(fs, (const uint8_t *)path, strlen(path));
    CHECK(index >= 0);
    if (index >= 0) {
        CHECK_EQ_INT(fs->files[index].size, size);
        CHECK(size == 0u || memcmp(fs->files[index].data, data, size) == 0);
    }
}

static void fake_fs_files(fake_fs_t *fs)
{
    memset(fs, 0, sizeof(*fs));
    fake_add(fs, "a.data", (const uint8_t *)"alpha", 5u);
    fake_add(fs, "logs/2025/run1.data", (const uint8_t *)"first run", 9u);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */

static void test_get_transfers_whole_file(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"logs/2025/run1.data",
                                          19u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    CHECK_EQ_INT(ctrl_log.get_done_path_len, 19);
    CHECK(memcmp(ctrl_log.get_done_path, "logs/2025/run1.data", 19u) == 0);
    CHECK_EQ_INT(ctrl_log.get_done_size, 9);
    CHECK_EQ_INT(ctrl_log.get_done_crc, rqft_crc32((const uint8_t *)"first run", 9u));
    CHECK_EQ_INT(resp_log.get_served_events, 1);
    CHECK_EQ_INT(resp_log.get_served_path_len, 19);
    CHECK(memcmp(resp_log.get_served_path, "logs/2025/run1.data", 19u) == 0);
    CHECK_EQ_INT(resp_log.get_served_size, 9);
    CHECK_EQ_INT(resp_log.get_served_crc, rqft_crc32((const uint8_t *)"first run", 9u));
    check_committed(&ctrl_fs, "logs/2025/run1.data", (const uint8_t *)"first run", 9u);
    CHECK(!ctrl_fs.writing);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_get_streams_full_chunks_with_streaming_crc(void)
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
    fake_add(&resp_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    stream_start = resp_log.consumed;

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    CHECK_EQ_INT(ctrl_log.get_done_size, 1536);
    CHECK_EQ_INT(ctrl_log.get_done_crc, rqft_crc32(big, sizeof(big)));
    check_committed(&ctrl_fs, "big.bin", big, sizeof(big));

    /* 1536 bytes at a 511-byte chunk: FILE_INFO, 511+511+511+3, FILE_END. */
    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_INFO);
    CHECK_EQ_INT(msg.u.file_info.size, 1536);
    for (size_t i = 0u; i < 4u; i++) {
        CHECK(nth_data_message(resp_log.wire + stream_start,
                               resp_log.wire_len - stream_start, 1u + i, &msg));
        CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_DATA);
        CHECK_EQ_INT(msg.u.file_data.len, i < 3u ? 511u : 3u);
    }
    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 5u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_END);
    CHECK_EQ_INT(msg.u.file_end.crc32, rqft_crc32(big, sizeof(big)));

    /* The responder hashed while reading: no read spans the file. */
    CHECK(resp_fs.max_read_len <= 511u);
}

static void test_get_zero_byte_file(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    size_t stream_start;
    rqft_msg_t msg;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&resp_fs, "empty.bin", NULL, 0u);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    stream_start = resp_log.consumed;

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"empty.bin", 9u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    CHECK_EQ_INT(ctrl_log.get_done_size, 0);
    CHECK_EQ_INT(ctrl_log.get_done_crc, 0);
    CHECK_EQ_INT(resp_log.get_served_events, 1);
    CHECK_EQ_INT(resp_log.get_served_size, 0);
    CHECK_EQ_INT(resp_log.get_served_crc, 0);
    check_committed(&ctrl_fs, "empty.bin", NULL, 0u);
    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_INFO);
    CHECK_EQ_INT(msg.u.file_info.size, 0);
    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 1u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_FILE_END);
    CHECK_EQ_INT(msg.u.file_end.crc32, 0);
    CHECK_EQ_INT(count_messages(resp_log.wire + stream_start,
                                resp_log.wire_len - stream_start, RQFT_MSG_FILE_DATA),
                 0);
}

/* Feed the controller one crafted FILE_INFO / FILE_DATA / FILE_END. */
static void feed_file_info(rqft_session_t *ctrl, uint8_t seq, uint32_t size, uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_FILE_INFO;
    msg.u.file_info.size = size;
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(ctrl, wire, wire_len, now_ms);
}

static void feed_file_data(rqft_session_t *ctrl, uint8_t seq, const char *data, uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_FILE_DATA;
    msg.u.file_data.data = (const uint8_t *)data;
    msg.u.file_data.len = strlen(data);
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(ctrl, wire, wire_len, now_ms);
}

static void feed_file_end(rqft_session_t *ctrl, uint8_t seq, uint32_t crc, uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_FILE_END;
    msg.u.file_end.crc32 = crc;
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(ctrl, wire, wire_len, now_ms);
}

/* Acknowledge every outbound DATA frame below seq, freeing the window. */
static void feed_ack(rqft_session_t *session, uint8_t seq, uint32_t now_ms)
{
    uint8_t wire[16];
    size_t wire_len = 0u;

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ACK, SID, seq, 0u, NULL, 0u,
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);
    rqft_session_receive(session, wire, wire_len, now_ms);
}

static void test_get_writes_temp_then_commits_on_file_end(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"f.bin", 5u, 10u), RQFT_OK);

    feed_file_info(&ctrl, 0u, 3u, 10u);
    feed_file_data(&ctrl, 1u, "ab", 10u);
    CHECK(ctrl_fs.writing);
    CHECK(fake_find(&ctrl_fs, (const uint8_t *)"f.bin", 5u) < 0);

    feed_file_data(&ctrl, 2u, "c", 10u);
    feed_file_end(&ctrl, 3u, rqft_crc32((const uint8_t *)"abc", 3u), 10u);

    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    check_committed(&ctrl_fs, "f.bin", (const uint8_t *)"abc", 3u);
    CHECK(!ctrl_fs.writing);

    /* Committing the verify answers the responder with GET_DONE(0). */
    {
        rqft_msg_t sent;
        CHECK_EQ_INT(count_messages(ctrl_log.wire, ctrl_log.wire_len, RQFT_MSG_GET_DONE), 1);
        CHECK(nth_data_message(ctrl_log.wire, ctrl_log.wire_len, 1u, &sent));
        CHECK_EQ_INT(sent.type, RQFT_MSG_GET_DONE);
        CHECK_EQ_INT(sent.u.get_done.status, 0);
    }
}

static void test_get_crc_mismatch_retries_once_then_fails_batch_continues(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"f.bin", 5u, 10u), RQFT_OK);

    /* First stream ends with a lying CRC: silent discard + one retry,
     * with GET_DONE(E_CRC_FILE) reported ahead of the retry GET_REQ. */
    feed_file_info(&ctrl, 0u, 3u, 10u);
    feed_file_data(&ctrl, 1u, "abc", 10u);
    feed_file_end(&ctrl, 2u, 0xDEADBEEFu, 10u);
    CHECK_EQ_INT(ctrl_log.op_failed_events, 0);
    CHECK_EQ_INT(ctrl_fs.discarded, 1);
    CHECK_EQ_INT(count_messages(ctrl_log.wire, ctrl_log.wire_len, RQFT_MSG_GET_REQ), 2);
    {
        rqft_msg_t sent;
        CHECK(nth_data_message(ctrl_log.wire, ctrl_log.wire_len, 1u, &sent));
        CHECK_EQ_INT(sent.type, RQFT_MSG_GET_DONE);
        CHECK_EQ_INT(sent.u.get_done.status, RQFT_E_CRC_FILE);
        CHECK(nth_data_message(ctrl_log.wire, ctrl_log.wire_len, 2u, &sent));
        CHECK_EQ_INT(sent.type, RQFT_MSG_GET_REQ);
    }

    /* Second mismatch surfaces the per-file error; the session lives. */
    feed_file_info(&ctrl, 3u, 3u, 20u);
    feed_file_data(&ctrl, 4u, "abc", 20u);
    feed_file_end(&ctrl, 5u, 0xDEADBEEFu, 20u);
    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request, RQFT_MSG_GET_REQ);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_CRC_FILE);
    CHECK_EQ_INT(ctrl_log.op_failed_path_len, 5);
    CHECK(memcmp(ctrl_log.op_failed_path, "f.bin", 5u) == 0);
    CHECK_EQ_INT(ctrl_fs.discarded, 2);
    CHECK(fake_find(&ctrl_fs, (const uint8_t *)"f.bin", 5u) < 0);
    CHECK(rqft_session_active(&ctrl));

    /* The failed operation releases the slot; the next GET commits.
     * Every FILE_END processed produced exactly one GET_DONE. Ack the
     * four unacked frames so the window can carry the last exchange. */
    feed_ack(&ctrl, 4u, 30u);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 30u), RQFT_OK);
    feed_file_info(&ctrl, 6u, 5u, 30u);
    feed_file_data(&ctrl, 7u, "alpha", 30u);
    feed_file_end(&ctrl, 8u, rqft_crc32((const uint8_t *)"alpha", 5u), 30u);
    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    check_committed(&ctrl_fs, "a.data", (const uint8_t *)"alpha", 5u);
    CHECK_EQ_INT(count_messages(ctrl_log.wire, ctrl_log.wire_len, RQFT_MSG_GET_DONE), 3);
}

static void test_get_size_mismatch_counts_as_verification_failure(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"f.bin", 5u, 10u), RQFT_OK);

    feed_file_info(&ctrl, 0u, 5u, 10u);
    feed_file_data(&ctrl, 1u, "ab", 10u);
    feed_file_end(&ctrl, 2u, rqft_crc32((const uint8_t *)"ab", 2u), 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 0);
    CHECK_EQ_INT(ctrl_fs.discarded, 1);
    CHECK_EQ_INT(count_messages(ctrl_log.wire, ctrl_log.wire_len, RQFT_MSG_GET_REQ), 2);
}

static void test_get_err_on_open_fails_op_and_batch_continues(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"nosuch.bin", 10u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request, RQFT_MSG_GET_REQ);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_OPEN);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 20u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 20u);
    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    check_committed(&ctrl_fs, "a.data", (const uint8_t *)"alpha", 5u);
}

static void test_get_responder_read_error_mid_stream_answers_err(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t big[1536];

    memset(big, 0, sizeof(big));
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&resp_fs, "big.bin", big, sizeof(big));
    strcpy(resp_fs.fail_read_path, "big.bin");
    resp_fs.fail_read_at = 600u; /* first chunk fine, second read fails */
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_READ);
    CHECK_EQ_INT(ctrl_fs.discarded, 1);
    CHECK_EQ_INT(resp_fs.read_index, -1);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_get_write_failure_drains_stream_and_fails_file(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    ctrl_fs.fail_write = true;
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_WRITE);
    CHECK_EQ_INT(ctrl_fs.discarded, 1);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));

    ctrl_fs.fail_write = false;
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 20u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 20u);
    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    check_committed(&ctrl_fs, "a.data", (const uint8_t *)"alpha", 5u);
}

static void test_get_open_write_failure_drains_stream_and_fails_file(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    strcpy(ctrl_fs.fail_open_write, "a.data");
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_OPEN);
    CHECK_EQ_INT(ctrl_fs.discarded, 0);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

static void test_get_commit_failure_sends_get_done_write_error(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    ctrl_fs.fail_commit = true;
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_WRITE);
    CHECK_EQ_INT(resp_log.get_served_events, 0);
    CHECK_EQ_INT(resp_log.op_failed_events, 1);
    CHECK_EQ_INT(resp_log.op_failed_request, RQFT_MSG_GET_REQ);
    CHECK_EQ_INT(resp_log.op_failed_code, RQFT_E_FS_WRITE);
    CHECK_EQ_INT(resp_log.op_failed_path_len, 6);
    CHECK(memcmp(resp_log.op_failed_path, "a.data", 6u) == 0);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));
}

/* Feed one GET_REQ and pump the responder through FILE_END. */
static void serve_get(rqft_session_t *resp,
                      session_log_t *resp_log,
                      uint8_t seq,
                      const char *path,
                      uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_GET_REQ;
    msg.u.get_req.path = (const uint8_t *)path;
    msg.u.get_req.path_len = strlen(path);
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(resp, wire, wire_len, now_ms);
    for (int i = 0; i < 100; i++) {
        if (!rqft_session_work_pending(resp)) {
            (void)resp_log;
            return;
        }
        rqft_session_poll(resp, now_ms);
    }
    CHECK(false);
}

static void feed_get_done(rqft_session_t *resp, uint8_t seq, uint8_t status, uint32_t now_ms)
{
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_GET_DONE;
    msg.u.get_done.status = status;
    wire_len = data_frame(seq, &msg, wire, sizeof(wire));
    rqft_session_receive(resp, wire, wire_len, now_ms);
}

static void test_responder_surfaces_nonzero_get_done_as_op_failed(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    serve_get(&resp, &resp_log, 0u, "a.data", 10u);

    feed_get_done(&resp, 1u, RQFT_E_CRC_FILE, 11u);

    CHECK_EQ_INT(resp_log.get_served_events, 0);
    CHECK_EQ_INT(resp_log.op_failed_events, 1);
    CHECK_EQ_INT(resp_log.op_failed_request, RQFT_MSG_GET_REQ);
    CHECK_EQ_INT(resp_log.op_failed_code, RQFT_E_CRC_FILE);
    CHECK_EQ_INT(resp_log.op_failed_path_len, 6);
    CHECK(memcmp(resp_log.op_failed_path, "a.data", 6u) == 0);
    CHECK(rqft_session_active(&resp));
}

static void test_responder_answers_stray_get_done_with_bad_state(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    rqft_msg_t msg;
    size_t stream_start;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    stream_start = resp_log.consumed;

    feed_get_done(&resp, 0u, 0u, 10u);

    CHECK_EQ_INT(resp_log.get_served_events, 0);
    CHECK_EQ_INT(resp_log.op_failed_events, 0);
    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_BAD_STATE);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_GET_DONE);
    CHECK(rqft_session_active(&resp));
}

static void test_responder_consumes_get_done_verdict_only_once(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    rqft_msg_t msg;
    size_t stream_start;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    serve_get(&resp, &resp_log, 0u, "a.data", 10u);

    feed_get_done(&resp, 1u, 0u, 11u);
    CHECK_EQ_INT(resp_log.get_served_events, 1);
    CHECK_EQ_INT(resp_log.get_served_path_len, 6);
    CHECK(memcmp(resp_log.get_served_path, "a.data", 6u) == 0);
    CHECK_EQ_INT(resp_log.get_served_size, 5);
    CHECK_EQ_INT(resp_log.get_served_crc, rqft_crc32((const uint8_t *)"alpha", 5u));

    stream_start = resp_log.wire_len;
    feed_get_done(&resp, 2u, 0u, 12u);
    CHECK_EQ_INT(resp_log.get_served_events, 1);
    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_BAD_STATE);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_GET_DONE);
    CHECK(rqft_session_active(&resp));
}

static void test_new_request_supersedes_served_get_record(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;
    size_t stream_start;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    serve_get(&resp, &resp_log, 0u, "a.data", 10u);
    /* Ack the served frames so the send window can carry the ERR later. */
    feed_ack(&resp, 3u, 10u);

    /* A non-conforming controller skips GET_DONE and lists instead: the
     * served-GET record dies with the new request. */
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_REQ;
    msg.u.list_req.root_len = 0u;
    wire_len = data_frame(1u, &msg, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 11u);
    for (int i = 0; i < 100; i++) {
        if (!rqft_session_work_pending(&resp)) {
            break;
        }
        rqft_session_poll(&resp, 11u);
    }
    feed_ack(&resp, 6u, 11u);

    stream_start = resp_log.wire_len;
    feed_get_done(&resp, 2u, 0u, 12u);
    CHECK_EQ_INT(resp_log.get_served_events, 0);
    CHECK(nth_data_message(resp_log.wire + stream_start,
                           resp_log.wire_len - stream_start, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_BAD_STATE);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_GET_DONE);
    CHECK(rqft_session_active(&resp));
}

static void test_get_done_mid_get_stream_aborts_responder(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t big[1536];

    /* window=1 wedges the responder mid-stream: FILE_INFO stays unacked. */
    memset(big, 0, sizeof(big));
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&resp_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 1u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    CHECK(rqft_session_work_pending(&resp));

    feed_get_done(&resp, 1u, 0u, 11u);

    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_PROTO);
    CHECK(!resp_log.ended_from_peer);
    CHECK_EQ_INT(rqft_session_state(&resp), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(resp_fs.read_index, -1);
}

static void test_responder_rejects_nonzero_offset_and_bad_path(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_GET_REQ;
    msg.u.get_req.offset = 5u;
    msg.u.get_req.path = (const uint8_t *)"a.data";
    msg.u.get_req.path_len = 6u;
    wire_len = data_frame(0u, &msg, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 10u);

    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_UNSUPPORTED);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_GET_REQ);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_GET_REQ;
    msg.u.get_req.offset = 0u;
    msg.u.get_req.path = (const uint8_t *)"../up";
    msg.u.get_req.path_len = 5u;
    wire_len = data_frame(1u, &msg, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 10u);

    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 1u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_PATH);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_GET_REQ);
    CHECK(rqft_session_active(&resp));
}

/* One unexpected mid-stream message must abort E_PROTO with the temp
 * discarded; run for both a wrong op message and a PING. */
static void check_ctrl_mid_stream_abort(const rqft_msg_t *unexpected)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t wire[600];
    size_t wire_len;
    rqft_msg_t msg;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"f.bin", 5u, 10u), RQFT_OK);

    feed_file_info(&ctrl, 0u, 10u, 10u);
    wire_len = data_frame(1u, unexpected, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 10u);

    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_PROTO);
    CHECK(!ctrl_log.ended_from_peer);
    CHECK_EQ_INT(rqft_session_state(&ctrl), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(ctrl_fs.discarded, 1);

    /* The last outbound frame is the best-effort ABORT(E_PROTO). */
    {
        size_t pos = ctrl_log.wire_len;
        size_t end;
        uint8_t decoded[16];
        size_t decoded_len = 0u;
        while (pos > 0u && ctrl_log.wire[pos - 1u] == 0u) {
            pos--;
        }
        end = pos;
        while (pos > 0u && ctrl_log.wire[pos - 1u] != 0u) {
            pos--;
        }
        CHECK_EQ_INT(rqft_cobs_decode(ctrl_log.wire + pos, end - pos, decoded,
                                      sizeof(decoded), &decoded_len),
                     RQFT_OK);
        CHECK_EQ_INT(decoded[0], RQFT_FRAME_ABORT);
        CHECK_EQ_INT(decoded[4], RQFT_ABORT_E_PROTO);
    }
    (void)msg;
}

static void test_unexpected_message_mid_stream_aborts_controller(void)
{
    rqft_msg_t msg;

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_ENTRY;
    msg.u.list_entry.path = (const uint8_t *)"x";
    msg.u.list_entry.path_len = 1u;
    msg.u.list_entry.size = 1u;
    check_ctrl_mid_stream_abort(&msg);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PING;
    msg.u.token.token = 7u;
    check_ctrl_mid_stream_abort(&msg);
}

static void test_message_mid_get_stream_aborts_responder(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t big[1536];
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    /* window=1 wedges the responder mid-stream: FILE_INFO stays unacked. */
    memset(big, 0, sizeof(big));
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&resp_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 1u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    CHECK(rqft_session_work_pending(&resp));

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_REQ;
    msg.u.list_req.root_len = 0u;
    wire_len = data_frame(1u, &msg, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 11u);

    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_PROTO);
    CHECK(!resp_log.ended_from_peer);
    CHECK_EQ_INT(rqft_session_state(&resp), RQFT_SESSION_ENDED);
    CHECK_EQ_INT(resp_fs.read_index, -1);
}

static void test_session_end_mid_get_discards_temp(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    uint8_t reason = RQFT_ABORT_E_USER;
    uint8_t wire[16];
    size_t wire_len = 0u;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"f.bin", 5u, 10u), RQFT_OK);
    feed_file_info(&ctrl, 0u, 9u, 10u);
    feed_file_data(&ctrl, 1u, "abc", 10u);
    CHECK(ctrl_fs.writing);

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ABORT, SID, 0u, 0u, &reason, 1u,
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);
    rqft_session_receive(&ctrl, wire, wire_len, 11u);

    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(ctrl_log.ended_from_peer);
    CHECK(!ctrl_fs.writing);
    CHECK_EQ_INT(ctrl_fs.discarded, 1);
}

static void test_request_get_validates_role_state_path_and_fs(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;

    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_get(&resp, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"../up", 5u, 10u),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, NULL, 0u, 10u), RQFT_ERR_MALFORMED);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 10u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 11u),
                 RQFT_ERR_MALFORMED);
}

static void test_request_get_requires_staging_callbacks(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t resp_fs;

    /* A controller without filesystem callbacks cannot stage the file. */
    fake_fs_files(&resp_fs);
    establish_pair(&ctrl, &ctrl_log, NULL, &resp, &resp_log, &resp_fs, 4u);

    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 10u),
                 RQFT_ERR_MALFORMED);
}

static void test_progress_reports_get_byte_counters_on_both_sides(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t ctrl_fs, resp_fs;
    rqft_transfer_progress_t progress;
    uint8_t big[4000];

    for (size_t i = 0u; i < sizeof(big); i++) {
        big[i] = (uint8_t)(i * 7u);
    }
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    fake_add(&resp_fs, "big.bin", big, sizeof(big));
    establish_pair(&ctrl, &ctrl_log, &ctrl_fs, &resp, &resp_log, &resp_fs, 4u);
    CHECK(!rqft_session_progress(&ctrl, &progress));
    CHECK(!rqft_session_progress(&resp, &progress));

    /* Awaiting FILE_INFO: the download exists but its size is unknown. */
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"big.bin", 7u, 10u),
                 RQFT_OK);
    CHECK(rqft_session_progress(&ctrl, &progress));
    CHECK_EQ_INT(progress.request, RQFT_MSG_GET_REQ);
    CHECK_EQ_INT(progress.phase, RQFT_PROGRESS_STREAM);
    CHECK_EQ_INT(progress.done, 0);
    CHECK(!progress.has_total);

    /* Responder serves the first window: FILE_INFO plus three chunks. */
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    CHECK(rqft_session_progress(&resp, &progress));
    CHECK_EQ_INT(progress.request, RQFT_MSG_GET_REQ);
    CHECK_EQ_INT(progress.phase, RQFT_PROGRESS_STREAM);
    CHECK(progress.done > 0u && progress.done < sizeof(big));
    CHECK(progress.has_total);
    CHECK_EQ_INT(progress.total, sizeof(big));

    rqft_session_receive(&ctrl, resp_log.wire + resp_log.consumed,
                         resp_log.wire_len - resp_log.consumed, 10u);
    resp_log.consumed = resp_log.wire_len;
    CHECK(rqft_session_progress(&ctrl, &progress));
    CHECK(progress.done > 0u && progress.done < sizeof(big));
    CHECK(progress.has_total);
    CHECK_EQ_INT(progress.total, sizeof(big));

    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);
    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    CHECK(!rqft_session_progress(&ctrl, &progress));
    CHECK(!rqft_session_progress(&resp, &progress));
}

int main(void)
{
    test_get_transfers_whole_file();
    test_get_streams_full_chunks_with_streaming_crc();
    test_get_zero_byte_file();
    test_get_writes_temp_then_commits_on_file_end();
    test_get_crc_mismatch_retries_once_then_fails_batch_continues();
    test_get_size_mismatch_counts_as_verification_failure();
    test_get_err_on_open_fails_op_and_batch_continues();
    test_get_responder_read_error_mid_stream_answers_err();
    test_get_write_failure_drains_stream_and_fails_file();
    test_get_open_write_failure_drains_stream_and_fails_file();
    test_get_commit_failure_sends_get_done_write_error();
    test_responder_surfaces_nonzero_get_done_as_op_failed();
    test_responder_answers_stray_get_done_with_bad_state();
    test_responder_consumes_get_done_verdict_only_once();
    test_new_request_supersedes_served_get_record();
    test_get_done_mid_get_stream_aborts_responder();
    test_responder_rejects_nonzero_offset_and_bad_path();
    test_unexpected_message_mid_stream_aborts_controller();
    test_message_mid_get_stream_aborts_responder();
    test_session_end_mid_get_discards_temp();
    test_request_get_validates_role_state_path_and_fs();
    test_request_get_requires_staging_callbacks();
    test_progress_reports_get_byte_counters_on_both_sides();
    TEST_MAIN_END();
}
