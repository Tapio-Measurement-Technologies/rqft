// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session_traces.c - golden session trace replay tests. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WIRE_CAP 16384u
#define TRACE_MAX_ENTRIES 32u
#define TRACE_LINE_CAP 2048u
#define FAKE_MAX_FILES 8u
#define FAKE_FILE_CAP 4096u
#define SID 0x42u

typedef enum trace_direction {
    TRACE_C_TO_R = 0,
    TRACE_R_TO_C = 1,
} trace_direction_t;

typedef struct trace_entry {
    uint32_t now_ms;
    trace_direction_t direction;
    uint8_t data[WIRE_CAP];
    size_t len;
} trace_entry_t;

typedef struct trace_log {
    trace_entry_t entries[TRACE_MAX_ENTRIES];
    size_t count;
} trace_log_t;

typedef struct session_log {
    uint8_t wire[WIRE_CAP];
    size_t wire_len;
    size_t consumed;
    uint32_t now_ms;
    uint8_t sid_value;
    size_t established_events;
    size_t notify_events;
    uint32_t notify_flags;
    size_t list_done_events;
    uint16_t list_done_count;
    size_t get_done_events;
    uint8_t get_done_path[RQFT_MAX_PATH];
    size_t get_done_path_len;
    uint32_t get_done_size;
    uint32_t get_done_crc;
    size_t put_done_events;
    uint8_t put_done_path[RQFT_MAX_PATH];
    size_t put_done_path_len;
    uint32_t put_done_size;
    uint32_t put_done_crc;
    size_t ended_events;
    rqft_abort_reason_t ended_reason;
    bool ended_from_peer;
} session_log_t;

typedef struct fake_file {
    char path[RQFT_MAX_PATH + 1u];
    uint8_t data[FAKE_FILE_CAP];
    size_t size;
    uint32_t mtime;
} fake_file_t;

typedef struct fake_fs {
    fake_file_t files[FAKE_MAX_FILES];
    size_t file_count;
    size_t list_pos;
    int read_index;
    size_t read_pos;
    char write_path[RQFT_MAX_PATH + 1u];
    uint8_t write_buf[FAKE_FILE_CAP];
    size_t write_len;
    bool writing;
} fake_fs_t;

static void trace_append(trace_log_t *log,
                         uint32_t now_ms,
                         trace_direction_t direction,
                         const uint8_t *data,
                         size_t len)
{
    if (len == 0u) {
        return;
    }
    CHECK(log->count < TRACE_MAX_ENTRIES);
    CHECK(len <= WIRE_CAP);
    trace_entry_t *entry = &log->entries[log->count++];
    entry->now_ms = now_ms;
    entry->direction = direction;
    entry->len = len;
    memcpy(entry->data, data, len);
}

static int hex_nibble(char ch)
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

static size_t decode_hex(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t hex_len = strlen(hex);
    CHECK((hex_len % 2u) == 0u);
    CHECK((hex_len / 2u) <= out_cap);
    size_t len = hex_len / 2u;
    for (size_t i = 0u; i < len; i++) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        CHECK(hi >= 0);
        CHECK(lo >= 0);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return len;
}

static void load_trace(const char *name, trace_log_t *log)
{
    char path[512];
    char line[TRACE_LINE_CAP];
    int written = snprintf(path, sizeof(path),
                           RQFT_REPO_ROOT "/testvectors/sessions/%s.trace", name);
    CHECK(written > 0);
    CHECK((size_t)written < sizeof(path));

    FILE *file = fopen(path, "r");
    CHECK(file != NULL);
    if (file == NULL) {
        return;
    }

    memset(log, 0, sizeof(*log));
    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned int now_ms = 0u;
        char direction_text[4];
        char hex[TRACE_LINE_CAP];
        char *cursor = line;
        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        if (*cursor == '\0' || *cursor == '\n' || *cursor == '#') {
            continue;
        }
        CHECK_EQ_INT(sscanf(cursor, "%u %3s %2047s", &now_ms, direction_text, hex), 3);
        CHECK(log->count < TRACE_MAX_ENTRIES);
        trace_entry_t *entry = &log->entries[log->count++];
        entry->now_ms = now_ms;
        if (strcmp(direction_text, "C>R") == 0) {
            entry->direction = TRACE_C_TO_R;
        } else {
            CHECK_EQ_STR(direction_text, "R>C");
            entry->direction = TRACE_R_TO_C;
        }
        entry->len = decode_hex(hex, entry->data, sizeof(entry->data));
    }

    fclose(file);
}

static void check_trace_equal(const char *name, const trace_log_t *actual)
{
    trace_log_t expected;
    load_trace(name, &expected);
    CHECK_EQ_INT(actual->count, expected.count);
    size_t count = actual->count < expected.count ? actual->count : expected.count;
    for (size_t i = 0u; i < count; i++) {
        const trace_entry_t *got = &actual->entries[i];
        const trace_entry_t *want = &expected.entries[i];
        CHECK_EQ_INT(got->now_ms, want->now_ms);
        CHECK_EQ_INT(got->direction, want->direction);
        CHECK_EQ_INT(got->len, want->len);
        if (got->len == want->len) {
            CHECK(memcmp(got->data, want->data, got->len) == 0);
        }
    }
}

static void log_transmit(void *user, const uint8_t *wire, size_t wire_len)
{
    session_log_t *log = (session_log_t *)user;
    CHECK(log->wire_len + wire_len <= WIRE_CAP);
    memcpy(log->wire + log->wire_len, wire, wire_len);
    log->wire_len += wire_len;
}

static void copy_event_path(uint8_t *dst, size_t *dst_len, const uint8_t *path, size_t path_len)
{
    CHECK(path_len <= RQFT_MAX_PATH);
    if (path_len > 0u) {
        memcpy(dst, path, path_len);
    }
    *dst_len = path_len;
}

static void log_event(void *user, const rqft_session_event_t *event)
{
    session_log_t *log = (session_log_t *)user;
    switch (event->type) {
    case RQFT_SESSION_EVENT_ESTABLISHED:
        log->established_events++;
        break;
    case RQFT_SESSION_EVENT_NOTIFY:
        log->notify_events++;
        log->notify_flags = event->u.notify.flags;
        break;
    case RQFT_SESSION_EVENT_LIST_DONE:
        log->list_done_events++;
        log->list_done_count = event->u.list_done.count;
        break;
    case RQFT_SESSION_EVENT_GET_DONE:
        log->get_done_events++;
        copy_event_path(log->get_done_path, &log->get_done_path_len,
                        event->u.get_done.path, event->u.get_done.path_len);
        log->get_done_size = event->u.get_done.size;
        log->get_done_crc = event->u.get_done.crc32;
        break;
    case RQFT_SESSION_EVENT_PUT_DONE:
        log->put_done_events++;
        copy_event_path(log->put_done_path, &log->put_done_path_len,
                        event->u.put_done.path, event->u.put_done.path_len);
        log->put_done_size = event->u.put_done.size;
        log->put_done_crc = event->u.put_done.crc32;
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

static void fake_add(fake_fs_t *fs,
                     const char *path,
                     const uint8_t *data,
                     size_t size,
                     uint32_t mtime)
{
    CHECK(fs->file_count < FAKE_MAX_FILES);
    fake_file_t *file = &fs->files[fs->file_count++];
    CHECK(size <= FAKE_FILE_CAP);
    strcpy(file->path, path);
    if (size > 0u) {
        memcpy(file->data, data, size);
    }
    file->size = size;
    file->mtime = mtime;
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
    entry->mtime = file->mtime;
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
    size_t remaining = file->size - fs->read_pos;
    size_t chunk = remaining < cap ? remaining : cap;
    if (chunk > 0u) {
        memcpy(buf, file->data + fs->read_pos, chunk);
    }
    fs->read_pos += chunk;
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
    int index = fake_find(fs, (const uint8_t *)fs->write_path, strlen(fs->write_path));
    if (index < 0) {
        fake_add(fs, fs->write_path, fs->write_buf, fs->write_len, 0u);
    } else {
        CHECK(fs->write_len <= FAKE_FILE_CAP);
        memcpy(fs->files[index].data, fs->write_buf, fs->write_len);
        fs->files[index].size = fs->write_len;
    }
    return true;
}

static void fake_discard(void *user)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    fs->writing = false;
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

static uint8_t fixed_sid(void *user)
{
    return *(uint8_t *)user;
}

static void setup_endpoint(rqft_session_t *session,
                           session_log_t *log,
                           rqft_role_t role,
                           fake_fs_t *fs,
                           uint8_t sid,
                           uint8_t caps,
                           uint8_t ver_min,
                           uint8_t ver_max)
{
    rqft_session_config_t config;
    memset(log, 0, sizeof(*log));
    log->now_ms = 0u;
    memset(&config, 0, sizeof(config));
    config.role = role;
    config.ver_min = ver_min;
    config.ver_max = ver_max;
    config.max_payload = 512u;
    config.window = 4u;
    config.caps = caps;
    config.next_sid = fixed_sid;
    log->sid_value = sid;
    config.sid_user = &log->sid_value;
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

static void drain_to_peer(rqft_session_t *peer,
                          session_log_t *src_log,
                          session_log_t *peer_log,
                          trace_log_t *capture,
                          trace_direction_t direction,
                          uint32_t record_now_ms,
                          uint32_t receive_now_ms)
{
    size_t len = src_log->wire_len - src_log->consumed;
    if (len == 0u) {
        return;
    }
    trace_append(capture, record_now_ms, direction, src_log->wire + src_log->consumed, len);
    peer_log->now_ms = receive_now_ms;
    rqft_session_receive(peer, src_log->wire + src_log->consumed, len, receive_now_ms);
    src_log->consumed = src_log->wire_len;
}

static bool drain_if_ready(rqft_session_t *peer,
                           session_log_t *src_log,
                           session_log_t *peer_log,
                           trace_log_t *capture,
                           trace_direction_t direction,
                           uint32_t now_ms)
{
    size_t before = src_log->consumed;
    drain_to_peer(peer, src_log, peer_log, capture, direction, now_ms, now_ms);
    return src_log->consumed != before;
}

static void poll_endpoint(rqft_session_t *session, session_log_t *log, uint32_t now_ms)
{
    log->now_ms = now_ms;
    rqft_session_poll(session, now_ms);
}

static void shuttle(rqft_session_t *ctrl,
                    session_log_t *ctrl_log,
                    rqft_session_t *resp,
                    session_log_t *resp_log,
                    trace_log_t *capture,
                    uint32_t now_ms)
{
    for (int i = 0; i < 400; i++) {
        bool progressed = false;
        if (drain_if_ready(resp, ctrl_log, resp_log, capture, TRACE_C_TO_R, now_ms)) {
            progressed = true;
        }
        if (rqft_session_work_pending(resp)) {
            poll_endpoint(resp, resp_log, now_ms);
            progressed = true;
        }
        if (drain_if_ready(ctrl, resp_log, ctrl_log, capture, TRACE_R_TO_C, now_ms)) {
            progressed = true;
        }
        if (rqft_session_work_pending(ctrl)) {
            poll_endpoint(ctrl, ctrl_log, now_ms);
            progressed = true;
        }
        if (!progressed) {
            return;
        }
    }
    CHECK(false);
}

static void check_file(fake_fs_t *fs, const char *path, const uint8_t *data, size_t size)
{
    int index = fake_find(fs, (const uint8_t *)path, strlen(path));
    CHECK(index >= 0);
    if (index >= 0) {
        CHECK_EQ_INT(fs->files[index].size, size);
        CHECK(memcmp(fs->files[index].data, data, size) == 0);
    }
}

static void test_hello_list_get_trace(void)
{
    trace_log_t capture;
    rqft_session_t ctrl;
    rqft_session_t resp;
    session_log_t ctrl_log;
    session_log_t resp_log;
    fake_fs_t ctrl_fs;
    fake_fs_t resp_fs;

    memset(&capture, 0, sizeof(capture));
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    resp_fs.read_index = -1;
    ctrl_fs.read_index = -1;
    fake_add(&resp_fs, "a.data", (const uint8_t *)"alpha", 5u, 1735689600u);
    fake_add(&resp_fs, "logs/run1.data", (const uint8_t *)"first run", 9u, 0u);

    setup_endpoint(&ctrl, &ctrl_log, RQFT_ROLE_CONTROLLER, &ctrl_fs, SID, 0u, 1u, 1u);
    setup_endpoint(&resp, &resp_log, RQFT_ROLE_RESPONDER, &resp_fs, SID, 0u, 1u, 1u);

    ctrl_log.now_ms = 0u;
    CHECK_EQ_INT(rqft_session_start(&ctrl, 0u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, &capture, 0u);

    ctrl_log.now_ms = 10u;
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, &capture, 10u);
    CHECK_EQ_INT(ctrl_log.list_done_events, 1);
    CHECK_EQ_INT(ctrl_log.list_done_count, 2);

    ctrl_log.now_ms = 20u;
    CHECK_EQ_INT(rqft_session_request_get(&ctrl, (const uint8_t *)"a.data", 6u, 20u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, &capture, 20u);
    CHECK_EQ_INT(ctrl_log.get_done_events, 1);
    CHECK_EQ_INT(ctrl_log.get_done_size, 5u);
    CHECK_EQ_INT(ctrl_log.get_done_crc, 0xD0E0396Au);
    check_file(&ctrl_fs, "a.data", (const uint8_t *)"alpha", 5u);

    check_trace_equal("hello_list_get", &capture);
}

static void test_put_trace(void)
{
    trace_log_t capture;
    rqft_session_t ctrl;
    rqft_session_t resp;
    session_log_t ctrl_log;
    session_log_t resp_log;
    fake_fs_t ctrl_fs;
    fake_fs_t resp_fs;

    memset(&capture, 0, sizeof(capture));
    memset(&ctrl_fs, 0, sizeof(ctrl_fs));
    memset(&resp_fs, 0, sizeof(resp_fs));
    ctrl_fs.read_index = -1;
    resp_fs.read_index = -1;
    fake_add(&ctrl_fs, "upload.bin", (const uint8_t *)"bravo-data", 10u, 0u);

    setup_endpoint(&ctrl, &ctrl_log, RQFT_ROLE_CONTROLLER, &ctrl_fs, SID, 0u, 1u, 1u);
    setup_endpoint(&resp, &resp_log, RQFT_ROLE_RESPONDER, &resp_fs, SID, 0u, 1u, 1u);

    ctrl_log.now_ms = 0u;
    CHECK_EQ_INT(rqft_session_start(&ctrl, 0u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, &capture, 0u);

    ctrl_log.now_ms = 10u;
    CHECK_EQ_INT(rqft_session_request_put(&ctrl, (const uint8_t *)"upload.bin", 10u, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, &capture, 10u);
    CHECK_EQ_INT(ctrl_log.put_done_events, 1);
    CHECK_EQ_INT(ctrl_log.put_done_size, 10u);
    CHECK_EQ_INT(ctrl_log.put_done_crc, 0x37706819u);
    check_file(&resp_fs, "upload.bin", (const uint8_t *)"bravo-data", 10u);

    check_trace_equal("put", &capture);
}

static void test_abort_trace(void)
{
    trace_log_t capture;
    rqft_session_t ctrl;
    rqft_session_t resp;
    session_log_t ctrl_log;
    session_log_t resp_log;

    memset(&capture, 0, sizeof(capture));
    setup_endpoint(&ctrl, &ctrl_log, RQFT_ROLE_CONTROLLER, NULL, SID, 0u, 1u, 1u);
    setup_endpoint(&resp, &resp_log, RQFT_ROLE_RESPONDER, NULL, SID, 0u, 2u, 2u);

    ctrl_log.now_ms = 0u;
    CHECK_EQ_INT(rqft_session_start(&ctrl, 0u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, &capture, 0u);
    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_VERSION);
    CHECK(ctrl_log.ended_from_peer);

    check_trace_equal("abort", &capture);
}

static void test_user_abort_trace(void)
{
    trace_log_t capture;
    rqft_session_t ctrl;
    rqft_session_t resp;
    session_log_t ctrl_log;
    session_log_t resp_log;

    memset(&capture, 0, sizeof(capture));
    setup_endpoint(&ctrl, &ctrl_log, RQFT_ROLE_CONTROLLER, NULL, SID, 0u, 1u, 1u);
    setup_endpoint(&resp, &resp_log, RQFT_ROLE_RESPONDER, NULL, SID, 0u, 1u, 1u);

    ctrl_log.now_ms = 0u;
    CHECK_EQ_INT(rqft_session_start(&ctrl, 0u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, &capture, 0u);
    CHECK(rqft_session_active(&ctrl));
    CHECK(rqft_session_active(&resp));

    resp_log.now_ms = 10u;
    rqft_session_abort(&resp, RQFT_ABORT_E_USER, 10u);
    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(!resp_log.ended_from_peer);

    drain_to_peer(&ctrl, &resp_log, &ctrl_log, &capture, TRACE_R_TO_C, 10u, 10u);
    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(ctrl_log.ended_from_peer);

    check_trace_equal("user_abort", &capture);
}

static void test_doorbell_trace(void)
{
    trace_log_t capture;
    rqft_session_t host;
    rqft_session_t device;
    session_log_t host_log;
    session_log_t device_log;

    memset(&capture, 0, sizeof(capture));
    setup_endpoint(&host, &host_log, RQFT_ROLE_CONTROLLER, NULL, SID, 0u, 1u, 1u);
    setup_endpoint(&device, &device_log, RQFT_ROLE_RESPONDER, NULL, 0x51u, 1u, 1u, 1u);

    device_log.now_ms = 0u;
    CHECK_EQ_INT(rqft_session_start(&device, 0u), RQFT_OK);
    drain_to_peer(&host, &device_log, &host_log, &capture, TRACE_R_TO_C, 0u, 5u);
    drain_to_peer(&device, &host_log, &device_log, &capture, TRACE_C_TO_R, 10u, 10u);

    CHECK(rqft_session_active(&host));
    CHECK(rqft_session_active(&device));
    CHECK_EQ_INT(host_log.established_events, 1);
    CHECK_EQ_INT(device_log.established_events, 1);

    check_trace_equal("doorbell", &capture);
}

static void test_doorbell_notify_trace(void)
{
    trace_log_t capture;
    rqft_session_t host;
    rqft_session_t device;
    session_log_t host_log;
    session_log_t device_log;

    memset(&capture, 0, sizeof(capture));
    setup_endpoint(&host, &host_log, RQFT_ROLE_CONTROLLER, NULL, SID, 0u, 1u, 1u);
    setup_endpoint(&device, &device_log, RQFT_ROLE_RESPONDER, NULL, 0x51u, 1u, 1u, 1u);

    device_log.now_ms = 0u;
    CHECK_EQ_INT(rqft_session_start(&device, 0u), RQFT_OK);
    drain_to_peer(&host, &device_log, &host_log, &capture, TRACE_R_TO_C, 0u, 5u);
    drain_to_peer(&device, &host_log, &device_log, &capture, TRACE_C_TO_R, 10u, 10u);

    CHECK(rqft_session_active(&host));
    CHECK(rqft_session_active(&device));
    CHECK_EQ_INT(host_log.established_events, 1);
    CHECK_EQ_INT(device_log.established_events, 1);

    /* The established responder asks for an incremental pull. */
    CHECK_EQ_INT(rqft_session_send_notify(&device, RQFT_NOTIFY_SYNC_INCREMENTAL, 20u),
                 RQFT_OK);
    drain_to_peer(&host, &device_log, &host_log, &capture, TRACE_R_TO_C, 20u, 20u);
    drain_to_peer(&device, &host_log, &device_log, &capture, TRACE_C_TO_R, 20u, 20u);

    CHECK_EQ_INT(host_log.notify_events, 1);
    CHECK_EQ_INT(host_log.notify_flags, RQFT_NOTIFY_SYNC_INCREMENTAL);

    check_trace_equal("doorbell_notify", &capture);
}

int main(void)
{
    test_hello_list_get_trace();
    test_put_trace();
    test_abort_trace();
    test_user_abort_trace();
    test_doorbell_trace();
    test_doorbell_notify_trace();
    TEST_MAIN_END();
}
