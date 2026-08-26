// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_session_list.c - LIST operation tests for SPEC.md section 5.4. */
#include "rqft/rqft.h"
#include "test_support.h"

#include <stdint.h>

#define WIRE_CAP 16384u
#define MAX_ENTRIES 16u
#define SID 0x42u

/* ------------------------------------------------------------------ */
/* Event and wire logging                                              */

typedef struct session_log {
    uint8_t wire[WIRE_CAP];
    size_t wire_len;
    size_t consumed;
    uint8_t entry_path[MAX_ENTRIES][RQFT_MAX_PATH];
    size_t entry_path_len[MAX_ENTRIES];
    uint32_t entry_size[MAX_ENTRIES];
    uint32_t entry_crc[MAX_ENTRIES];
    bool entry_has_crc[MAX_ENTRIES];
    uint8_t entry_etype[MAX_ENTRIES];
    uint32_t entry_mtime[MAX_ENTRIES];
    size_t entries;
    size_t list_done_events;
    uint16_t list_done_count;
    size_t list_skip_events;
    rqft_err_code_t list_skip_code;
    uint16_t list_skip_detail;
    size_t op_failed_events;
    uint8_t op_failed_request;
    rqft_err_code_t op_failed_code;
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
    case RQFT_SESSION_EVENT_LIST_ENTRY:
        CHECK(log->entries < MAX_ENTRIES);
        CHECK(event->u.list_entry.path_len <= RQFT_MAX_PATH);
        memcpy(log->entry_path[log->entries], event->u.list_entry.path,
               event->u.list_entry.path_len);
        log->entry_path_len[log->entries] = event->u.list_entry.path_len;
        log->entry_size[log->entries] = event->u.list_entry.size;
        log->entry_crc[log->entries] = event->u.list_entry.crc32;
        log->entry_has_crc[log->entries] = event->u.list_entry.has_crc;
        log->entry_etype[log->entries] = event->u.list_entry.etype;
        log->entry_mtime[log->entries] = event->u.list_entry.mtime;
        log->entries++;
        break;
    case RQFT_SESSION_EVENT_LIST_DONE:
        log->list_done_events++;
        log->list_done_count = event->u.list_done.count;
        break;
    case RQFT_SESSION_EVENT_LIST_SKIP:
        log->list_skip_events++;
        log->list_skip_code = event->u.list_skip.code;
        log->list_skip_detail = event->u.list_skip.detail;
        break;
    case RQFT_SESSION_EVENT_OP_FAILED:
        log->op_failed_events++;
        log->op_failed_request = event->u.op_failed.request;
        log->op_failed_code = event->u.op_failed.code;
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
/* In-memory fake filesystem                                           */

#define FAKE_MAX_FILES 8u
#define FAKE_FILE_CAP 12288u

typedef struct fake_file {
    char path[RQFT_MAX_PATH + 1u];
    uint8_t data[FAKE_FILE_CAP];
    size_t size;
    uint32_t mtime;
} fake_file_t;

typedef struct fake_fs {
    fake_file_t files[FAKE_MAX_FILES];
    size_t file_count;
    rqft_fs_entry_t override_entries[4];
    size_t override_count;
    bool use_override;
    size_t list_pos;
    char prefix[RQFT_MAX_PATH + 2u];
    int read_index;
    size_t read_pos;
    char fail_open_read[RQFT_MAX_PATH + 1u];
    char fail_read_path[RQFT_MAX_PATH + 1u];
    size_t fail_read_at;
    size_t bytes_read;
    size_t list_closed;
} fake_fs_t;

static void fake_add(fake_fs_t *fs, const char *path, const uint8_t *data, size_t size,
                     uint32_t mtime)
{
    fake_file_t *file = &fs->files[fs->file_count++];
    CHECK(fs->file_count <= FAKE_MAX_FILES);
    CHECK(size <= FAKE_FILE_CAP);
    strcpy(file->path, path);
    if (size > 0u) {
        memcpy(file->data, data, size);
    }
    file->size = size;
    file->mtime = mtime;
}

static bool fake_list_begin(void *user, const uint8_t *root, size_t root_len)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    fs->list_pos = 0u;
    fs->prefix[0] = '\0';
    if (fs->use_override) {
        return true;
    }
    if (root_len > 0u) {
        bool any = false;
        memcpy(fs->prefix, root, root_len);
        fs->prefix[root_len] = '/';
        fs->prefix[root_len + 1u] = '\0';
        for (size_t i = 0u; i < fs->file_count; i++) {
            if (strncmp(fs->files[i].path, fs->prefix, root_len + 1u) == 0) {
                any = true;
            }
        }
        if (!any) {
            return false;
        }
    }
    return true;
}

static int fake_list_next(void *user, rqft_fs_entry_t *entry)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    if (fs->use_override) {
        if (fs->list_pos >= fs->override_count) {
            return 0;
        }
        *entry = fs->override_entries[fs->list_pos++];
        return 1;
    }
    while (fs->list_pos < fs->file_count) {
        const fake_file_t *file = &fs->files[fs->list_pos++];
        if (fs->prefix[0] != '\0' &&
            strncmp(file->path, fs->prefix, strlen(fs->prefix)) != 0) {
            continue;
        }
        memset(entry, 0, sizeof(*entry));
        entry->path_len = strlen(file->path);
        memcpy(entry->path, file->path, entry->path_len);
        entry->size = (uint32_t)file->size;
        entry->mtime = file->mtime;
        entry->etype = 0u;
        return 1;
    }
    return 0;
}

static void fake_list_close(void *user)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    fs->list_closed++;
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

static bool fake_open_read(void *user, const uint8_t *path, size_t path_len, uint32_t *size)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    int index = fake_find(fs, path, path_len);
    if (index < 0) {
        return false;
    }
    if (strlen(fs->fail_open_read) == path_len &&
        memcmp(fs->fail_open_read, path, path_len) == 0) {
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
    return (int)chunk;
}

static void fake_close_read(void *user)
{
    fake_fs_t *fs = (fake_fs_t *)user;
    fs->read_index = -1;
}

static const rqft_fs_ops_t fake_ops = {
    fake_list_begin, fake_list_next, fake_list_close,
    fake_open_read, fake_read, fake_close_read,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
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
                           rqft_session_t *resp,
                           session_log_t *resp_log,
                           fake_fs_t *fs,
                           uint8_t window)
{
    setup_endpoint(ctrl, ctrl_log, RQFT_ROLE_CONTROLLER, NULL, 4u);
    setup_endpoint(resp, resp_log, RQFT_ROLE_RESPONDER, fs, window);
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

static void check_entry(const session_log_t *log,
                        size_t index,
                        const char *path,
                        uint32_t size,
                        bool has_crc,
                        uint32_t crc)
{
    CHECK(index < log->entries);
    CHECK_EQ_INT(log->entry_path_len[index], strlen(path));
    CHECK(memcmp(log->entry_path[index], path, strlen(path)) == 0);
    CHECK_EQ_INT(log->entry_size[index], size);
    CHECK_EQ_INT(log->entry_has_crc[index], has_crc);
    if (has_crc) {
        CHECK_EQ_INT(log->entry_crc[index], crc);
    }
}

static void fake_fs_files(fake_fs_t *fs)
{
    memset(fs, 0, sizeof(*fs));
    fake_add(fs, "a.data", (const uint8_t *)"alpha", 5u, 1735689600u);
    fake_add(fs, "logs/2025/run1.data", (const uint8_t *)"first run", 9u, 0u);
    fake_add(fs, "logs/2025/run2.data", (const uint8_t *)"second run data", 15u, 0u);
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

/* ------------------------------------------------------------------ */
/* Tests                                                               */

static void test_list_streams_entries_and_end(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.entries, 3);
    check_entry(&ctrl_log, 0u, "a.data", 5u, false, 0u);
    CHECK_EQ_INT(ctrl_log.entry_mtime[0], 1735689600u);
    check_entry(&ctrl_log, 1u, "logs/2025/run1.data", 9u, false, 0u);
    check_entry(&ctrl_log, 2u, "logs/2025/run2.data", 15u, false, 0u);
    CHECK_EQ_INT(ctrl_log.list_done_events, 1);
    CHECK_EQ_INT(ctrl_log.list_done_count, 3);
}

static void test_list_subtree_root_filters(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, (const uint8_t *)"logs", 4u, false, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.entries, 2);
    check_entry(&ctrl_log, 0u, "logs/2025/run1.data", 9u, false, 0u);
    check_entry(&ctrl_log, 1u, "logs/2025/run2.data", 15u, false, 0u);
    CHECK_EQ_INT(ctrl_log.list_done_count, 2);
}

static void test_list_want_crc_computes_values(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.entries, 3);
    check_entry(&ctrl_log, 0u, "a.data", 5u, true,
                rqft_crc32((const uint8_t *)"alpha", 5u));
    check_entry(&ctrl_log, 1u, "logs/2025/run1.data", 9u, true,
                rqft_crc32((const uint8_t *)"first run", 9u));
    check_entry(&ctrl_log, 2u, "logs/2025/run2.data", 15u, true,
                rqft_crc32((const uint8_t *)"second run data", 15u));
    CHECK_EQ_INT(ctrl_log.list_done_count, 3);
}

static void test_list_crc_work_bounded_per_poll(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    uint8_t big[10240];
    size_t polls = 0u;

    for (size_t i = 0u; i < sizeof(big); i++) {
        big[i] = (uint8_t)i;
    }
    memset(&fs, 0, sizeof(fs));
    fake_add(&fs, "big.bin", big, sizeof(big), 0u);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);

    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 10u), RQFT_OK);
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;

    while (rqft_session_work_pending(&resp) && polls < 50u) {
        size_t before = fs.bytes_read;
        rqft_session_poll(&resp, 10u);
        CHECK(fs.bytes_read - before <= RQFT_CRC_BUDGET_PER_POLL);
        polls++;
    }
    /* 10240 bytes at 4096 per poll: the receive pass hashes one budget,
     * then at least two more polls are needed. */
    CHECK(polls >= 2u);

    rqft_session_receive(&ctrl, resp_log.wire, resp_log.wire_len, 20u);
    CHECK_EQ_INT(ctrl_log.entries, 1);
    check_entry(&ctrl_log, 0u, "big.bin", 10240u, true, rqft_crc32(big, sizeof(big)));
    CHECK_EQ_INT(ctrl_log.list_done_count, 1);
}

static void test_list_unreadable_file_skipped(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    rqft_msg_t msg;

    fake_fs_files(&fs);
    strcpy(fs.fail_open_read, "logs/2025/run1.data");
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.entries, 2);
    check_entry(&ctrl_log, 0u, "a.data", 5u, true, rqft_crc32((const uint8_t *)"alpha", 5u));
    check_entry(&ctrl_log, 1u, "logs/2025/run2.data", 15u, true,
                rqft_crc32((const uint8_t *)"second run data", 15u));
    CHECK_EQ_INT(ctrl_log.list_done_count, 2);
    CHECK_EQ_INT(ctrl_log.list_skip_events, 1);
    CHECK_EQ_INT(ctrl_log.list_skip_code, RQFT_E_FS_READ);
    CHECK_EQ_INT(ctrl_log.list_skip_detail, 0);

    /* The skip travels as an informational ERR between the entries. */
    CHECK(nth_data_message(resp_log.wire, resp_log.wire_len, 1u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_FS_READ);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_LIST_REQ);
}

static void test_list_read_error_mid_hash_skips_entry(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;

    fake_fs_files(&fs);
    strcpy(fs.fail_read_path, "logs/2025/run2.data");
    fs.fail_read_at = 4u;
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.entries, 2);
    CHECK_EQ_INT(ctrl_log.list_done_count, 2);
    CHECK_EQ_INT(ctrl_log.list_skip_events, 1);
    CHECK_EQ_INT(ctrl_log.list_skip_code, RQFT_E_FS_READ);
}

static void test_controller_keeps_list_open_across_informational_err(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 10u), RQFT_OK);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_ERR;
    msg.u.err.code = RQFT_E_FS_READ;
    msg.u.err.ref_msgtype = RQFT_MSG_LIST_REQ;
    wire_len = data_frame(0u, &msg, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 10u);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_END;
    msg.u.list_end.count = 0u;
    wire_len = data_frame(1u, &msg, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 10u);

    CHECK_EQ_INT(ctrl_log.list_skip_events, 1);
    CHECK_EQ_INT(ctrl_log.list_skip_code, RQFT_E_FS_READ);
    CHECK_EQ_INT(ctrl_log.op_failed_events, 0);
    CHECK_EQ_INT(ctrl_log.list_done_events, 1);
    CHECK_EQ_INT(ctrl_log.list_done_count, 0);
    CHECK(rqft_session_active(&ctrl));
}

static void test_responder_invalid_entry_paths_skipped(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    rqft_fs_entry_t *bad;
    rqft_fs_entry_t *good;

    memset(&fs, 0, sizeof(fs));
    fake_add(&fs, "ok.bin", (const uint8_t *)"ok", 2u, 0u);
    fs.use_override = true;
    fs.override_count = 2u;
    bad = &fs.override_entries[0];
    memcpy(bad->path, "../evil", 7u);
    bad->path_len = 7u;
    bad->size = 1u;
    good = &fs.override_entries[1];
    memcpy(good->path, "ok.bin", 6u);
    good->path_len = 6u;
    good->size = 2u;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.entries, 1);
    check_entry(&ctrl_log, 0u, "ok.bin", 2u, false, 0u);
    CHECK_EQ_INT(ctrl_log.list_done_count, 1);
}

static void test_list_entries_trickle_through_window_of_one(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 1u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.entries, 3);
    CHECK_EQ_INT(ctrl_log.list_done_count, 3);
}

static void test_responder_rejects_invalid_root_with_e_path(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_REQ;
    msg.u.list_req.want_crc = false;
    msg.u.list_req.root = (const uint8_t *)"../up";
    msg.u.list_req.root_len = 5u;
    wire_len = data_frame(0u, &msg, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 10u);

    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_PATH);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_LIST_REQ);
    CHECK(rqft_session_active(&resp));
}

static void test_missing_root_fails_op_and_releases_slot(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, (const uint8_t *)"nosuch", 6u, false, 10u),
                 RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_request, RQFT_MSG_LIST_REQ);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_FS_OPEN);
    CHECK(rqft_session_active(&ctrl));

    /* The failed operation releases the slot for the next request. */
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 20u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 20u);
    CHECK_EQ_INT(ctrl_log.list_done_events, 1);
    CHECK_EQ_INT(ctrl_log.list_done_count, 3);
}

static void test_responder_without_fs_answers_unsupported(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;

    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, NULL, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 10u), RQFT_OK);
    shuttle(&ctrl, &ctrl_log, &resp, &resp_log, 10u);

    CHECK_EQ_INT(ctrl_log.op_failed_events, 1);
    CHECK_EQ_INT(ctrl_log.op_failed_code, RQFT_E_UNSUPPORTED);
}

static void test_controller_drops_invalid_entry_paths_but_counts_them(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 10u), RQFT_OK);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_ENTRY;
    msg.u.list_entry.path = (const uint8_t *)"../evil";
    msg.u.list_entry.path_len = 7u;
    msg.u.list_entry.size = 1u;
    wire_len = data_frame(0u, &msg, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 10u);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_END;
    msg.u.list_end.count = 1u;
    wire_len = data_frame(1u, &msg, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 10u);

    CHECK_EQ_INT(ctrl_log.entries, 0);
    CHECK_EQ_INT(ctrl_log.list_done_events, 1);
    CHECK_EQ_INT(ctrl_log.list_done_count, 1);
    CHECK(rqft_session_active(&ctrl));
}

static void test_list_end_count_mismatch_aborts_e_proto(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    rqft_msg_t msg;
    uint8_t wire[600];
    size_t wire_len;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 10u), RQFT_OK);

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_END;
    msg.u.list_end.count = 5u;
    wire_len = data_frame(0u, &msg, wire, sizeof(wire));
    rqft_session_receive(&ctrl, wire, wire_len, 10u);

    CHECK_EQ_INT(ctrl_log.ended_events, 1);
    CHECK_EQ_INT(ctrl_log.ended_reason, RQFT_ABORT_E_PROTO);
    CHECK(!ctrl_log.ended_from_peer);
    CHECK_EQ_INT(rqft_session_state(&ctrl), RQFT_SESSION_ENDED);
}

static void test_request_list_validates_role_state_and_path(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;

    fake_fs_files(&fs);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);

    CHECK_EQ_INT(rqft_session_request_list(&resp, NULL, 0u, false, 10u), RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, (const uint8_t *)"../up", 5u, false, 10u),
                 RQFT_ERR_MALFORMED);

    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 10u), RQFT_OK);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, false, 11u), RQFT_ERR_MALFORMED);
}

static void test_session_end_mid_list_closes_read_cursor(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    uint8_t big[10240];
    uint8_t reason = RQFT_ABORT_E_USER;
    uint8_t wire[16];
    size_t wire_len = 0u;

    /* A slow want_crc listing holds the fs read cursor across polls. */
    memset(big, 0, sizeof(big));
    memset(&fs, 0, sizeof(fs));
    fake_add(&fs, "big.bin", big, sizeof(big), 0u);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 10u), RQFT_OK);
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    CHECK(rqft_session_work_pending(&resp));
    CHECK(fs.bytes_read > 0u);

    CHECK_EQ_INT(rqft_frame_build(RQFT_FRAME_ABORT, SID, 0u, 0u, &reason, 1u,
                                  wire, sizeof(wire), &wire_len),
                 RQFT_OK);
    rqft_session_receive(&resp, wire, wire_len, 11u);

    CHECK_EQ_INT(resp_log.ended_events, 1);
    CHECK_EQ_INT(resp_log.ended_reason, RQFT_ABORT_E_USER);
    CHECK(resp_log.ended_from_peer);
    CHECK_EQ_INT(fs.read_index, -1);
    CHECK(fs.list_closed >= 1u);
    CHECK(!rqft_session_work_pending(&resp));
}

static void test_message_during_list_stream_answered_bad_state(void)
{
    rqft_session_t ctrl, resp;
    session_log_t ctrl_log, resp_log;
    fake_fs_t fs;
    rqft_msg_t msg;
    uint8_t big[10240];
    uint8_t wire[600];
    size_t wire_len;
    int i;

    /* A slow want_crc listing keeps the operation open across polls. */
    memset(big, 0, sizeof(big));
    memset(&fs, 0, sizeof(fs));
    fake_add(&fs, "big.bin", big, sizeof(big), 0u);
    establish_pair(&ctrl, &ctrl_log, &resp, &resp_log, &fs, 4u);
    CHECK_EQ_INT(rqft_session_request_list(&ctrl, NULL, 0u, true, 10u), RQFT_OK);
    rqft_session_receive(&resp, ctrl_log.wire + ctrl_log.consumed,
                         ctrl_log.wire_len - ctrl_log.consumed, 10u);
    ctrl_log.consumed = ctrl_log.wire_len;
    CHECK(rqft_session_work_pending(&resp));

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_REQ;
    msg.u.list_req.root_len = 0u;
    wire_len = data_frame(1u, &msg, wire, sizeof(wire));
    rqft_session_receive(&resp, wire, wire_len, 11u);
    for (i = 0; i < 10; i++) {
        if (rqft_session_work_pending(&resp)) {
            rqft_session_poll(&resp, 12u);
        }
    }

    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 0u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_ERR);
    CHECK_EQ_INT(msg.u.err.code, RQFT_E_BAD_STATE);
    CHECK_EQ_INT(msg.u.err.ref_msgtype, RQFT_MSG_LIST_REQ);
    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 1u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_LIST_ENTRY);
    CHECK(nth_data_message(resp_log.wire + resp_log.consumed,
                           resp_log.wire_len - resp_log.consumed, 2u, &msg));
    CHECK_EQ_INT(msg.type, RQFT_MSG_LIST_END);
    CHECK(rqft_session_active(&resp));
}

int main(void)
{
    test_list_streams_entries_and_end();
    test_list_subtree_root_filters();
    test_list_want_crc_computes_values();
    test_list_crc_work_bounded_per_poll();
    test_list_unreadable_file_skipped();
    test_list_read_error_mid_hash_skips_entry();
    test_controller_keeps_list_open_across_informational_err();
    test_responder_invalid_entry_paths_skipped();
    test_list_entries_trickle_through_window_of_one();
    test_responder_rejects_invalid_root_with_e_path();
    test_missing_root_fails_op_and_releases_slot();
    test_responder_without_fs_answers_unsupported();
    test_controller_drops_invalid_entry_paths_but_counts_them();
    test_list_end_count_mismatch_aborts_e_proto();
    test_request_list_validates_role_state_and_path();
    test_session_end_mid_list_closes_read_cursor();
    test_message_during_list_stream_answered_bad_state();
    TEST_MAIN_END();
}
