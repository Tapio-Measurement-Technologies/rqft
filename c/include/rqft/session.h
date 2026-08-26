// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Sans-I/O session endpoint, filesystem, events, and operations.
 */
#ifndef RQFT_SESSION_H
#define RQFT_SESSION_H

#include "rqft/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RQFT_T_HELLO_MS 500u
#define RQFT_N_HELLO 5u
#define RQFT_T_PING_MS 2000u
#define RQFT_T_DEAD_MS 10000u
#define RQFT_CRC_BUDGET_PER_POLL 4096u
#define RQFT_SESSION_STORAGE_SIZE 10240u

typedef struct rqft_fs_entry {
    uint8_t path[RQFT_MAX_PATH];
    size_t path_len;
    uint32_t size;
    uint32_t mtime;
    uint8_t etype;
} rqft_fs_entry_t;

/**
 * Filesystem callbacks supplied by the host.
 *
 * One listing, read, and write cursor may be open at a time. Received files
 * must be staged through open_write/write and published atomically by commit.
 * discard removes any staged file. Listing recursion and filtering are host
 * policy.
 */
typedef struct rqft_fs_ops {
    bool (*list_begin)(void *user, const uint8_t *root, size_t root_len);
    int (*list_next)(void *user, rqft_fs_entry_t *entry);
    void (*list_close)(void *user);
    bool (*open_read)(void *user,
                      const uint8_t *path,
                      size_t path_len,
                      uint32_t *size);
    int (*read)(void *user, uint8_t *buf, size_t cap);
    void (*close_read)(void *user);
    bool (*open_write)(void *user, const uint8_t *path, size_t path_len);
    bool (*write)(void *user, const uint8_t *data, size_t len);
    bool (*commit)(void *user);
    void (*discard)(void *user);
    bool (*remove_file)(void *user, const uint8_t *path, size_t path_len);
    bool (*remove_dir)(void *user, const uint8_t *path, size_t path_len);
    bool (*allow_delete)(void *user, const uint8_t *path, size_t path_len);
} rqft_fs_ops_t;

typedef enum rqft_session_state {
    RQFT_SESSION_IDLE = 0,
    RQFT_SESSION_HELLO_SENT = 1,
    RQFT_SESSION_ACTIVE = 2,
    RQFT_SESSION_ENDED = 3,
} rqft_session_state_t;

typedef enum rqft_session_event_type {
    RQFT_SESSION_EVENT_ESTABLISHED = 1,
    RQFT_SESSION_EVENT_ENDED = 2,
    RQFT_SESSION_EVENT_PASSTHROUGH = 3,
    RQFT_SESSION_EVENT_LIST_ENTRY = 4,
    RQFT_SESSION_EVENT_LIST_DONE = 5,
    RQFT_SESSION_EVENT_OP_FAILED = 6,
    RQFT_SESSION_EVENT_GET_DONE = 7,
    RQFT_SESSION_EVENT_PUT_DONE = 8,
    RQFT_SESSION_EVENT_DEL_DONE = 9,
    RQFT_SESSION_EVENT_PLAN = 10,
    RQFT_SESSION_EVENT_LIST_SKIP = 11,
    RQFT_SESSION_EVENT_GET_SERVED = 12,
    RQFT_SESSION_EVENT_NOTIFY = 13,
} rqft_session_event_type_t;

typedef struct rqft_session_list_entry {
    uint8_t etype;
    bool has_crc;
    uint32_t size;
    uint32_t crc32;
    uint32_t mtime;
    const uint8_t *path;
    size_t path_len;
} rqft_session_list_entry_t;

typedef struct rqft_session_list_done {
    uint16_t count;
} rqft_session_list_done_t;

typedef struct rqft_session_list_skip {
    rqft_err_code_t code;
    uint16_t detail;
} rqft_session_list_skip_t;

typedef struct rqft_session_get_done {
    const uint8_t *path;
    size_t path_len;
    uint32_t size;
    uint32_t crc32;
} rqft_session_get_done_t;

typedef struct rqft_session_get_served {
    const uint8_t *path;
    size_t path_len;
    uint32_t size;
    uint32_t crc32;
} rqft_session_get_served_t;

typedef struct rqft_session_put_done {
    const uint8_t *path;
    size_t path_len;
    uint32_t size;
    uint32_t crc32;
} rqft_session_put_done_t;

typedef struct rqft_session_del_done {
    const uint8_t *path;
    size_t path_len;
    bool is_dir;
} rqft_session_del_done_t;

typedef struct rqft_session_plan {
    uint16_t nfiles;
    uint32_t nbytes;
} rqft_session_plan_t;

typedef struct rqft_session_notify {
    /** RQFT_NOTIFY_* flag bits from the responder's NOTIFY. */
    uint32_t flags;
} rqft_session_notify_t;

typedef struct rqft_session_op_failed {
    uint8_t request;
    rqft_err_code_t code;
    uint16_t detail;
    const uint8_t *path;
    size_t path_len;
} rqft_session_op_failed_t;

typedef struct rqft_session_established {
    uint8_t sid;
    uint8_t version;
    rqft_role_t role;
    uint16_t max_payload;
    uint8_t window;
    uint8_t peer_caps;
} rqft_session_established_t;

typedef struct rqft_session_ended {
    rqft_abort_reason_t reason;
    bool from_peer;
} rqft_session_ended_t;

typedef struct rqft_session_passthrough {
    const uint8_t *data;
    size_t len;
} rqft_session_passthrough_t;

/** Event payload pointers remain valid only during the callback. */
typedef struct rqft_session_event {
    rqft_session_event_type_t type;
    union {
        rqft_session_established_t established;
        rqft_session_ended_t ended;
        rqft_session_passthrough_t passthrough;
        rqft_session_list_entry_t list_entry;
        rqft_session_list_done_t list_done;
        rqft_session_list_skip_t list_skip;
        rqft_session_op_failed_t op_failed;
        rqft_session_get_done_t get_done;
        rqft_session_get_served_t get_served;
        rqft_session_put_done_t put_done;
        rqft_session_del_done_t del_done;
        rqft_session_plan_t plan;
        rqft_session_notify_t notify;
    } u;
} rqft_session_event_t;

typedef void (*rqft_session_event_fn)(void *user,
                                      const rqft_session_event_t *event);
typedef uint8_t (*rqft_session_sid_fn)(void *user);

typedef struct rqft_session_config {
    /** Endpoint role once active. */
    rqft_role_t role;

    /** Lowest and highest supported wire protocol versions. */
    uint8_t ver_min;
    uint8_t ver_max;

    /** Largest accepted frame payload and buffered send window. */
    uint16_t max_payload;
    uint8_t window;

    /** Declared capability bits. */
    uint8_t caps;

    /** Required session-id source and its caller data. */
    rqft_session_sid_fn next_sid;
    void *sid_user;

    /** Required complete-frame sink for direct sans-I/O use. */
    rqft_wire_transmit_fn transmit;
    void *transmit_user;

    /** Required event sink and its caller data. */
    rqft_session_event_fn on_event;
    void *event_user;

    /** Optional filesystem provider and its caller data. */
    const rqft_fs_ops_t *fs;
    void *fs_user;
} rqft_session_config_t;

typedef struct rqft_session {
    uint64_t alignment;
    uint8_t storage[RQFT_SESSION_STORAGE_SIZE];
} rqft_session_t;

/**
 * Clear config and apply supported protocol version and maximum limits.
 * next_sid and on_event remain required. Direct session users must also set
 * transmit; rqft_session_driver_t supplies it for driver users.
 */
void rqft_session_config_init(rqft_session_config_t *config,
                              rqft_role_t role);

rqft_result_t rqft_session_init(rqft_session_t *session,
                                const rqft_session_config_t *config);
rqft_result_t rqft_session_start(rqft_session_t *session, uint32_t now_ms);

/**
 * Feed raw transport bytes. Drain all currently available RX through this
 * function before every rqft_session_poll() call.
 */
void rqft_session_receive(rqft_session_t *session,
                          const uint8_t *data,
                          size_t len,
                          uint32_t now_ms);

/** Run timers and one bounded work slice after transport RX is drained. */
void rqft_session_poll(rqft_session_t *session, uint32_t now_ms);
bool rqft_session_next_timeout(const rqft_session_t *session,
                               uint32_t *deadline_ms);
rqft_session_state_t rqft_session_state(const rqft_session_t *session);
bool rqft_session_active(const rqft_session_t *session);
bool rqft_session_work_pending(const rqft_session_t *session);

typedef enum rqft_progress_phase {
    RQFT_PROGRESS_HASH = 0,
    RQFT_PROGRESS_STREAM = 1,
} rqft_progress_phase_t;

typedef struct rqft_transfer_progress {
    rqft_msg_type_t request;
    rqft_progress_phase_t phase;
    uint32_t done;
    bool has_total;
    uint32_t total;
} rqft_transfer_progress_t;

bool rqft_session_progress(const rqft_session_t *session,
                           rqft_transfer_progress_t *out);

/** End a live session and release operation resources. ABORT is best-effort. */
void rqft_session_abort(rqft_session_t *session,
                        rqft_abort_reason_t reason,
                        uint32_t now_ms);

/** Controller operations are sequential and report completion through events. */
rqft_result_t rqft_session_request_list(rqft_session_t *session,
                                        const uint8_t *root,
                                        size_t root_len,
                                        bool want_crc,
                                        uint32_t now_ms);
rqft_result_t rqft_session_request_get(rqft_session_t *session,
                                       const uint8_t *path,
                                       size_t path_len,
                                       uint32_t now_ms);
rqft_result_t rqft_session_request_put(rqft_session_t *session,
                                       const uint8_t *path,
                                       size_t path_len,
                                       uint32_t now_ms);
rqft_result_t rqft_session_request_del(rqft_session_t *session,
                                       const uint8_t *path,
                                       size_t path_len,
                                       bool is_dir,
                                       uint32_t now_ms);
rqft_result_t rqft_session_send_plan(rqft_session_t *session,
                                     uint16_t nfiles,
                                     uint32_t nbytes,
                                     uint32_t now_ms);
/** Ask the controller to pull files with NOTIFY (responder only, SPEC.md
 * section 5.4). flags is a combination of the RQFT_NOTIFY_* bits; fails
 * while an operation is in flight — retry after it completes. */
rqft_result_t rqft_session_send_notify(rqft_session_t *session,
                                       uint32_t flags,
                                       uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_SESSION_H */
