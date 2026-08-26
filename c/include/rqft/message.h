// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/** @file @brief Session handshake and message body codecs. */
#ifndef RQFT_MESSAGE_H
#define RQFT_MESSAGE_H

#include "rqft/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RQFT_HELLO_BODY_LEN 8u

typedef struct rqft_hello {
    uint8_t ver_min;
    uint8_t ver_max;
    rqft_role_t role;
    uint16_t max_payload;
    uint8_t window;
    uint8_t caps;
} rqft_hello_t;

typedef struct rqft_hello_ok {
    uint8_t ver;
    rqft_role_t role;
    uint16_t max_payload;
    uint8_t window;
    uint8_t caps;
} rqft_hello_ok_t;

rqft_result_t rqft_hello_encode(const rqft_hello_t *hello,
                                uint8_t out[RQFT_HELLO_BODY_LEN]);
rqft_result_t rqft_hello_decode(const uint8_t *data,
                                size_t len,
                                rqft_hello_t *out);
rqft_result_t rqft_hello_ok_encode(const rqft_hello_ok_t *ok,
                                   uint8_t out[RQFT_HELLO_BODY_LEN]);
rqft_result_t rqft_hello_ok_decode(const uint8_t *data,
                                   size_t len,
                                   rqft_hello_ok_t *out);

/** Validate a relative UTF-8 wire path. */
bool rqft_path_valid(const uint8_t *path, size_t len, bool allow_empty);

typedef struct rqft_msg_list_req {
    bool want_crc;
    const uint8_t *root;
    size_t root_len;
} rqft_msg_list_req_t;

typedef struct rqft_msg_list_entry {
    uint8_t etype;
    bool crc_valid;
    uint32_t size;
    uint32_t crc32;
    uint32_t mtime;
    const uint8_t *path;
    size_t path_len;
} rqft_msg_list_entry_t;

typedef struct rqft_msg_list_end {
    uint16_t count;
} rqft_msg_list_end_t;

typedef struct rqft_msg_get_req {
    uint32_t offset;
    const uint8_t *path;
    size_t path_len;
} rqft_msg_get_req_t;

typedef struct rqft_msg_file_info {
    uint32_t size;
} rqft_msg_file_info_t;

typedef struct rqft_msg_file_data {
    const uint8_t *data;
    size_t len;
} rqft_msg_file_data_t;

typedef struct rqft_msg_file_end {
    uint32_t crc32;
} rqft_msg_file_end_t;

typedef struct rqft_msg_get_done {
    uint8_t status;
} rqft_msg_get_done_t;

typedef struct rqft_msg_put_req {
    uint32_t size;
    uint32_t crc32;
    const uint8_t *path;
    size_t path_len;
} rqft_msg_put_req_t;

typedef struct rqft_msg_put_done {
    uint8_t status;
} rqft_msg_put_done_t;

typedef struct rqft_msg_del {
    const uint8_t *path;
    size_t path_len;
} rqft_msg_del_t;

typedef struct rqft_msg_plan {
    uint16_t nfiles;
    uint32_t nbytes;
} rqft_msg_plan_t;

typedef struct rqft_msg_notify {
    /** RQFT_NOTIFY_* flag bits; see SPEC.md section 5.4. */
    uint32_t flags;
} rqft_msg_notify_t;

typedef struct rqft_msg_token {
    uint32_t token;
} rqft_msg_token_t;

typedef struct rqft_msg_err {
    rqft_err_code_t code;
    uint8_t ref_msgtype;
    uint16_t detail;
} rqft_msg_err_t;

typedef struct rqft_msg_unknown {
    uint8_t msg_type;
    const uint8_t *body;
    size_t len;
} rqft_msg_unknown_t;

/** Decoded message. Pointer members alias the decoded payload buffer. */
typedef struct rqft_msg {
    rqft_msg_type_t type;
    union {
        rqft_msg_list_req_t list_req;
        rqft_msg_list_entry_t list_entry;
        rqft_msg_list_end_t list_end;
        rqft_msg_get_req_t get_req;
        rqft_msg_file_info_t file_info;
        rqft_msg_file_data_t file_data;
        rqft_msg_file_end_t file_end;
        rqft_msg_get_done_t get_done;
        rqft_msg_put_req_t put_req;
        rqft_msg_put_done_t put_done;
        rqft_msg_del_t del_path;
        rqft_msg_plan_t plan;
        rqft_msg_notify_t notify;
        rqft_msg_token_t token;
        rqft_msg_err_t err;
        rqft_msg_unknown_t unknown;
    } u;
} rqft_msg_t;

rqft_result_t rqft_msg_encode(const rqft_msg_t *msg,
                              uint8_t *out,
                              size_t out_cap,
                              size_t *out_len);
rqft_result_t rqft_msg_decode(const uint8_t *payload,
                              size_t len,
                              rqft_msg_t *out);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_MESSAGE_H */
