// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Types and limits shared by all librqft layers.
 */
#ifndef RQFT_COMMON_H
#define RQFT_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rqft/version.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RQFT_PROTOCOL_VERSION 1
#define RQFT_MAX_PAYLOAD 512
#define RQFT_MAX_ENCODED 523
#define RQFT_MAX_PATH 128
#define RQFT_WINDOW_MAX 8

typedef enum rqft_result {
    RQFT_OK = 0,
    RQFT_ERR_OUTPUT_TOO_SMALL = 1,
    RQFT_ERR_MALFORMED = 2,
    RQFT_ERR_WINDOW_FULL = 3,
    RQFT_ERR_LINK_DEAD = 4,
    RQFT_ERR_TRANSPORT = 5,
} rqft_result_t;

/** Session roles from SPEC.md section 5.1. */
typedef enum rqft_role {
    RQFT_ROLE_CONTROLLER = 0x00,
    RQFT_ROLE_RESPONDER = 0x01,
} rqft_role_t;

/** Capability bit granting DEL_FILE/DEL_DIR against this endpoint. */
#define RQFT_CAP_ALLOW_DELETE 0x01u

/** NOTIFY sync-mode flag bit: clear = full sync (complete mirror), set =
 * incremental sync (pull only files new since the controller's last
 * sync). */
#define RQFT_NOTIFY_SYNC_INCREMENTAL 0x00000001u

/** NOTIFY flag bit: delete each file from the responder's filesystem
 * after a verified fetch. Only actionable together with
 * RQFT_CAP_ALLOW_DELETE, which gates the DEL operations. */
#define RQFT_NOTIFY_DELETE_AFTER_SYNC 0x00000002u

/** NOTIFY flag bits defined by this implementation; the rest are masked
 * on receive and rejected on send per SPEC.md section 5.4. */
#define RQFT_NOTIFY_DEFINED_MASK 0x00000003u

/** ABORT reason codes from SPEC.md section 4.6. */
typedef enum rqft_abort_reason {
    RQFT_ABORT_CLOSE = 0x00,
    RQFT_ABORT_E_VERSION = 0x01,
    RQFT_ABORT_E_TIMEOUT = 0x02,
    RQFT_ABORT_E_PROTO = 0x03,
    RQFT_ABORT_E_BUSY = 0x04,
    RQFT_ABORT_E_INTERNAL = 0x05,
    RQFT_ABORT_E_USER = 0x06,
} rqft_abort_reason_t;

/** Non-fatal per-operation error codes from SPEC.md section 5.3. */
typedef enum rqft_err_code {
    RQFT_E_FS_OPEN = 0x01,
    RQFT_E_FS_READ = 0x02,
    RQFT_E_FS_WRITE = 0x03,
    RQFT_E_FS_REMOVE = 0x04,
    RQFT_E_PATH = 0x05,
    RQFT_E_CRC_FILE = 0x06,
    RQFT_E_TOO_LARGE = 0x07,
    RQFT_E_DENIED = 0x08,
    RQFT_E_BAD_STATE = 0x09,
    RQFT_E_UNSUPPORTED = 0x0A,
} rqft_err_code_t;

/** Session message type values from SPEC.md section 5.3. */
typedef enum rqft_msg_type {
    RQFT_MSG_UNKNOWN = 0x00,
    RQFT_MSG_LIST_REQ = 0x10,
    RQFT_MSG_LIST_ENTRY = 0x11,
    RQFT_MSG_LIST_END = 0x12,
    RQFT_MSG_GET_REQ = 0x20,
    RQFT_MSG_FILE_INFO = 0x21,
    RQFT_MSG_FILE_DATA = 0x22,
    RQFT_MSG_FILE_END = 0x23,
    RQFT_MSG_GET_DONE = 0x24,
    RQFT_MSG_PUT_REQ = 0x28,
    RQFT_MSG_PUT_OK = 0x29,
    RQFT_MSG_PUT_DONE = 0x2A,
    RQFT_MSG_DEL_FILE = 0x30,
    RQFT_MSG_DEL_DIR = 0x31,
    RQFT_MSG_DEL_OK = 0x32,
    RQFT_MSG_PLAN = 0x40,
    RQFT_MSG_NOTIFY = 0x41,
    RQFT_MSG_PING = 0x50,
    RQFT_MSG_PONG = 0x51,
    RQFT_MSG_ERR = 0x7F,
} rqft_msg_type_t;

/**
 * Complete-wire-frame sink used by the sans-I/O session and link APIs.
 *
 * wire contains leading and trailing 0x00 delimiters and remains valid only
 * for the callback. The callback must synchronously consume or copy all
 * wire_len bytes. Use rqft_session_driver_t when the transport can make
 * partial writes.
 */
typedef void (*rqft_wire_transmit_fn)(void *user,
                                      const uint8_t *wire,
                                      size_t wire_len);

/** Compatibility name for the link layer's complete-frame sink. */
typedef rqft_wire_transmit_fn rqft_link_transmit_fn;

/** Return the static "MAJOR.MINOR.PATCH" library version string. */
const char *rqft_lib_version(void);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_COMMON_H */
