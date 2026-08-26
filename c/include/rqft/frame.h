// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/** @file @brief Wire frame builder and resynchronizing stream parser. */
#ifndef RQFT_FRAME_H
#define RQFT_FRAME_H

#include "rqft/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RQFT_T_FLUSH_MS 50
#define RQFT_FRAME_PARSER_STORAGE_SIZE 640u

typedef enum rqft_frame_type {
    RQFT_FRAME_HELLO = 0x01,
    RQFT_FRAME_HELLO_OK = 0x02,
    RQFT_FRAME_DATA = 0x03,
    RQFT_FRAME_ACK = 0x04,
    RQFT_FRAME_ABORT = 0x05,
} rqft_frame_type_t;

typedef enum rqft_frame_parser_state {
    RQFT_FRAME_PARSER_HUNT = 0,
    RQFT_FRAME_PARSER_FRAME = 1,
} rqft_frame_parser_state_t;

typedef struct rqft_frame {
    rqft_frame_type_t type;
    uint8_t sid;
    uint8_t seq;
    uint8_t flags;
    uint8_t payload[RQFT_MAX_PAYLOAD];
    size_t payload_len;
} rqft_frame_t;

typedef struct rqft_frame_diag {
    uint32_t frames_ok;
    uint32_t frames_crc_fail;
    uint32_t frames_oversize;
    uint32_t frames_dropped;
    uint32_t candidates_idle_flushed;
    uint32_t valid_candidates_idle_flushed;
    uint32_t bytes_idle_flushed;
    uint32_t bytes_passthrough;
    uint32_t bytes_dropped_in_session;
} rqft_frame_diag_t;

typedef enum rqft_frame_event_type {
    RQFT_FRAME_EVENT_FRAME = 1,
    RQFT_FRAME_EVENT_PASSTHROUGH = 2,
} rqft_frame_event_type_t;

typedef struct rqft_frame_event {
    rqft_frame_event_type_t type;
    rqft_frame_t frame;
    const uint8_t *passthrough;
    size_t passthrough_len;
} rqft_frame_event_t;

typedef void (*rqft_frame_event_fn)(void *user, const rqft_frame_event_t *event);

typedef struct rqft_frame_parser {
    uint64_t alignment;
    uint8_t storage[RQFT_FRAME_PARSER_STORAGE_SIZE];
} rqft_frame_parser_t;

rqft_result_t rqft_frame_build(rqft_frame_type_t type,
                               uint8_t sid,
                               uint8_t seq,
                               uint8_t flags,
                               const uint8_t *payload,
                               size_t payload_len,
                               uint8_t *encoded,
                               size_t encoded_cap,
                               size_t *encoded_len);

void rqft_frame_parser_init(rqft_frame_parser_t *parser, uint16_t max_payload);
void rqft_frame_parser_set_session_active(rqft_frame_parser_t *parser, bool active);
rqft_frame_parser_state_t rqft_frame_parser_state(const rqft_frame_parser_t *parser);
const rqft_frame_diag_t *rqft_frame_parser_diag(const rqft_frame_parser_t *parser);
void rqft_frame_parser_feed(rqft_frame_parser_t *parser,
                            const uint8_t *data,
                            size_t data_len,
                            uint32_t now_ms,
                            rqft_frame_event_fn emit,
                            void *user);
/** Flush a timed-out partial candidate only while session is inactive. */
void rqft_frame_parser_flush_idle(rqft_frame_parser_t *parser,
                                  uint32_t now_ms,
                                  rqft_frame_event_fn emit,
                                  void *user);
void rqft_frame_parser_set_max_payload(rqft_frame_parser_t *parser,
                                       uint16_t max_payload);
/** Return inactive-session partial-candidate deadline, when one exists. */
bool rqft_frame_parser_next_flush(const rqft_frame_parser_t *parser,
                                  uint32_t *deadline_ms);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_FRAME_H */
