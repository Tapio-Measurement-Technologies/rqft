// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/** @file @brief Go-Back-N reliable link layer. */
#ifndef RQFT_LINK_H
#define RQFT_LINK_H

#include "rqft/frame.h"
#include "rqft/rto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RQFT_N_RETRY 8
#define RQFT_LINK_STORAGE_SIZE 4608u

rqft_abort_reason_t rqft_abort_reason_from_byte(uint8_t byte);

typedef enum rqft_link_state {
    RQFT_LINK_ACTIVE = 0,
    RQFT_LINK_DEAD = 1,
} rqft_link_state_t;

typedef enum rqft_link_event_type {
    RQFT_LINK_EVENT_DELIVER = 1,
    RQFT_LINK_EVENT_ABORT = 2,
} rqft_link_event_type_t;

typedef struct rqft_link_event {
    rqft_link_event_type_t type;
    const uint8_t *payload;
    size_t payload_len;
    rqft_abort_reason_t reason;
    bool from_peer;
} rqft_link_event_t;

typedef void (*rqft_link_event_fn)(void *user, const rqft_link_event_t *event);

typedef struct rqft_link_config {
    uint8_t sid;
    uint8_t window;
    uint16_t max_payload;
    rqft_wire_transmit_fn transmit;
    void *transmit_user;
    rqft_link_event_fn on_event;
    void *event_user;
} rqft_link_config_t;

typedef struct rqft_link_diag {
    uint32_t frames_wrong_sid;
    uint32_t frames_retransmitted;
    uint32_t naks_sent;
    uint32_t duplicate_data_received;
    uint32_t out_of_order_data_received;
} rqft_link_diag_t;

typedef struct rqft_link {
    uint64_t alignment;
    uint8_t storage[RQFT_LINK_STORAGE_SIZE];
} rqft_link_t;

rqft_result_t rqft_link_init(rqft_link_t *link, const rqft_link_config_t *config);
rqft_link_state_t rqft_link_state(const rqft_link_t *link);
size_t rqft_link_in_flight(const rqft_link_t *link);
const rqft_link_diag_t *rqft_link_diagnostics(const rqft_link_t *link);
rqft_result_t rqft_link_send(rqft_link_t *link,
                             const uint8_t *payload,
                             size_t payload_len,
                             uint32_t now_ms);
void rqft_link_on_frame(rqft_link_t *link,
                        const rqft_frame_t *frame,
                        uint32_t now_ms);
void rqft_link_poll(rqft_link_t *link, uint32_t now_ms);
bool rqft_link_next_timeout(const rqft_link_t *link, uint32_t *deadline_ms);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_LINK_H */
