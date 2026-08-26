// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/** @file @brief Safe transport driver for one session endpoint. */
#ifndef RQFT_DRIVER_H
#define RQFT_DRIVER_H

#include "rqft/session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RQFT_SESSION_DRIVER_STORAGE_SIZE (RQFT_SESSION_STORAGE_SIZE + 4608u)

/**
 * Non-blocking transport read callback.
 *
 * @return 1..cap bytes read, zero when RX is drained, or a negative value on
 * transport failure. Callback must never wait for new input.
 */
typedef ptrdiff_t (*rqft_session_driver_read_fn)(void *user,
                                                 uint8_t *data,
                                                 size_t cap);

/**
 * Non-blocking partial-write transport sink.
 *
 * @return 1..len bytes consumed, zero when the transport cannot accept any
 * byte right now (TX buffer full), or a negative value on transport failure.
 * Driver retries positive partial progress and defers unwritten bytes across
 * polls; a zero return is never treated as failure. Callback must never block
 * waiting for TX capacity.
 */
typedef ptrdiff_t (*rqft_session_driver_write_fn)(void *user,
                                                  const uint8_t *data,
                                                  size_t len);

/** Transport callbacks copied into safe session driver. */
typedef struct rqft_session_driver_config {
    /** Non-blocking RX source. Must be non-null. */
    rqft_session_driver_read_fn read;

    /** Partial-write-capable TX sink. Must be non-null. */
    rqft_session_driver_write_fn write;

    /** Caller data passed to read and write. */
    void *user;
} rqft_session_driver_config_t;

/**
 * Static driver owning one session. It drains all available RX before every
 * session poll and buffers TX bytes the transport cannot accept yet, flushing
 * them on later polls. When the deferred-TX backlog is full, whole frames are
 * dropped and recovered by link-layer retransmission, exactly like wire loss.
 * Do not move or copy after init.
 */
typedef struct rqft_session_driver {
    /** Private alignment reserve. Do not access directly. */
    uint64_t alignment;

    /** Private storage. Initialize with rqft_session_driver_init(). */
    uint8_t storage[RQFT_SESSION_DRIVER_STORAGE_SIZE];
} rqft_session_driver_t;

/**
 * Initialize driver and its owned session.
 *
 * Driver supplies session_config.transmit and transmit_user. Both driver and
 * owned session keep self-references and must not be moved or copied after
 * initialization.
 */
rqft_result_t rqft_session_driver_init(
    rqft_session_driver_t *driver,
    const rqft_session_config_t *session_config,
    const rqft_session_driver_config_t *driver_config);

/** Return session owned by initialized driver. */
rqft_session_t *rqft_session_driver_session(rqft_session_driver_t *driver);

/** Return owned session for read-only use. */
const rqft_session_t *rqft_session_driver_session_const(
    const rqft_session_driver_t *driver);

/** Start owned session and surface synchronous transport failure. */
rqft_result_t rqft_session_driver_start(rqft_session_driver_t *driver,
                                        uint32_t now_ms);

/**
 * Flush deferred TX, drain all currently available RX, then run one bounded
 * session poll. Call again for every extra work slice. Transport failure
 * remains sticky until reinitialization.
 */
rqft_result_t rqft_session_driver_poll(rqft_session_driver_t *driver,
                                       uint32_t now_ms);

/**
 * Return sticky transport status. Check after direct owned-session calls that
 * may transmit but cannot return a transport result themselves.
 */
rqft_result_t rqft_session_driver_status(
    const rqft_session_driver_t *driver);

/** Return deferred TX bytes not yet accepted by the transport. */
size_t rqft_session_driver_tx_pending(const rqft_session_driver_t *driver);

/**
 * Return count of whole frames dropped because the deferred-TX backlog was
 * full. Dropped frames are recovered by link retransmission, like wire loss;
 * a growing count signals sustained transport backpressure.
 */
uint32_t rqft_session_driver_tx_dropped(const rqft_session_driver_t *driver);

#ifdef __cplusplus
}
#endif

#endif /* RQFT_DRIVER_H */
