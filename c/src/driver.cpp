// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Safe transport driver for the C session API.
 */
#include "rqft/driver.h"

#include <cstring>
#include <new>

namespace {

constexpr size_t kRxChunkSize = 256u;
constexpr size_t kMaxWireFrame = RQFT_MAX_ENCODED + 2u;
constexpr size_t kTxBacklogSize = RQFT_WINDOW_MAX * kMaxWireFrame;

struct DriverState {
    rqft_session_t session;
    rqft_session_driver_read_fn read;
    rqft_session_driver_write_fn write;
    void *user;
    bool transport_failed;
    uint8_t rx[kRxChunkSize];
    uint8_t tx[kTxBacklogSize];
    size_t tx_head;
    size_t tx_len;
    uint32_t tx_frames_dropped;
};

static_assert(sizeof(DriverState) <= RQFT_SESSION_DRIVER_STORAGE_SIZE,
              "rqft_session_driver_t storage is too small");
static_assert(alignof(DriverState) <= alignof(rqft_session_driver_t),
              "rqft_session_driver_t storage is under-aligned");

DriverState &driver_state(rqft_session_driver_t *driver)
{
    return *std::launder(reinterpret_cast<DriverState *>(&driver->storage[0]));
}

const DriverState &driver_state(const rqft_session_driver_t *driver)
{
    return *std::launder(reinterpret_cast<const DriverState *>(&driver->storage[0]));
}

/** Write backlogged TX until drained, transport would-block, or failure. */
void flush_backlog(DriverState &state)
{
    while (!state.transport_failed && state.tx_len > 0u) {
        size_t chunk = kTxBacklogSize - state.tx_head;
        if (chunk > state.tx_len) {
            chunk = state.tx_len;
        }
        ptrdiff_t written = state.write(state.user, state.tx + state.tx_head, chunk);
        if (written == 0) {
            return;
        }
        if (written < 0 || static_cast<size_t>(written) > chunk) {
            state.transport_failed = true;
            return;
        }
        state.tx_head = (state.tx_head + static_cast<size_t>(written)) % kTxBacklogSize;
        state.tx_len -= static_cast<size_t>(written);
    }
}

/** Append bytes to the TX ring. Caller has verified capacity. */
void backlog_append(DriverState &state, const uint8_t *data, size_t len)
{
    size_t tail = (state.tx_head + state.tx_len) % kTxBacklogSize;
    size_t first = kTxBacklogSize - tail;
    if (first > len) {
        first = len;
    }
    std::memcpy(state.tx + tail, data, first);
    std::memcpy(state.tx, data + first, len - first);
    state.tx_len += len;
}

void driver_transmit(void *user, const uint8_t *wire, size_t wire_len)
{
    DriverState &state = *static_cast<DriverState *>(user);
    flush_backlog(state);
    if (state.transport_failed) {
        return;
    }

    size_t offset = 0u;
    if (state.tx_len == 0u) {
        while (offset < wire_len) {
            size_t remaining = wire_len - offset;
            ptrdiff_t written = state.write(state.user, wire + offset, remaining);
            if (written == 0) {
                break;
            }
            if (written < 0 || static_cast<size_t>(written) > remaining) {
                state.transport_failed = true;
                return;
            }
            offset += static_cast<size_t>(written);
        }
        if (offset == wire_len) {
            return;
        }
    }

    /* Frames append atomically. A partially written frame always fits: the
     * direct-write path only runs with an empty backlog, and one wire frame
     * never exceeds kTxBacklogSize. A whole frame that does not fit is
     * dropped and recovered by link retransmission, like wire loss. */
    size_t rest = wire_len - offset;
    if (rest > kTxBacklogSize - state.tx_len) {
        state.tx_frames_dropped++;
        return;
    }
    backlog_append(state, wire + offset, rest);
}

rqft_result_t transport_status(const DriverState &state)
{
    return state.transport_failed ? RQFT_ERR_TRANSPORT : RQFT_OK;
}

} // namespace

rqft_result_t rqft_session_driver_init(rqft_session_driver_t *driver,
                                       const rqft_session_config_t *session_config,
                                       const rqft_session_driver_config_t *driver_config)
{
    if (driver == nullptr || session_config == nullptr || driver_config == nullptr ||
        driver_config->read == nullptr || driver_config->write == nullptr) {
        return RQFT_ERR_MALFORMED;
    }

    DriverState *state = ::new (static_cast<void *>(&driver->storage[0])) DriverState{};
    state->read = driver_config->read;
    state->write = driver_config->write;
    state->user = driver_config->user;

    rqft_session_config_t owned_config = *session_config;
    owned_config.transmit = driver_transmit;
    owned_config.transmit_user = state;
    return rqft_session_init(&state->session, &owned_config);
}

rqft_session_t *rqft_session_driver_session(rqft_session_driver_t *driver)
{
    return &driver_state(driver).session;
}

const rqft_session_t *rqft_session_driver_session_const(const rqft_session_driver_t *driver)
{
    return &driver_state(driver).session;
}

rqft_result_t rqft_session_driver_start(rqft_session_driver_t *driver, uint32_t now_ms)
{
    DriverState &state = driver_state(driver);
    if (state.transport_failed) {
        return RQFT_ERR_TRANSPORT;
    }
    rqft_result_t result = rqft_session_start(&state.session, now_ms);
    return state.transport_failed ? RQFT_ERR_TRANSPORT : result;
}

rqft_result_t rqft_session_driver_poll(rqft_session_driver_t *driver, uint32_t now_ms)
{
    DriverState &state = driver_state(driver);
    if (state.transport_failed) {
        return RQFT_ERR_TRANSPORT;
    }

    flush_backlog(state);
    if (state.transport_failed) {
        return RQFT_ERR_TRANSPORT;
    }

    for (;;) {
        ptrdiff_t received = state.read(state.user, state.rx, sizeof(state.rx));
        if (received < 0 || static_cast<size_t>(received) > sizeof(state.rx)) {
            state.transport_failed = true;
            return RQFT_ERR_TRANSPORT;
        }
        if (received == 0) {
            break;
        }
        rqft_session_receive(&state.session, state.rx,
                             static_cast<size_t>(received), now_ms);
        if (state.transport_failed) {
            return RQFT_ERR_TRANSPORT;
        }
    }

    rqft_session_poll(&state.session, now_ms);
    flush_backlog(state);
    return transport_status(state);
}

rqft_result_t rqft_session_driver_status(const rqft_session_driver_t *driver)
{
    return transport_status(driver_state(driver));
}

size_t rqft_session_driver_tx_pending(const rqft_session_driver_t *driver)
{
    return driver_state(driver).tx_len;
}

uint32_t rqft_session_driver_tx_dropped(const rqft_session_driver_t *driver)
{
    return driver_state(driver).tx_frames_dropped;
}
