// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Go-Back-N link layer for SPEC.md section 4.
 */
#include "rqft/link.h"

#include <cstring>
#include <new>

namespace {

constexpr size_t kMaxWireFrame = RQFT_MAX_ENCODED + 2u;

/** One unacknowledged DATA frame buffered for retransmission. */
struct SendSlot {
    uint8_t payload[RQFT_MAX_PAYLOAD];
    uint16_t payload_len;
    uint8_t seq;
    bool retransmitted;
    uint32_t first_tx_ms;
};

struct LinkStateImpl {
    rqft_link_config_t config;
    rqft_link_state_t state;
    SendSlot slots[RQFT_WINDOW_MAX];
    uint8_t slot_head;
    uint8_t slot_count;
    uint8_t base_seq;
    uint8_t next_seq;
    uint8_t retries;
    uint32_t rto_ms;
    bool timer_running;
    uint32_t timer_start_ms;
    bool nak_goback_used;
    rqft_rto_t estimator;
    uint8_t expected_seq;
    rqft_link_diag_t diag;
};

static_assert(sizeof(LinkStateImpl) <= RQFT_LINK_STORAGE_SIZE,
              "rqft_link_t storage is too small");
static_assert(alignof(LinkStateImpl) <= alignof(rqft_link_t),
              "rqft_link_t storage is under-aligned");

LinkStateImpl &link_impl(rqft_link_t *link)
{
    return *std::launder(reinterpret_cast<LinkStateImpl *>(&link->storage[0]));
}

const LinkStateImpl &link_impl(const rqft_link_t *link)
{
    return *std::launder(reinterpret_cast<const LinkStateImpl *>(&link->storage[0]));
}

SendSlot &slot_at(LinkStateImpl &impl, size_t index)
{
    return impl.slots[(static_cast<size_t>(impl.slot_head) + index) % RQFT_WINDOW_MAX];
}

void transmit_data_frame(LinkStateImpl &impl, const SendSlot &slot)
{
    uint8_t wire[kMaxWireFrame];
    size_t wire_len = 0u;
    if (rqft_frame_build(RQFT_FRAME_DATA,
                         impl.config.sid,
                         slot.seq,
                         0u,
                         slot.payload,
                         slot.payload_len,
                         wire,
                         sizeof(wire),
                         &wire_len) == RQFT_OK) {
        impl.config.transmit(impl.config.transmit_user, wire, wire_len);
    }
}

void transmit_ack(LinkStateImpl &impl, bool nak)
{
    uint8_t wire[kMaxWireFrame];
    size_t wire_len = 0u;
    if (rqft_frame_build(RQFT_FRAME_ACK,
                         impl.config.sid,
                         impl.expected_seq,
                         nak ? 0x01u : 0x00u,
                         nullptr,
                         0u,
                         wire,
                         sizeof(wire),
                         &wire_len) == RQFT_OK) {
        impl.config.transmit(impl.config.transmit_user, wire, wire_len);
    }
}

void on_data(LinkStateImpl &impl, const rqft_frame_t *frame)
{
    if (frame->seq != impl.expected_seq) {
        uint8_t distance = static_cast<uint8_t>(frame->seq - impl.expected_seq);
        impl.diag.naks_sent++;
        if (distance < 0x80u) {
            impl.diag.out_of_order_data_received++;
        } else {
            impl.diag.duplicate_data_received++;
        }
        transmit_ack(impl, true);
        return;
    }

    impl.expected_seq = static_cast<uint8_t>(impl.expected_seq + 1u);
    transmit_ack(impl, false);

    rqft_link_event_t event{};
    event.type = RQFT_LINK_EVENT_DELIVER;
    event.payload = frame->payload;
    event.payload_len = frame->payload_len;
    impl.config.on_event(impl.config.event_user, &event);
}

void on_abort(LinkStateImpl &impl, const rqft_frame_t *frame)
{
    impl.state = RQFT_LINK_DEAD;
    rqft_link_event_t event{};
    event.type = RQFT_LINK_EVENT_ABORT;
    event.reason = rqft_abort_reason_from_byte(frame->payload[0]);
    event.from_peer = true;
    impl.config.on_event(impl.config.event_user, &event);
}

/** Retransmit every unacknowledged frame and restart the timer. */
void retransmit_all(LinkStateImpl &impl, uint32_t now_ms)
{
    impl.diag.frames_retransmitted += impl.slot_count;
    for (size_t i = 0u; i < impl.slot_count; i++) {
        SendSlot &slot = slot_at(impl, i);
        slot.retransmitted = true;
        transmit_data_frame(impl, slot);
    }
    impl.timer_start_ms = now_ms;
}

void on_ack(LinkStateImpl &impl, uint8_t ack_seq, bool nak, uint32_t now_ms)
{
    uint8_t dist = static_cast<uint8_t>(ack_seq - impl.base_seq);
    if (dist > 0u && dist <= impl.slot_count) {
        const SendSlot &newest = slot_at(impl, static_cast<size_t>(dist) - 1u);
        if (!newest.retransmitted) {
            rqft_rto_sample(&impl.estimator, now_ms - newest.first_tx_ms);
            impl.rto_ms = impl.estimator.rto_ms;
        }
        impl.slot_head = static_cast<uint8_t>((impl.slot_head + dist) % RQFT_WINDOW_MAX);
        impl.slot_count = static_cast<uint8_t>(impl.slot_count - dist);
        impl.base_seq = ack_seq;
        impl.retries = 0u;
        impl.nak_goback_used = false;
        if (impl.slot_count > 0u) {
            impl.timer_start_ms = now_ms;
        } else {
            impl.timer_running = false;
        }
    }

    if (nak && impl.slot_count > 0u && !impl.nak_goback_used) {
        impl.nak_goback_used = true;
        retransmit_all(impl, now_ms);
    }
}

void abort_local(LinkStateImpl &impl, rqft_abort_reason_t reason)
{
    uint8_t wire[kMaxWireFrame];
    size_t wire_len = 0u;
    uint8_t payload = static_cast<uint8_t>(reason);
    if (rqft_frame_build(RQFT_FRAME_ABORT,
                         impl.config.sid,
                         0u,
                         0u,
                         &payload,
                         1u,
                         wire,
                         sizeof(wire),
                         &wire_len) == RQFT_OK) {
        impl.config.transmit(impl.config.transmit_user, wire, wire_len);
    }

    impl.state = RQFT_LINK_DEAD;
    rqft_link_event_t event{};
    event.type = RQFT_LINK_EVENT_ABORT;
    event.reason = reason;
    event.from_peer = false;
    impl.config.on_event(impl.config.event_user, &event);
}

} // namespace

rqft_abort_reason_t rqft_abort_reason_from_byte(uint8_t byte)
{
    switch (byte) {
    case RQFT_ABORT_CLOSE:
    case RQFT_ABORT_E_VERSION:
    case RQFT_ABORT_E_TIMEOUT:
    case RQFT_ABORT_E_PROTO:
    case RQFT_ABORT_E_BUSY:
    case RQFT_ABORT_E_INTERNAL:
    case RQFT_ABORT_E_USER:
        return static_cast<rqft_abort_reason_t>(byte);
    default:
        return RQFT_ABORT_E_PROTO;
    }
}

rqft_result_t rqft_link_init(rqft_link_t *link, const rqft_link_config_t *config)
{
    if (config->sid == 0u ||
        config->window < 1u || config->window > RQFT_WINDOW_MAX ||
        config->max_payload < 1u || config->max_payload > RQFT_MAX_PAYLOAD ||
        config->transmit == nullptr || config->on_event == nullptr) {
        return RQFT_ERR_MALFORMED;
    }

    LinkStateImpl *impl = ::new (static_cast<void *>(&link->storage[0])) LinkStateImpl{};
    impl->config = *config;
    impl->state = RQFT_LINK_ACTIVE;
    rqft_rto_init(&impl->estimator);
    impl->rto_ms = RQFT_RTO_INITIAL_MS;
    return RQFT_OK;
}

rqft_link_state_t rqft_link_state(const rqft_link_t *link)
{
    return link_impl(link).state;
}

size_t rqft_link_in_flight(const rqft_link_t *link)
{
    return link_impl(link).slot_count;
}

const rqft_link_diag_t *rqft_link_diagnostics(const rqft_link_t *link)
{
    return &link_impl(link).diag;
}

bool rqft_link_next_timeout(const rqft_link_t *link, uint32_t *deadline_ms)
{
    const LinkStateImpl &impl = link_impl(link);
    if (impl.state == RQFT_LINK_DEAD || !impl.timer_running) {
        return false;
    }
    *deadline_ms = impl.timer_start_ms + impl.rto_ms;
    return true;
}

rqft_result_t rqft_link_send(rqft_link_t *link,
                             const uint8_t *payload,
                             size_t payload_len,
                             uint32_t now_ms)
{
    LinkStateImpl &impl = link_impl(link);
    if (impl.state == RQFT_LINK_DEAD) {
        return RQFT_ERR_LINK_DEAD;
    }
    if (payload_len < 1u || payload_len > impl.config.max_payload) {
        return RQFT_ERR_MALFORMED;
    }
    if (impl.slot_count >= impl.config.window) {
        return RQFT_ERR_WINDOW_FULL;
    }

    SendSlot &slot = slot_at(impl, impl.slot_count);
    std::memcpy(slot.payload, payload, payload_len);
    slot.payload_len = static_cast<uint16_t>(payload_len);
    slot.seq = impl.next_seq;
    slot.retransmitted = false;
    slot.first_tx_ms = now_ms;
    impl.next_seq = static_cast<uint8_t>(impl.next_seq + 1u);
    impl.slot_count++;
    if (!impl.timer_running) {
        impl.timer_running = true;
        impl.timer_start_ms = now_ms;
    }

    transmit_data_frame(impl, slot);
    return RQFT_OK;
}

void rqft_link_on_frame(rqft_link_t *link, const rqft_frame_t *frame, uint32_t now_ms)
{
    LinkStateImpl &impl = link_impl(link);
    if (impl.state == RQFT_LINK_DEAD) {
        return;
    }
    if (frame->type == RQFT_FRAME_HELLO || frame->type == RQFT_FRAME_HELLO_OK) {
        return;
    }
    if (frame->sid != impl.config.sid) {
        impl.diag.frames_wrong_sid++;
        return;
    }

    switch (frame->type) {
    case RQFT_FRAME_ACK:
        on_ack(impl, frame->seq, (frame->flags & 0x01u) != 0u, now_ms);
        break;
    case RQFT_FRAME_DATA:
        on_data(impl, frame);
        break;
    case RQFT_FRAME_ABORT:
        on_abort(impl, frame);
        break;
    default:
        break;
    }
}

void rqft_link_poll(rqft_link_t *link, uint32_t now_ms)
{
    LinkStateImpl &impl = link_impl(link);
    if (impl.state == RQFT_LINK_DEAD || !impl.timer_running) {
        return;
    }
    if (now_ms - impl.timer_start_ms < impl.rto_ms) {
        return;
    }

    impl.retries++;
    if (impl.retries >= RQFT_N_RETRY) {
        abort_local(impl, RQFT_ABORT_E_TIMEOUT);
        return;
    }

    retransmit_all(impl, now_ms);
    impl.nak_goback_used = false;
    impl.rto_ms = impl.rto_ms * 2u > RQFT_RTO_MAX_MS ? RQFT_RTO_MAX_MS : impl.rto_ms * 2u;
}
