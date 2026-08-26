// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief RQFT frame codec and resynchronizing parser for SPEC.md section 3.
 */
#include "rqft/frame.h"

#include "rqft/cobs.h"
#include "rqft/crc32.h"

#include <cstring>
#include <new>

namespace {

constexpr size_t kFrameHeaderLen = 4u;
constexpr size_t kFrameCrcLen = 4u;
constexpr size_t kMaxDecodedFrame = kFrameHeaderLen + RQFT_MAX_PAYLOAD + kFrameCrcLen;

struct FrameParserState {
    rqft_frame_parser_state_t state;
    uint8_t candidate[RQFT_MAX_ENCODED + 1u];
    size_t candidate_len;
    uint16_t max_payload;
    bool session_active;
    uint32_t last_byte_ms;
    rqft_frame_diag_t diag;
};

static_assert(sizeof(FrameParserState) <= RQFT_FRAME_PARSER_STORAGE_SIZE,
              "rqft_frame_parser_t storage is too small");
static_assert(alignof(FrameParserState) <= alignof(rqft_frame_parser_t),
              "rqft_frame_parser_t storage is under-aligned");

FrameParserState &parser_state(rqft_frame_parser_t *parser)
{
    return *std::launder(reinterpret_cast<FrameParserState *>(&parser->storage[0]));
}

const FrameParserState &parser_state(const rqft_frame_parser_t *parser)
{
    return *std::launder(reinterpret_cast<const FrameParserState *>(&parser->storage[0]));
}

void put_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = static_cast<uint8_t>(value & 0xffu);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xffu);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xffu);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xffu);
}

uint32_t get_u32_le(const uint8_t *data)
{
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

bool valid_shape(uint8_t type, uint8_t sid, uint8_t flags, size_t payload_len)
{
    if (sid == 0u) {
        return false;
    }

    switch (type) {
    case RQFT_FRAME_HELLO:
        return flags == 0u && payload_len == 8u;
    case RQFT_FRAME_HELLO_OK:
        return flags == 0u && payload_len == 8u;
    case RQFT_FRAME_DATA:
        return flags == 0u && payload_len >= 1u;
    case RQFT_FRAME_ACK:
        return (flags & static_cast<uint8_t>(~0x01u)) == 0u && payload_len == 0u;
    case RQFT_FRAME_ABORT:
        return flags == 0u && payload_len == 1u;
    default:
        return false;
    }
}

void emit_passthrough(FrameParserState *state,
                      const uint8_t *data,
                      size_t len,
                      rqft_frame_event_fn emit,
                      void *user)
{
    if (len == 0u) {
        return;
    }
    if (state->session_active) {
        state->diag.bytes_dropped_in_session += static_cast<uint32_t>(len);
        return;
    }

    state->diag.bytes_passthrough += static_cast<uint32_t>(len);
    rqft_frame_event_t event{};
    event.type = RQFT_FRAME_EVENT_PASSTHROUGH;
    event.passthrough = data;
    event.passthrough_len = len;
    emit(user, &event);
}

void emit_frame(FrameParserState *state, const rqft_frame_t *frame, rqft_frame_event_fn emit, void *user)
{
    state->diag.frames_ok++;
    rqft_frame_event_t event{};
    event.type = RQFT_FRAME_EVENT_FRAME;
    event.frame = *frame;
    emit(user, &event);
}

bool decode_candidate(const FrameParserState *state, uint8_t *decoded, size_t *decoded_len)
{
    rqft_result_t result = rqft_cobs_decode(state->candidate,
                                            state->candidate_len,
                                            decoded,
                                            kMaxDecodedFrame,
                                            decoded_len);
    if (result != RQFT_OK || *decoded_len < (kFrameHeaderLen + kFrameCrcLen)) {
        return false;
    }

    size_t body_len = *decoded_len - kFrameCrcLen;
    uint32_t expected_crc = get_u32_le(decoded + body_len);
    return rqft_crc32(decoded, body_len) == expected_crc;
}

void process_candidate(FrameParserState *state, rqft_frame_event_fn emit, void *user)
{
    uint8_t decoded[kMaxDecodedFrame];
    size_t decoded_len = 0u;
    if (!decode_candidate(state, decoded, &decoded_len)) {
        state->diag.frames_crc_fail++;
        emit_passthrough(state, state->candidate, state->candidate_len, emit, user);
        state->candidate_len = 0u;
        return;
    }

    size_t body_len = decoded_len - kFrameCrcLen;
    size_t payload_len = body_len - kFrameHeaderLen;
    if (payload_len > static_cast<size_t>(state->max_payload) ||
        !valid_shape(decoded[0], decoded[1], decoded[3], payload_len)) {
        state->diag.frames_dropped++;
        state->candidate_len = 0u;
        return;
    }

    rqft_frame_t frame{};
    frame.type = static_cast<rqft_frame_type_t>(decoded[0]);
    frame.sid = decoded[1];
    frame.seq = decoded[2];
    frame.flags = decoded[3];
    frame.payload_len = payload_len;
    if (payload_len > 0u) {
        std::memcpy(frame.payload, decoded + kFrameHeaderLen, payload_len);
    }

    state->candidate_len = 0u;
    emit_frame(state, &frame, emit, user);
}

} // namespace

rqft_result_t rqft_frame_build(rqft_frame_type_t type,
                               uint8_t sid,
                               uint8_t seq,
                               uint8_t flags,
                               const uint8_t *payload,
                               size_t payload_len,
                               uint8_t *encoded,
                               size_t encoded_cap,
                               size_t *encoded_len)
{
    if (payload_len > RQFT_MAX_PAYLOAD ||
        !valid_shape(static_cast<uint8_t>(type), sid, flags, payload_len)) {
        return RQFT_ERR_MALFORMED;
    }
    if (encoded_cap < 2u) {
        return RQFT_ERR_OUTPUT_TOO_SMALL;
    }

    uint8_t decoded[kMaxDecodedFrame];
    size_t decoded_len = kFrameHeaderLen + payload_len + kFrameCrcLen;
    decoded[0] = static_cast<uint8_t>(type);
    decoded[1] = sid;
    decoded[2] = seq;
    decoded[3] = flags;
    if (payload_len > 0u) {
        std::memcpy(decoded + kFrameHeaderLen, payload, payload_len);
    }
    put_u32_le(decoded + kFrameHeaderLen + payload_len,
               rqft_crc32(decoded, kFrameHeaderLen + payload_len));

    size_t cobs_len = 0u;
    rqft_result_t result = rqft_cobs_encode(decoded,
                                            decoded_len,
                                            encoded + 1u,
                                            encoded_cap - 2u,
                                            &cobs_len);
    if (result != RQFT_OK) {
        return result;
    }

    encoded[0] = 0u;
    encoded[1u + cobs_len] = 0u;
    *encoded_len = cobs_len + 2u;
    return RQFT_OK;
}

void rqft_frame_parser_init(rqft_frame_parser_t *parser, uint16_t max_payload)
{
    FrameParserState *state = ::new (static_cast<void *>(&parser->storage[0])) FrameParserState{};
    state->state = RQFT_FRAME_PARSER_HUNT;
    state->max_payload = max_payload > RQFT_MAX_PAYLOAD ? static_cast<uint16_t>(RQFT_MAX_PAYLOAD) : max_payload;
}

void rqft_frame_parser_set_session_active(rqft_frame_parser_t *parser, bool active)
{
    parser_state(parser).session_active = active;
}

void rqft_frame_parser_set_max_payload(rqft_frame_parser_t *parser, uint16_t max_payload)
{
    parser_state(parser).max_payload =
        max_payload > RQFT_MAX_PAYLOAD ? static_cast<uint16_t>(RQFT_MAX_PAYLOAD) : max_payload;
}

bool rqft_frame_parser_next_flush(const rqft_frame_parser_t *parser, uint32_t *deadline_ms)
{
    const FrameParserState &state = parser_state(parser);
    if (state.session_active ||
        state.state != RQFT_FRAME_PARSER_FRAME || state.candidate_len == 0u) {
        return false;
    }
    *deadline_ms = state.last_byte_ms + static_cast<uint32_t>(RQFT_T_FLUSH_MS);
    return true;
}

rqft_frame_parser_state_t rqft_frame_parser_state(const rqft_frame_parser_t *parser)
{
    return parser_state(parser).state;
}

const rqft_frame_diag_t *rqft_frame_parser_diag(const rqft_frame_parser_t *parser)
{
    return &parser_state(parser).diag;
}

void rqft_frame_parser_feed(rqft_frame_parser_t *parser,
                            const uint8_t *data,
                            size_t data_len,
                            uint32_t now_ms,
                            rqft_frame_event_fn emit,
                            void *user)
{
    FrameParserState &state = parser_state(parser);
    size_t pos = 0u;
    while (pos < data_len) {
        uint8_t byte = data[pos];
        pos++;

        if (state.state == RQFT_FRAME_PARSER_HUNT) {
            if (byte == 0u) {
                state.state = RQFT_FRAME_PARSER_FRAME;
                state.candidate_len = 0u;
            } else {
                emit_passthrough(&state, &data[pos - 1u], 1u, emit, user);
            }
            continue;
        }

        if (byte == 0u) {
            if (state.candidate_len > 0u) {
                process_candidate(&state, emit, user);
            }
            continue;
        }

        state.candidate[state.candidate_len] = byte;
        state.candidate_len++;
        state.last_byte_ms = now_ms;
        if (state.candidate_len > RQFT_MAX_ENCODED) {
            state.diag.frames_oversize++;
            emit_passthrough(&state, state.candidate, state.candidate_len, emit, user);
            state.candidate_len = 0u;
            state.state = RQFT_FRAME_PARSER_HUNT;
        }
    }
}

void rqft_frame_parser_flush_idle(rqft_frame_parser_t *parser,
                                  uint32_t now_ms,
                                  rqft_frame_event_fn emit,
                                  void *user)
{
    FrameParserState &state = parser_state(parser);
    if (state.session_active ||
        state.state != RQFT_FRAME_PARSER_FRAME || state.candidate_len == 0u) {
        return;
    }

    if ((now_ms - state.last_byte_ms) >= static_cast<uint32_t>(RQFT_T_FLUSH_MS)) {
        uint8_t decoded[kMaxDecodedFrame];
        size_t decoded_len = 0u;
        state.diag.candidates_idle_flushed++;
        state.diag.bytes_idle_flushed += static_cast<uint32_t>(state.candidate_len);
        if (decode_candidate(&state, decoded, &decoded_len)) {
            state.diag.valid_candidates_idle_flushed++;
        }
        emit_passthrough(&state, state.candidate, state.candidate_len, emit, user);
        state.candidate_len = 0u;
        state.state = RQFT_FRAME_PARSER_HUNT;
    }
}
