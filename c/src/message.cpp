// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Session-layer body codecs for SPEC.md sections 5.2 and 5.3.
 */
#include "rqft/message.h"

#include <cstring>

namespace {

/** caps bits not defined by protocol version 1; they must be zero. */
constexpr uint8_t kCapsReservedMask = 0xFEu;

/** Validate shared HELLO/HELLO_OK field ranges from SPEC.md section 5.2. */
bool hello_fields_valid(uint8_t ver_min,
                        uint8_t ver_max,
                        uint16_t max_payload,
                        uint8_t window,
                        uint8_t caps)
{
    return ver_min <= ver_max &&
           max_payload >= 1u && max_payload <= RQFT_MAX_PAYLOAD &&
           window >= 1u && window <= RQFT_WINDOW_MAX &&
           (caps & kCapsReservedMask) == 0u;
}

/** Map a wire role byte to a typed role; false when undefined. */
bool decode_role(uint8_t byte, rqft_role_t *out)
{
    if (byte != RQFT_ROLE_CONTROLLER && byte != RQFT_ROLE_RESPONDER) {
        return false;
    }
    *out = static_cast<rqft_role_t>(byte);
    return true;
}

void put_u16_le(uint8_t *out, uint16_t value)
{
    out[0] = static_cast<uint8_t>(value & 0xFFu);
    out[1] = static_cast<uint8_t>(value >> 8u);
}

uint16_t get_u16_le(const uint8_t *data)
{
    return static_cast<uint16_t>(static_cast<uint16_t>(data[0]) |
                                 static_cast<uint16_t>(static_cast<uint16_t>(data[1]) << 8u));
}

} // namespace

rqft_result_t rqft_hello_encode(const rqft_hello_t *hello, uint8_t out[RQFT_HELLO_BODY_LEN])
{
    if (!hello_fields_valid(hello->ver_min, hello->ver_max, hello->max_payload,
                            hello->window, hello->caps)) {
        return RQFT_ERR_MALFORMED;
    }

    out[0] = hello->ver_min;
    out[1] = hello->ver_max;
    out[2] = static_cast<uint8_t>(hello->role);
    put_u16_le(&out[3], hello->max_payload);
    out[5] = hello->window;
    out[6] = hello->caps;
    out[7] = 0u;
    return RQFT_OK;
}

rqft_result_t rqft_hello_decode(const uint8_t *data, size_t len, rqft_hello_t *out)
{
    if (len != RQFT_HELLO_BODY_LEN || data[7] != 0u || !decode_role(data[2], &out->role)) {
        return RQFT_ERR_MALFORMED;
    }

    out->ver_min = data[0];
    out->ver_max = data[1];
    out->max_payload = get_u16_le(&data[3]);
    out->window = data[5];
    out->caps = data[6];
    if (!hello_fields_valid(out->ver_min, out->ver_max, out->max_payload,
                            out->window, out->caps)) {
        return RQFT_ERR_MALFORMED;
    }
    return RQFT_OK;
}

rqft_result_t rqft_hello_ok_encode(const rqft_hello_ok_t *ok, uint8_t out[RQFT_HELLO_BODY_LEN])
{
    if (!hello_fields_valid(ok->ver, ok->ver, ok->max_payload, ok->window, ok->caps)) {
        return RQFT_ERR_MALFORMED;
    }

    out[0] = ok->ver;
    out[1] = static_cast<uint8_t>(ok->role);
    put_u16_le(&out[2], ok->max_payload);
    out[4] = ok->window;
    out[5] = ok->caps;
    out[6] = 0u;
    out[7] = 0u;
    return RQFT_OK;
}

rqft_result_t rqft_hello_ok_decode(const uint8_t *data, size_t len, rqft_hello_ok_t *out)
{
    if (len != RQFT_HELLO_BODY_LEN || data[6] != 0u || data[7] != 0u ||
        !decode_role(data[1], &out->role)) {
        return RQFT_ERR_MALFORMED;
    }

    out->ver = data[0];
    out->max_payload = get_u16_le(&data[2]);
    out->window = data[4];
    out->caps = data[5];
    if (!hello_fields_valid(out->ver, out->ver, out->max_payload, out->window, out->caps)) {
        return RQFT_ERR_MALFORMED;
    }
    return RQFT_OK;
}

namespace {

/** Validate strict UTF-8: no overlongs, no surrogates, max U+10FFFF. */
bool utf8_valid(const uint8_t *data, size_t len)
{
    size_t i = 0u;
    while (i < len) {
        uint8_t lead = data[i];
        size_t cont = 0u;
        uint32_t cp = 0u;
        uint32_t min = 0u;
        if (lead < 0x80u) {
            i++;
            continue;
        }
        if ((lead & 0xE0u) == 0xC0u) {
            cont = 1u;
            cp = lead & 0x1Fu;
            min = 0x80u;
        } else if ((lead & 0xF0u) == 0xE0u) {
            cont = 2u;
            cp = lead & 0x0Fu;
            min = 0x800u;
        } else if ((lead & 0xF8u) == 0xF0u) {
            cont = 3u;
            cp = lead & 0x07u;
            min = 0x10000u;
        } else {
            return false;
        }
        if (i + cont >= len) {
            return false;
        }
        for (size_t k = 1u; k <= cont; k++) {
            if ((data[i + k] & 0xC0u) != 0x80u) {
                return false;
            }
            cp = (cp << 6u) | (data[i + k] & 0x3Fu);
        }
        if (cp < min || cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) {
            return false;
        }
        i += cont + 1u;
    }
    return true;
}

/** Bounded little-endian field reader over one message body. */
struct Reader {
    const uint8_t *data;
    size_t len;
    size_t pos;
    bool ok;

    explicit Reader(const uint8_t *body, size_t body_len)
        : data(body), len(body_len), pos(0u), ok(true)
    {
    }

    const uint8_t *take(size_t count)
    {
        if (!ok || pos + count > len) {
            ok = false;
            return nullptr;
        }
        const uint8_t *chunk = data + pos;
        pos += count;
        return chunk;
    }

    uint8_t u8()
    {
        const uint8_t *chunk = take(1u);
        return chunk != nullptr ? chunk[0] : 0u;
    }

    uint16_t u16()
    {
        const uint8_t *chunk = take(2u);
        return chunk != nullptr ? get_u16_le(chunk) : 0u;
    }

    uint32_t u32()
    {
        const uint8_t *chunk = take(4u);
        if (chunk == nullptr) {
            return 0u;
        }
        return static_cast<uint32_t>(chunk[0]) |
               (static_cast<uint32_t>(chunk[1]) << 8u) |
               (static_cast<uint32_t>(chunk[2]) << 16u) |
               (static_cast<uint32_t>(chunk[3]) << 24u);
    }

    void path(const uint8_t **out, size_t *out_len)
    {
        uint8_t length = u8();
        if (length > RQFT_MAX_PATH) {
            ok = false;
        }
        const uint8_t *chunk = take(length);
        *out = chunk;
        *out_len = chunk != nullptr ? length : 0u;
    }

    bool finished() const { return ok && pos == len; }
};

/** Bounded writer assembling one message payload. */
struct Writer {
    uint8_t *out;
    size_t cap;
    size_t pos;
    bool ok;

    explicit Writer(uint8_t *buffer, size_t buffer_cap)
        : out(buffer), cap(buffer_cap), pos(0u), ok(true)
    {
    }

    void bytes(const uint8_t *data, size_t len)
    {
        if (!ok || pos + len > cap) {
            ok = false;
            return;
        }
        if (len > 0u) {
            std::memcpy(out + pos, data, len);
        }
        pos += len;
    }

    void u8(uint8_t value) { bytes(&value, 1u); }

    void u16(uint16_t value)
    {
        uint8_t chunk[2];
        chunk[0] = static_cast<uint8_t>(value & 0xFFu);
        chunk[1] = static_cast<uint8_t>(value >> 8u);
        bytes(chunk, sizeof(chunk));
    }

    void u32(uint32_t value)
    {
        uint8_t chunk[4];
        chunk[0] = static_cast<uint8_t>(value & 0xFFu);
        chunk[1] = static_cast<uint8_t>((value >> 8u) & 0xFFu);
        chunk[2] = static_cast<uint8_t>((value >> 16u) & 0xFFu);
        chunk[3] = static_cast<uint8_t>((value >> 24u) & 0xFFu);
        bytes(chunk, sizeof(chunk));
    }

    bool path(const uint8_t *data, size_t len)
    {
        if (len > RQFT_MAX_PATH) {
            return false;
        }
        u8(static_cast<uint8_t>(len));
        bytes(data, len);
        return true;
    }
};

/** Map a wire error code byte to a typed code; false when undefined. */
bool decode_err_code(uint8_t byte, rqft_err_code_t *out)
{
    if (byte < RQFT_E_FS_OPEN || byte > RQFT_E_UNSUPPORTED) {
        return false;
    }
    *out = static_cast<rqft_err_code_t>(byte);
    return true;
}

/** Check a GET_DONE/PUT_DONE status value: 0 or a defined ERR code. */
bool done_status_valid(uint8_t status)
{
    rqft_err_code_t code;
    return status == 0u || decode_err_code(status, &code);
}

} // namespace

bool rqft_path_valid(const uint8_t *path, size_t len, bool allow_empty)
{
    if (len == 0u) {
        return allow_empty;
    }
    if (len > RQFT_MAX_PATH) {
        return false;
    }
    for (size_t i = 0u; i < len; i++) {
        if (path[i] == 0x00u || path[i] == '\\') {
            return false;
        }
    }
    if (!utf8_valid(path, len)) {
        return false;
    }

    size_t start = 0u;
    for (size_t i = 0u; i <= len; i++) {
        if (i == len || path[i] == '/') {
            size_t seg_len = i - start;
            if (seg_len == 0u) {
                return false;
            }
            if (seg_len == 1u && path[start] == '.') {
                return false;
            }
            if (seg_len == 2u && path[start] == '.' && path[start + 1u] == '.') {
                return false;
            }
            start = i + 1u;
        }
    }
    return true;
}

rqft_result_t rqft_msg_encode(const rqft_msg_t *msg,
                              uint8_t *out,
                              size_t out_cap,
                              size_t *out_len)
{
    Writer writer(out, out_cap);
    bool encodable = true;

    switch (msg->type) {
    case RQFT_MSG_LIST_REQ:
        writer.u8(RQFT_MSG_LIST_REQ);
        writer.u8(msg->u.list_req.want_crc ? 0x01u : 0x00u);
        encodable = writer.path(msg->u.list_req.root, msg->u.list_req.root_len);
        break;
    case RQFT_MSG_LIST_ENTRY:
        writer.u8(RQFT_MSG_LIST_ENTRY);
        writer.u8(msg->u.list_entry.etype);
        writer.u8(msg->u.list_entry.crc_valid ? 0x01u : 0x00u);
        writer.u32(msg->u.list_entry.size);
        writer.u32(msg->u.list_entry.crc32);
        writer.u32(msg->u.list_entry.mtime);
        encodable = writer.path(msg->u.list_entry.path, msg->u.list_entry.path_len);
        break;
    case RQFT_MSG_LIST_END:
        writer.u8(RQFT_MSG_LIST_END);
        writer.u16(msg->u.list_end.count);
        break;
    case RQFT_MSG_GET_REQ:
        writer.u8(RQFT_MSG_GET_REQ);
        writer.u32(msg->u.get_req.offset);
        encodable = writer.path(msg->u.get_req.path, msg->u.get_req.path_len);
        break;
    case RQFT_MSG_FILE_INFO:
        writer.u8(RQFT_MSG_FILE_INFO);
        writer.u32(msg->u.file_info.size);
        break;
    case RQFT_MSG_FILE_DATA:
        writer.u8(RQFT_MSG_FILE_DATA);
        writer.bytes(msg->u.file_data.data, msg->u.file_data.len);
        break;
    case RQFT_MSG_FILE_END:
        writer.u8(RQFT_MSG_FILE_END);
        writer.u32(msg->u.file_end.crc32);
        break;
    case RQFT_MSG_GET_DONE:
        writer.u8(RQFT_MSG_GET_DONE);
        writer.u8(msg->u.get_done.status);
        encodable = done_status_valid(msg->u.get_done.status);
        break;
    case RQFT_MSG_PUT_REQ:
        writer.u8(RQFT_MSG_PUT_REQ);
        writer.u32(msg->u.put_req.size);
        writer.u32(msg->u.put_req.crc32);
        encodable = writer.path(msg->u.put_req.path, msg->u.put_req.path_len);
        break;
    case RQFT_MSG_PUT_OK:
        writer.u8(RQFT_MSG_PUT_OK);
        break;
    case RQFT_MSG_PUT_DONE:
        writer.u8(RQFT_MSG_PUT_DONE);
        writer.u8(msg->u.put_done.status);
        encodable = done_status_valid(msg->u.put_done.status);
        break;
    case RQFT_MSG_DEL_FILE:
    case RQFT_MSG_DEL_DIR:
        writer.u8(static_cast<uint8_t>(msg->type));
        encodable = writer.path(msg->u.del_path.path, msg->u.del_path.path_len);
        break;
    case RQFT_MSG_DEL_OK:
        writer.u8(RQFT_MSG_DEL_OK);
        break;
    case RQFT_MSG_PLAN:
        writer.u8(RQFT_MSG_PLAN);
        writer.u16(msg->u.plan.nfiles);
        writer.u32(msg->u.plan.nbytes);
        break;
    case RQFT_MSG_NOTIFY:
        writer.u8(RQFT_MSG_NOTIFY);
        writer.u32(msg->u.notify.flags);
        encodable = (msg->u.notify.flags & ~RQFT_NOTIFY_DEFINED_MASK) == 0u;
        break;
    case RQFT_MSG_PING:
    case RQFT_MSG_PONG:
        writer.u8(static_cast<uint8_t>(msg->type));
        writer.u32(msg->u.token.token);
        break;
    case RQFT_MSG_ERR:
        writer.u8(RQFT_MSG_ERR);
        writer.u8(static_cast<uint8_t>(msg->u.err.code));
        writer.u8(msg->u.err.ref_msgtype);
        writer.u16(msg->u.err.detail);
        break;
    case RQFT_MSG_UNKNOWN:
    default:
        return RQFT_ERR_MALFORMED;
    }

    if (!encodable) {
        return RQFT_ERR_MALFORMED;
    }
    if (!writer.ok) {
        return RQFT_ERR_OUTPUT_TOO_SMALL;
    }
    *out_len = writer.pos;
    return RQFT_OK;
}

rqft_result_t rqft_msg_decode(const uint8_t *payload, size_t len, rqft_msg_t *out)
{
    if (len == 0u) {
        return RQFT_ERR_MALFORMED;
    }
    uint8_t msg_type = payload[0];
    Reader reader(payload + 1u, len - 1u);
    std::memset(out, 0, sizeof(*out));

    switch (msg_type) {
    case RQFT_MSG_LIST_REQ: {
        out->type = RQFT_MSG_LIST_REQ;
        uint8_t flags = reader.u8();
        if ((flags & ~0x01u) != 0u) {
            return RQFT_ERR_MALFORMED;
        }
        out->u.list_req.want_crc = (flags & 0x01u) != 0u;
        reader.path(&out->u.list_req.root, &out->u.list_req.root_len);
        break;
    }
    case RQFT_MSG_LIST_ENTRY: {
        out->type = RQFT_MSG_LIST_ENTRY;
        out->u.list_entry.etype = reader.u8();
        uint8_t eflags = reader.u8();
        if ((eflags & ~0x01u) != 0u) {
            return RQFT_ERR_MALFORMED;
        }
        out->u.list_entry.crc_valid = (eflags & 0x01u) != 0u;
        out->u.list_entry.size = reader.u32();
        out->u.list_entry.crc32 = reader.u32();
        out->u.list_entry.mtime = reader.u32();
        reader.path(&out->u.list_entry.path, &out->u.list_entry.path_len);
        break;
    }
    case RQFT_MSG_LIST_END:
        out->type = RQFT_MSG_LIST_END;
        out->u.list_end.count = reader.u16();
        break;
    case RQFT_MSG_GET_REQ:
        out->type = RQFT_MSG_GET_REQ;
        out->u.get_req.offset = reader.u32();
        reader.path(&out->u.get_req.path, &out->u.get_req.path_len);
        break;
    case RQFT_MSG_FILE_INFO:
        out->type = RQFT_MSG_FILE_INFO;
        out->u.file_info.size = reader.u32();
        break;
    case RQFT_MSG_FILE_DATA:
        out->type = RQFT_MSG_FILE_DATA;
        out->u.file_data.data = payload + 1u;
        out->u.file_data.len = len - 1u;
        reader.pos = reader.len;
        break;
    case RQFT_MSG_FILE_END:
        out->type = RQFT_MSG_FILE_END;
        out->u.file_end.crc32 = reader.u32();
        break;
    case RQFT_MSG_GET_DONE:
        out->type = RQFT_MSG_GET_DONE;
        out->u.get_done.status = reader.u8();
        if (!done_status_valid(out->u.get_done.status)) {
            return RQFT_ERR_MALFORMED;
        }
        break;
    case RQFT_MSG_PUT_REQ:
        out->type = RQFT_MSG_PUT_REQ;
        out->u.put_req.size = reader.u32();
        out->u.put_req.crc32 = reader.u32();
        reader.path(&out->u.put_req.path, &out->u.put_req.path_len);
        break;
    case RQFT_MSG_PUT_OK:
        out->type = RQFT_MSG_PUT_OK;
        break;
    case RQFT_MSG_PUT_DONE:
        out->type = RQFT_MSG_PUT_DONE;
        out->u.put_done.status = reader.u8();
        if (!done_status_valid(out->u.put_done.status)) {
            return RQFT_ERR_MALFORMED;
        }
        break;
    case RQFT_MSG_DEL_FILE:
    case RQFT_MSG_DEL_DIR:
        out->type = static_cast<rqft_msg_type_t>(msg_type);
        reader.path(&out->u.del_path.path, &out->u.del_path.path_len);
        break;
    case RQFT_MSG_DEL_OK:
        out->type = RQFT_MSG_DEL_OK;
        break;
    case RQFT_MSG_PLAN:
        out->type = RQFT_MSG_PLAN;
        out->u.plan.nfiles = reader.u16();
        out->u.plan.nbytes = reader.u32();
        break;
    case RQFT_MSG_NOTIFY:
        out->type = RQFT_MSG_NOTIFY;
        // Lenient receive: mask undefined bits, ignore appended future
        // fields (spec 5.4). A body shorter than 4 bytes still fails via
        // the reader underrun.
        out->u.notify.flags = reader.u32() & RQFT_NOTIFY_DEFINED_MASK;
        reader.pos = reader.len;
        break;
    case RQFT_MSG_PING:
    case RQFT_MSG_PONG:
        out->type = static_cast<rqft_msg_type_t>(msg_type);
        out->u.token.token = reader.u32();
        break;
    case RQFT_MSG_ERR: {
        out->type = RQFT_MSG_ERR;
        if (!decode_err_code(reader.u8(), &out->u.err.code)) {
            return RQFT_ERR_MALFORMED;
        }
        out->u.err.ref_msgtype = reader.u8();
        out->u.err.detail = reader.u16();
        break;
    }
    default:
        out->type = RQFT_MSG_UNKNOWN;
        out->u.unknown.msg_type = msg_type;
        out->u.unknown.body = payload + 1u;
        out->u.unknown.len = len - 1u;
        return RQFT_OK;
    }

    return reader.finished() ? RQFT_OK : RQFT_ERR_MALFORMED;
}
