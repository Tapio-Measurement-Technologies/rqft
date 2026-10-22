// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Sans-io session layer for SPEC.md sections 4.2 and 5.
 */
#include "rqft/session.h"

#include "rqft/crc32.h"
#include "rqft/link.h"
#include "rqft/message.h"

#include <cstring>
#include <new>

namespace {

constexpr size_t kMaxWireFrame = RQFT_MAX_ENCODED + 2u;

/** Stored HELLO_OK wire frame: two delimiters plus the COBS body of a
 * 16-byte decoded frame. */
constexpr size_t kHelloOkWireCap = 24u;

/** Control-queue slot payload capacity: sized for the largest queued
 * message, a GET_REQ with a full-length path. */
constexpr size_t kCtrlSlotCap = 6u + RQFT_MAX_PATH;

/** Control-queue depth; overflow is a broken peer and aborts. */
constexpr size_t kCtrlSlots = 16u;

/** Upper bound on pump loop turns per poll, so a pathological listing
 * cannot stall one poll indefinitely. */
constexpr unsigned kPumpMaxSteps = 32u;

/** Wire overhead of a LIST_ENTRY message before path bytes: msg_type,
 * etype, eflags, size, crc32, mtime, and the path length prefix. */
constexpr size_t kListEntryOverhead = 16u;

/** Wire overhead of a GET_REQ message before path bytes: msg_type,
 * offset, and the path length prefix. */
constexpr size_t kGetReqOverhead = 6u;

/** Wire overhead of a PUT_REQ message before path bytes: msg_type,
 * size, crc32, and the path length prefix. */
constexpr size_t kPutReqOverhead = 10u;

/** Wire overhead of a DEL_FILE/DEL_DIR message before path bytes:
 * msg_type and the path length prefix. */
constexpr size_t kDelOverhead = 2u;

/** Largest single read handed to the filesystem while hashing. */
constexpr size_t kHashReadMax = 512u;

/** In-flight operation discriminator; None when no operation runs. */
enum class OpKind : uint8_t {
    None,
    CtrlList,
    RespList,
    CtrlGet,
    RespGet,
    CtrlPut,
    RespPut,
    CtrlDel,
};

/** Controller-side PUT progress through SPEC.md section 5.4. */
enum class PutPhase : uint8_t {
    Hash,
    AwaitOk,
    Stream,
    AwaitDone,
};

/** Controller-side LIST progress. */
struct CtrlListState {
    uint16_t received;
};

/** Responder-side LIST cursor and incremental-hash state. */
struct RespListState {
    bool want_crc;
    uint16_t count;
    bool have_entry;
    bool reading;
    uint32_t hashed;
    uint32_t crc;
    rqft_fs_entry_t entry;
};

/** Controller-side GET progress and temp-file staging state. */
struct CtrlGetState {
    uint8_t path[RQFT_MAX_PATH];
    size_t path_len;
    bool retried;
    bool streaming;
    bool writing;
    bool failed;
    rqft_err_code_t fail_code;
    uint32_t size;
    uint32_t received;
    uint32_t crc;
};

/** Responder-side GET stream cursor and staged chunk.
 *
 * The path and the served_pending flag outlive the operation: after
 * FILE_END they identify the most recently served GET until the
 * controller's GET_DONE verdict arrives (SPEC.md section 5.4).
 */
struct RespGetState {
    uint8_t path[RQFT_MAX_PATH];
    size_t path_len;
    bool served_pending;
    uint32_t size;
    uint32_t sent;
    uint32_t crc;
    size_t chunk_len;
    uint8_t chunk[RQFT_MAX_PAYLOAD - 1u];
};

/** Controller-side PUT hash state and upload stream cursor. */
struct CtrlPutState {
    uint8_t path[RQFT_MAX_PATH];
    size_t path_len;
    PutPhase phase;
    bool reading;
    bool failed;
    rqft_err_code_t fail_code;
    bool size_hint_known;
    uint32_t size_hint;
    uint32_t size;
    uint32_t crc;
    uint32_t hashed;
    uint32_t sent;
    size_t chunk_len;
    uint8_t chunk[RQFT_MAX_PAYLOAD - 1u];
};

/** Responder-side PUT verification and temp-file staging state. */
struct RespPutState {
    uint32_t size;
    uint32_t crc32;
    uint32_t received;
    uint32_t crc;
    bool writing;
    bool failed;
    rqft_err_code_t fail_code;
};

/** Controller-side DEL progress: awaiting DEL_OK or ERR. */
struct CtrlDelState {
    uint8_t path[RQFT_MAX_PATH];
    size_t path_len;
    bool is_dir;
};

/** One queued small control message awaiting window space. */
struct CtrlSlot {
    uint8_t payload[kCtrlSlotCap];
    uint8_t len;
};

struct SessionStateImpl {
    rqft_session_config_t config;
    rqft_session_state_t state;
    rqft_frame_parser_t parser;
    rqft_link_t link;
    bool link_ready;
    uint8_t sid;
    uint8_t hello_attempts;
    uint32_t last_hello_tx_ms;
    uint32_t now_ms;
    uint32_t last_tx_ms;
    uint32_t last_rx_ms;
    uint32_t ping_token;
    uint8_t hello_ok_wire[kHelloOkWireCap];
    size_t hello_ok_wire_len;
    rqft_abort_reason_t end_reason;
    uint16_t eff_max_payload;
    CtrlSlot ctrl_queue[kCtrlSlots];
    size_t ctrl_head;
    size_t ctrl_count;
    bool ctrl_overflow;
    OpKind op;
    CtrlListState ctrl_list;
    RespListState resp_list;
    CtrlGetState ctrl_get;
    RespGetState resp_get;
    CtrlPutState ctrl_put;
    RespPutState resp_put;
    CtrlDelState ctrl_del;
};

static_assert(sizeof(SessionStateImpl) <= RQFT_SESSION_STORAGE_SIZE,
              "rqft_session_t storage is too small");
static_assert(alignof(SessionStateImpl) <= alignof(rqft_session_t),
              "rqft_session_t storage is under-aligned");

SessionStateImpl &session_impl(rqft_session_t *session)
{
    return *std::launder(reinterpret_cast<SessionStateImpl *>(&session->storage[0]));
}

const SessionStateImpl &session_impl(const rqft_session_t *session)
{
    return *std::launder(reinterpret_cast<const SessionStateImpl *>(&session->storage[0]));
}

void transmit_frame(SessionStateImpl &impl,
                    rqft_frame_type_t type,
                    uint8_t sid,
                    const uint8_t *payload,
                    size_t payload_len)
{
    uint8_t wire[kMaxWireFrame];
    size_t wire_len = 0u;
    if (rqft_frame_build(type, sid, 0u, 0u, payload, payload_len,
                         wire, sizeof(wire), &wire_len) == RQFT_OK) {
        impl.config.transmit(impl.config.transmit_user, wire, wire_len);
    }
}

void send_abort_frame(SessionStateImpl &impl, uint8_t sid, rqft_abort_reason_t reason)
{
    uint8_t payload = static_cast<uint8_t>(reason);
    transmit_frame(impl, RQFT_FRAME_ABORT, sid, &payload, 1u);
}

void emit_ended(SessionStateImpl &impl, rqft_abort_reason_t reason, bool from_peer)
{
    rqft_session_event_t event{};
    event.type = RQFT_SESSION_EVENT_ENDED;
    event.u.ended.reason = reason;
    event.u.ended.from_peer = from_peer;
    impl.config.on_event(impl.config.event_user, &event);
}

/** Release filesystem resources held by an in-flight operation. */
void release_op(SessionStateImpl &impl)
{
    OpKind op = impl.op;
    impl.op = OpKind::None;
    const rqft_fs_ops_t *fs = impl.config.fs;
    if (fs == nullptr) {
        return;
    }
    if (op == OpKind::RespList) {
        if (impl.resp_list.reading) {
            fs->close_read(impl.config.fs_user);
        }
        fs->list_close(impl.config.fs_user);
    } else if (op == OpKind::RespGet) {
        fs->close_read(impl.config.fs_user);
    } else if (op == OpKind::CtrlGet && impl.ctrl_get.writing) {
        fs->discard(impl.config.fs_user);
    } else if (op == OpKind::CtrlPut && impl.ctrl_put.reading) {
        fs->close_read(impl.config.fs_user);
    } else if (op == OpKind::RespPut && impl.resp_put.writing) {
        fs->discard(impl.config.fs_user);
    }
}

void end_session(SessionStateImpl &impl, rqft_abort_reason_t reason, bool from_peer)
{
    release_op(impl);
    impl.state = RQFT_SESSION_ENDED;
    impl.end_reason = reason;
    rqft_frame_parser_set_session_active(&impl.parser, false);
    emit_ended(impl, reason, from_peer);
}

void abort_session(SessionStateImpl &impl, rqft_abort_reason_t reason)
{
    send_abort_frame(impl, impl.sid, reason);
    end_session(impl, reason, false);
}

/** Send queued control messages until the window fills. */
void drain_ctrl(SessionStateImpl &impl, uint32_t now_ms)
{
    while (impl.ctrl_count > 0u && impl.state == RQFT_SESSION_ACTIVE) {
        const CtrlSlot &slot = impl.ctrl_queue[impl.ctrl_head];
        if (rqft_link_send(&impl.link, slot.payload, slot.len, now_ms) != RQFT_OK) {
            return;
        }
        impl.ctrl_head = (impl.ctrl_head + 1u) % kCtrlSlots;
        impl.ctrl_count--;
    }
}

/** Queue one small control message and drain the queue in order.
 * Overflow marks the session for an E_INTERNAL abort at the next pump. */
void ctrl_send(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    if (impl.ctrl_count >= kCtrlSlots) {
        impl.ctrl_overflow = true;
        return;
    }
    CtrlSlot &slot = impl.ctrl_queue[(impl.ctrl_head + impl.ctrl_count) % kCtrlSlots];
    size_t len = 0u;
    if (rqft_msg_encode(&msg, slot.payload, sizeof(slot.payload), &len) != RQFT_OK) {
        return;
    }
    slot.len = static_cast<uint8_t>(len);
    impl.ctrl_count++;
    drain_ctrl(impl, now_ms);
}

/** Queue an informational ERR best-effort: a full control queue drops
 * it instead of marking overflow, since losing an informative report
 * must never end the session. */
void ctrl_send_info_err(SessionStateImpl &impl,
                        rqft_err_code_t code,
                        uint8_t ref,
                        uint32_t now_ms)
{
    if (impl.ctrl_count >= kCtrlSlots) {
        return;
    }
    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_ERR;
    msg.u.err.code = code;
    msg.u.err.ref_msgtype = ref;
    msg.u.err.detail = 0u;
    ctrl_send(impl, msg, now_ms);
}

void ctrl_send_err(SessionStateImpl &impl, rqft_err_code_t code, uint8_t ref, uint32_t now_ms)
{
    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_ERR;
    msg.u.err.code = code;
    msg.u.err.ref_msgtype = ref;
    msg.u.err.detail = 0u;
    ctrl_send(impl, msg, now_ms);
}

void ctrl_send_pong(SessionStateImpl &impl, uint32_t token, uint32_t now_ms)
{
    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PONG;
    msg.u.token.token = token;
    ctrl_send(impl, msg, now_ms);
}

/** Send one operation message unless queued control traffic or a full
 * window blocks it. */
bool try_send(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    if (impl.state != RQFT_SESSION_ACTIVE) {
        return false;
    }
    drain_ctrl(impl, now_ms);
    if (impl.ctrl_count > 0u) {
        return false;
    }
    uint8_t payload[1u + RQFT_MAX_PAYLOAD];
    size_t len = 0u;
    if (rqft_msg_encode(&msg, payload, sizeof(payload), &len) != RQFT_OK) {
        return false;
    }
    return rqft_link_send(&impl.link, payload, len, now_ms) == RQFT_OK;
}

void responder_on_list_req(SessionStateImpl &impl, const rqft_msg_list_req_t &req, uint32_t now_ms)
{
    if (!rqft_path_valid(req.root, req.root_len, true)) {
        ctrl_send_err(impl, RQFT_E_PATH, RQFT_MSG_LIST_REQ, now_ms);
        return;
    }
    if (impl.config.fs == nullptr) {
        ctrl_send_err(impl, RQFT_E_UNSUPPORTED, RQFT_MSG_LIST_REQ, now_ms);
        return;
    }
    if (!impl.config.fs->list_begin(impl.config.fs_user, req.root, req.root_len)) {
        ctrl_send_err(impl, RQFT_E_FS_OPEN, RQFT_MSG_LIST_REQ, now_ms);
        return;
    }
    impl.op = OpKind::RespList;
    std::memset(&impl.resp_list, 0, sizeof(impl.resp_list));
    impl.resp_list.want_crc = req.want_crc;
}

/** Open the download stream or answer with the failure ERR. */
void responder_on_get_req(SessionStateImpl &impl, const rqft_msg_get_req_t &req, uint32_t now_ms)
{
    const rqft_fs_ops_t *fs = impl.config.fs;
    if (!rqft_path_valid(req.path, req.path_len, false)) {
        ctrl_send_err(impl, RQFT_E_PATH, RQFT_MSG_GET_REQ, now_ms);
        return;
    }
    if (fs == nullptr || fs->open_read == nullptr || fs->read == nullptr ||
        fs->close_read == nullptr) {
        ctrl_send_err(impl, RQFT_E_UNSUPPORTED, RQFT_MSG_GET_REQ, now_ms);
        return;
    }
    if (req.offset != 0u) {
        ctrl_send_err(impl, RQFT_E_UNSUPPORTED, RQFT_MSG_GET_REQ, now_ms);
        return;
    }
    uint32_t size = 0u;
    if (!fs->open_read(impl.config.fs_user, req.path, req.path_len, &size)) {
        ctrl_send_err(impl, RQFT_E_FS_OPEN, RQFT_MSG_GET_REQ, now_ms);
        return;
    }
    impl.op = OpKind::RespGet;
    std::memset(&impl.resp_get, 0, sizeof(impl.resp_get));
    std::memcpy(impl.resp_get.path, req.path, req.path_len);
    impl.resp_get.path_len = req.path_len;
    impl.resp_get.size = size;

    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_FILE_INFO;
    msg.u.file_info.size = size;
    ctrl_send(impl, msg, now_ms);
}

void ctrl_send_put_done(SessionStateImpl &impl, uint8_t status, uint32_t now_ms)
{
    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PUT_DONE;
    msg.u.put_done.status = status;
    ctrl_send(impl, msg, now_ms);
}

/** Discard the staged temporary file if one is open. */
void put_discard(SessionStateImpl &impl)
{
    if (impl.resp_put.writing) {
        impl.config.fs->discard(impl.config.fs_user);
        impl.resp_put.writing = false;
    }
}

/** Open the upload temp file and accept, or answer the failure ERR. */
void responder_on_put_req(SessionStateImpl &impl, const rqft_msg_put_req_t &req, uint32_t now_ms)
{
    const rqft_fs_ops_t *fs = impl.config.fs;
    if (!rqft_path_valid(req.path, req.path_len, false)) {
        ctrl_send_err(impl, RQFT_E_PATH, RQFT_MSG_PUT_REQ, now_ms);
        return;
    }
    if (fs == nullptr || fs->open_write == nullptr || fs->write == nullptr ||
        fs->commit == nullptr || fs->discard == nullptr) {
        ctrl_send_err(impl, RQFT_E_UNSUPPORTED, RQFT_MSG_PUT_REQ, now_ms);
        return;
    }
    if (!fs->open_write(impl.config.fs_user, req.path, req.path_len)) {
        ctrl_send_err(impl, RQFT_E_FS_OPEN, RQFT_MSG_PUT_REQ, now_ms);
        return;
    }
    impl.op = OpKind::RespPut;
    std::memset(&impl.resp_put, 0, sizeof(impl.resp_put));
    impl.resp_put.size = req.size;
    impl.resp_put.crc32 = req.crc32;
    impl.resp_put.writing = true;

    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PUT_OK;
    ctrl_send(impl, msg, now_ms);
}

/** Remove the file or tree and answer DEL_OK, or answer the failure
 * ERR.
 *
 * Deletes are double-gated (SPEC.md section 5.4): this endpoint must
 * have advertised ALLOW_DELETE *and* the host callback must permit the
 * specific path, otherwise E_DENIED.
 */
void responder_on_del(SessionStateImpl &impl, const rqft_msg_del_t &req, bool is_dir,
                      uint32_t now_ms)
{
    const rqft_fs_ops_t *fs = impl.config.fs;
    uint8_t ref = static_cast<uint8_t>(is_dir ? RQFT_MSG_DEL_DIR : RQFT_MSG_DEL_FILE);
    if (!rqft_path_valid(req.path, req.path_len, false)) {
        ctrl_send_err(impl, RQFT_E_PATH, ref, now_ms);
        return;
    }
    if ((impl.config.caps & RQFT_CAP_ALLOW_DELETE) == 0u) {
        ctrl_send_err(impl, RQFT_E_DENIED, ref, now_ms);
        return;
    }
    if (fs == nullptr || fs->remove_file == nullptr || fs->remove_dir == nullptr ||
        fs->allow_delete == nullptr) {
        ctrl_send_err(impl, RQFT_E_UNSUPPORTED, ref, now_ms);
        return;
    }
    if (!fs->allow_delete(impl.config.fs_user, req.path, req.path_len)) {
        ctrl_send_err(impl, RQFT_E_DENIED, ref, now_ms);
        return;
    }
    bool removed = is_dir ? fs->remove_dir(impl.config.fs_user, req.path, req.path_len)
                          : fs->remove_file(impl.config.fs_user, req.path, req.path_len);
    if (!removed) {
        ctrl_send_err(impl, RQFT_E_FS_REMOVE, ref, now_ms);
        return;
    }
    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_DEL_OK;
    ctrl_send(impl, msg, now_ms);
}

/** Stage one chunk; a write error fails the file but keeps consuming
 * the stream so the session survives. */
void resp_on_put_data(SessionStateImpl &impl, const rqft_msg_file_data_t &data)
{
    RespPutState &op = impl.resp_put;
    if (op.failed) {
        return;
    }
    op.received += static_cast<uint32_t>(data.len);
    op.crc = rqft_crc32_update(op.crc, data.data, data.len);
    if (data.len > 0u && !impl.config.fs->write(impl.config.fs_user, data.data, data.len)) {
        impl.config.fs->discard(impl.config.fs_user);
        op.writing = false;
        op.failed = true;
        op.fail_code = RQFT_E_FS_WRITE;
    }
}

/** Close the stream: enforce the PUT_REQ/FILE_END CRC agreement, then
 * verify, commit, and answer PUT_DONE. */
void resp_on_put_end(SessionStateImpl &impl, uint32_t peer_crc, uint32_t now_ms)
{
    RespPutState &op = impl.resp_put;
    if (peer_crc != op.crc32) {
        /* The uploader produced both CRCs; disagreement is a protocol
         * violation, not a transfer error (SPEC.md section 5.4). */
        put_discard(impl);
        abort_session(impl, RQFT_ABORT_E_PROTO);
        return;
    }
    impl.op = OpKind::None;
    if (op.failed) {
        ctrl_send_put_done(impl, static_cast<uint8_t>(op.fail_code), now_ms);
        return;
    }
    if (op.received == op.size && op.crc == peer_crc) {
        op.writing = false;
        if (impl.config.fs->commit(impl.config.fs_user)) {
            ctrl_send_put_done(impl, 0u, now_ms);
        } else {
            ctrl_send_put_done(impl, RQFT_E_FS_WRITE, now_ms);
        }
        return;
    }
    put_discard(impl);
    ctrl_send_put_done(impl, RQFT_E_CRC_FILE, now_ms);
}

/** Handle one message inside the PUT_OK..FILE_END stream.
 *
 * ERR from the uploader fails the operation quietly; anything that is
 * not FILE_DATA, FILE_END, or ERR is fatal (SPEC.md section 5.3).
 */
void resp_on_put_stream(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    if (msg.type == RQFT_MSG_FILE_DATA) {
        resp_on_put_data(impl, msg.u.file_data);
    } else if (msg.type == RQFT_MSG_FILE_END) {
        resp_on_put_end(impl, msg.u.file_end.crc32, now_ms);
    } else if (msg.type == RQFT_MSG_ERR) {
        put_discard(impl);
        impl.op = OpKind::None;
    } else {
        put_discard(impl);
        abort_session(impl, RQFT_ABORT_E_PROTO);
    }
}

void emit_op_failed(SessionStateImpl &impl,
                    uint8_t request,
                    rqft_err_code_t code,
                    uint16_t detail,
                    const uint8_t *path,
                    size_t path_len);

/** Surface the controller's verdict on the last served GET.
 *
 * GET_DONE is informational (SPEC.md section 5.4): status 0 confirms
 * the peer committed the download; any other status surfaces as
 * OP_FAILED. Without a served GET to correlate to, the message is out
 * of place.
 */
void resp_on_get_done(SessionStateImpl &impl, uint8_t status, uint32_t now_ms)
{
    RespGetState &served = impl.resp_get;
    if (!served.served_pending) {
        ctrl_send_err(impl, RQFT_E_BAD_STATE, RQFT_MSG_GET_DONE, now_ms);
        return;
    }
    served.served_pending = false;
    if (status == 0u) {
        rqft_session_event_t event{};
        event.type = RQFT_SESSION_EVENT_GET_SERVED;
        event.u.get_served.path = served.path;
        event.u.get_served.path_len = served.path_len;
        event.u.get_served.size = served.size;
        event.u.get_served.crc32 = served.crc;
        impl.config.on_event(impl.config.event_user, &event);
    } else {
        emit_op_failed(impl, RQFT_MSG_GET_REQ, static_cast<rqft_err_code_t>(status), 0u,
                       served.path, served.path_len);
    }
}

void responder_on_message(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    if (impl.op == OpKind::RespGet) {
        /* No inbound message is valid while the file stream runs
         * (SPEC.md section 5.3), PING included. */
        abort_session(impl, RQFT_ABORT_E_PROTO);
        return;
    }
    if (impl.op == OpKind::RespPut) {
        resp_on_put_stream(impl, msg, now_ms);
        return;
    }
    if (msg.type == RQFT_MSG_PING) {
        ctrl_send_pong(impl, msg.u.token.token, now_ms);
        return;
    }
    if (msg.type == RQFT_MSG_PONG || msg.type == RQFT_MSG_ERR) {
        return;
    }
    if (impl.op == OpKind::RespList) {
        ctrl_send_err(impl, RQFT_E_BAD_STATE, static_cast<uint8_t>(msg.type), now_ms);
        return;
    }

    switch (msg.type) {
    case RQFT_MSG_LIST_REQ:
    case RQFT_MSG_GET_REQ:
    case RQFT_MSG_PUT_REQ:
    case RQFT_MSG_DEL_FILE:
    case RQFT_MSG_DEL_DIR:
        /* A new request supersedes the served-GET record; a conforming
         * controller sends GET_DONE first (SPEC.md section 5.4). */
        impl.resp_get.served_pending = false;
        break;
    default:
        break;
    }

    switch (msg.type) {
    case RQFT_MSG_LIST_REQ:
        responder_on_list_req(impl, msg.u.list_req, now_ms);
        break;
    case RQFT_MSG_GET_REQ:
        responder_on_get_req(impl, msg.u.get_req, now_ms);
        break;
    case RQFT_MSG_PUT_REQ:
        responder_on_put_req(impl, msg.u.put_req, now_ms);
        break;
    case RQFT_MSG_DEL_FILE:
        responder_on_del(impl, msg.u.del_path, false, now_ms);
        break;
    case RQFT_MSG_DEL_DIR:
        responder_on_del(impl, msg.u.del_path, true, now_ms);
        break;
    case RQFT_MSG_GET_DONE:
        resp_on_get_done(impl, msg.u.get_done.status, now_ms);
        break;
    case RQFT_MSG_PLAN: {
        rqft_session_event_t event{};
        event.type = RQFT_SESSION_EVENT_PLAN;
        event.u.plan.nfiles = msg.u.plan.nfiles;
        event.u.plan.nbytes = msg.u.plan.nbytes;
        impl.config.on_event(impl.config.event_user, &event);
        break;
    }
    case RQFT_MSG_UNKNOWN:
        ctrl_send_err(impl, RQFT_E_UNSUPPORTED, msg.u.unknown.msg_type, now_ms);
        break;
    default:
        ctrl_send_err(impl, RQFT_E_BAD_STATE, static_cast<uint8_t>(msg.type), now_ms);
        break;
    }
}

void ctrl_on_list_entry(SessionStateImpl &impl, const rqft_msg_list_entry_t &entry)
{
    impl.ctrl_list.received++;
    if (!rqft_path_valid(entry.path, entry.path_len, false)) {
        return;
    }
    rqft_session_event_t event{};
    event.type = RQFT_SESSION_EVENT_LIST_ENTRY;
    event.u.list_entry.etype = entry.etype;
    event.u.list_entry.has_crc = entry.crc_valid;
    event.u.list_entry.size = entry.size;
    event.u.list_entry.crc32 = entry.crc_valid ? entry.crc32 : 0u;
    event.u.list_entry.mtime = entry.mtime;
    event.u.list_entry.path = entry.path;
    event.u.list_entry.path_len = entry.path_len;
    impl.config.on_event(impl.config.event_user, &event);
}

void emit_op_failed(SessionStateImpl &impl,
                    uint8_t request,
                    rqft_err_code_t code,
                    uint16_t detail,
                    const uint8_t *path,
                    size_t path_len)
{
    rqft_session_event_t event{};
    event.type = RQFT_SESSION_EVENT_OP_FAILED;
    event.u.op_failed.request = request;
    event.u.op_failed.code = code;
    event.u.op_failed.detail = detail;
    event.u.op_failed.path = path;
    event.u.op_failed.path_len = path_len;
    impl.config.on_event(impl.config.event_user, &event);
}

/** Discard the staged temporary file if one is open. */
void ctrl_get_discard(SessionStateImpl &impl)
{
    if (impl.ctrl_get.writing) {
        impl.config.fs->discard(impl.config.fs_user);
        impl.ctrl_get.writing = false;
    }
}

/** Fail the running GET locally: discard the temp, end the operation,
 * and surface OP_FAILED with the file's path. */
void ctrl_get_fail(SessionStateImpl &impl, rqft_err_code_t code, uint16_t detail)
{
    ctrl_get_discard(impl);
    impl.op = OpKind::None;
    emit_op_failed(impl, RQFT_MSG_GET_REQ, code, detail,
                   impl.ctrl_get.path, impl.ctrl_get.path_len);
}

/** Handle one message while GET awaits FILE_INFO. */
void ctrl_on_get_await_info(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    CtrlGetState &op = impl.ctrl_get;
    if (msg.type == RQFT_MSG_FILE_INFO) {
        op.streaming = true;
        op.size = msg.u.file_info.size;
        op.received = 0u;
        op.crc = 0u;
        if (impl.config.fs->open_write(impl.config.fs_user, op.path, op.path_len)) {
            op.writing = true;
        } else {
            op.failed = true;
            op.fail_code = RQFT_E_FS_OPEN;
        }
    } else if (msg.type == RQFT_MSG_ERR) {
        impl.op = OpKind::None;
        emit_op_failed(impl, RQFT_MSG_GET_REQ, msg.u.err.code, msg.u.err.detail,
                       op.path, op.path_len);
    } else {
        ctrl_send_err(impl, RQFT_E_BAD_STATE, static_cast<uint8_t>(msg.type), now_ms);
    }
}

/** Stage one chunk; a write error fails the file but keeps consuming
 * the stream so the session survives. */
void ctrl_on_file_data(SessionStateImpl &impl, const rqft_msg_file_data_t &data)
{
    CtrlGetState &op = impl.ctrl_get;
    if (op.failed) {
        return;
    }
    op.received += static_cast<uint32_t>(data.len);
    op.crc = rqft_crc32_update(op.crc, data.data, data.len);
    if (data.len > 0u && !impl.config.fs->write(impl.config.fs_user, data.data, data.len)) {
        impl.config.fs->discard(impl.config.fs_user);
        op.writing = false;
        op.failed = true;
        op.fail_code = RQFT_E_FS_WRITE;
    }
}

/** Answer the responder with the GET verification verdict. */
void ctrl_send_get_done(SessionStateImpl &impl, uint8_t status, uint32_t now_ms)
{
    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_GET_DONE;
    msg.u.get_done.status = status;
    ctrl_send(impl, msg, now_ms);
}

/** Verify the finished stream: commit, retry once, or fail.
 *
 * Every FILE_END processed answers with exactly one GET_DONE (SPEC.md
 * section 5.4), queued ahead of any retry GET_REQ.
 */
void ctrl_on_file_end(SessionStateImpl &impl, uint32_t peer_crc, uint32_t now_ms)
{
    CtrlGetState &op = impl.ctrl_get;
    if (op.failed) {
        impl.op = OpKind::None;
        ctrl_send_get_done(impl, static_cast<uint8_t>(op.fail_code), now_ms);
        emit_op_failed(impl, RQFT_MSG_GET_REQ, op.fail_code, 0u, op.path, op.path_len);
        return;
    }
    if (op.received == op.size && op.crc == peer_crc) {
        op.writing = false;
        impl.op = OpKind::None;
        if (impl.config.fs->commit(impl.config.fs_user)) {
            ctrl_send_get_done(impl, 0u, now_ms);
            rqft_session_event_t event{};
            event.type = RQFT_SESSION_EVENT_GET_DONE;
            event.u.get_done.path = op.path;
            event.u.get_done.path_len = op.path_len;
            event.u.get_done.size = op.size;
            event.u.get_done.crc32 = op.crc;
            impl.config.on_event(impl.config.event_user, &event);
        } else {
            ctrl_send_get_done(impl, RQFT_E_FS_WRITE, now_ms);
            emit_op_failed(impl, RQFT_MSG_GET_REQ, RQFT_E_FS_WRITE, 0u, op.path, op.path_len);
        }
        return;
    }
    ctrl_get_discard(impl);
    ctrl_send_get_done(impl, RQFT_E_CRC_FILE, now_ms);
    if (op.retried) {
        impl.op = OpKind::None;
        emit_op_failed(impl, RQFT_MSG_GET_REQ, RQFT_E_CRC_FILE, 0u, op.path, op.path_len);
        return;
    }
    op.retried = true;
    op.streaming = false;
    op.failed = false;
    op.size = 0u;
    op.received = 0u;
    op.crc = 0u;

    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_GET_REQ;
    msg.u.get_req.offset = 0u;
    msg.u.get_req.path = op.path;
    msg.u.get_req.path_len = op.path_len;
    ctrl_send(impl, msg, now_ms);
}

/** Handle one message inside the FILE_INFO..FILE_END stream.
 *
 * ERR fails the file and ends the operation; anything that is not
 * FILE_DATA, FILE_END, or ERR is fatal (SPEC.md section 5.3).
 */
void ctrl_on_get_stream(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    if (msg.type == RQFT_MSG_FILE_DATA) {
        ctrl_on_file_data(impl, msg.u.file_data);
    } else if (msg.type == RQFT_MSG_FILE_END) {
        ctrl_on_file_end(impl, msg.u.file_end.crc32, now_ms);
    } else if (msg.type == RQFT_MSG_ERR) {
        ctrl_get_fail(impl, msg.u.err.code, msg.u.err.detail);
    } else {
        ctrl_get_discard(impl);
        abort_session(impl, RQFT_ABORT_E_PROTO);
    }
}

/** Handle one message while PUT hashes or awaits PUT_OK/PUT_DONE. */
void ctrl_on_put_reply(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    CtrlPutState &op = impl.ctrl_put;
    if (msg.type == RQFT_MSG_PUT_OK && op.phase == PutPhase::AwaitOk) {
        uint32_t size = 0u;
        if (!impl.config.fs->open_read(impl.config.fs_user, op.path, op.path_len, &size)) {
            impl.op = OpKind::None;
            ctrl_send_err(impl, RQFT_E_FS_OPEN, RQFT_MSG_PUT_REQ, now_ms);
            emit_op_failed(impl, RQFT_MSG_PUT_REQ, RQFT_E_FS_OPEN, 0u, op.path, op.path_len);
            return;
        }
        op.reading = true;
        op.phase = PutPhase::Stream;
        return;
    }
    if (msg.type == RQFT_MSG_PUT_DONE && op.phase == PutPhase::AwaitDone) {
        impl.op = OpKind::None;
        if (msg.u.put_done.status == 0u) {
            rqft_session_event_t event{};
            event.type = RQFT_SESSION_EVENT_PUT_DONE;
            event.u.put_done.path = op.path;
            event.u.put_done.path_len = op.path_len;
            event.u.put_done.size = op.size;
            event.u.put_done.crc32 = op.crc;
            impl.config.on_event(impl.config.event_user, &event);
        } else {
            emit_op_failed(impl, RQFT_MSG_PUT_REQ,
                           static_cast<rqft_err_code_t>(msg.u.put_done.status), 0u,
                           op.path, op.path_len);
        }
        return;
    }
    if (msg.type == RQFT_MSG_ERR) {
        if (op.phase == PutPhase::Hash) {
            /* Nothing has been requested yet; the ERR is stray. */
            return;
        }
        impl.op = OpKind::None;
        emit_op_failed(impl, RQFT_MSG_PUT_REQ, msg.u.err.code, msg.u.err.detail,
                       op.path, op.path_len);
        return;
    }
    ctrl_send_err(impl, RQFT_E_BAD_STATE, static_cast<uint8_t>(msg.type), now_ms);
}

/** Handle one message while DEL awaits DEL_OK. */
void ctrl_on_del_reply(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    CtrlDelState &op = impl.ctrl_del;
    uint8_t request = static_cast<uint8_t>(op.is_dir ? RQFT_MSG_DEL_DIR : RQFT_MSG_DEL_FILE);
    if (msg.type == RQFT_MSG_DEL_OK) {
        impl.op = OpKind::None;
        rqft_session_event_t event{};
        event.type = RQFT_SESSION_EVENT_DEL_DONE;
        event.u.del_done.path = op.path;
        event.u.del_done.path_len = op.path_len;
        event.u.del_done.is_dir = op.is_dir;
        impl.config.on_event(impl.config.event_user, &event);
        return;
    }
    if (msg.type == RQFT_MSG_ERR) {
        impl.op = OpKind::None;
        emit_op_failed(impl, request, msg.u.err.code, msg.u.err.detail,
                       op.path, op.path_len);
        return;
    }
    ctrl_send_err(impl, RQFT_E_BAD_STATE, static_cast<uint8_t>(msg.type), now_ms);
}

void controller_on_message(SessionStateImpl &impl, const rqft_msg_t &msg, uint32_t now_ms)
{
    if (impl.op == OpKind::CtrlGet && impl.ctrl_get.streaming) {
        ctrl_on_get_stream(impl, msg, now_ms);
        return;
    }
    if (impl.op == OpKind::CtrlPut && impl.ctrl_put.phase == PutPhase::Stream) {
        /* No inbound message is valid while our upload stream runs
         * (SPEC.md section 5.3), PING included. */
        abort_session(impl, RQFT_ABORT_E_PROTO);
        return;
    }
    if (msg.type == RQFT_MSG_PING) {
        ctrl_send_pong(impl, msg.u.token.token, now_ms);
        return;
    }
    if (msg.type == RQFT_MSG_PONG) {
        return;
    }
    if (msg.type == RQFT_MSG_NOTIFY) {
        /* Legal at any between-message point, like PONG (SPEC.md section
         * 5.4): the responder may queue it while our request is in flight. */
        rqft_session_event_t event{};
        event.type = RQFT_SESSION_EVENT_NOTIFY;
        event.u.notify.flags = msg.u.notify.flags;
        impl.config.on_event(impl.config.event_user, &event);
        return;
    }
    if (impl.op == OpKind::CtrlGet) {
        ctrl_on_get_await_info(impl, msg, now_ms);
        return;
    }
    if (impl.op == OpKind::CtrlPut) {
        ctrl_on_put_reply(impl, msg, now_ms);
        return;
    }
    if (impl.op == OpKind::CtrlDel) {
        ctrl_on_del_reply(impl, msg, now_ms);
        return;
    }

    if (impl.op == OpKind::CtrlList) {
        if (msg.type == RQFT_MSG_LIST_ENTRY) {
            ctrl_on_list_entry(impl, msg.u.list_entry);
        } else if (msg.type == RQFT_MSG_LIST_END) {
            uint16_t received = impl.ctrl_list.received;
            impl.op = OpKind::None;
            if (msg.u.list_end.count != received) {
                abort_session(impl, RQFT_ABORT_E_PROTO);
                return;
            }
            rqft_session_event_t event{};
            event.type = RQFT_SESSION_EVENT_LIST_DONE;
            event.u.list_done.count = received;
            impl.config.on_event(impl.config.event_user, &event);
        } else if (msg.type == RQFT_MSG_ERR) {
            if (msg.u.err.code == RQFT_E_FS_READ) {
                /* Informational skip report (SPEC.md section 5.4): the
                 * responder could not read one file; the listing lives. */
                rqft_session_event_t event{};
                event.type = RQFT_SESSION_EVENT_LIST_SKIP;
                event.u.list_skip.code = msg.u.err.code;
                event.u.list_skip.detail = msg.u.err.detail;
                impl.config.on_event(impl.config.event_user, &event);
            } else {
                impl.op = OpKind::None;
                emit_op_failed(impl, RQFT_MSG_LIST_REQ, msg.u.err.code, msg.u.err.detail,
                               nullptr, 0u);
            }
        } else {
            ctrl_send_err(impl, RQFT_E_BAD_STATE, static_cast<uint8_t>(msg.type), now_ms);
        }
        return;
    }

    if (msg.type == RQFT_MSG_ERR) {
        return;
    }
    if (msg.type == RQFT_MSG_UNKNOWN) {
        ctrl_send_err(impl, RQFT_E_UNSUPPORTED, msg.u.unknown.msg_type, now_ms);
    } else {
        ctrl_send_err(impl, RQFT_E_BAD_STATE, static_cast<uint8_t>(msg.type), now_ms);
    }
}

void on_message(SessionStateImpl &impl, const uint8_t *payload, size_t payload_len)
{
    rqft_msg_t msg;
    if (rqft_msg_decode(payload, payload_len, &msg) != RQFT_OK) {
        abort_session(impl, RQFT_ABORT_E_PROTO);
        return;
    }
    if (impl.config.role == RQFT_ROLE_RESPONDER) {
        responder_on_message(impl, msg, impl.now_ms);
    } else {
        controller_on_message(impl, msg, impl.now_ms);
    }
}

void link_event_thunk(void *user, const rqft_link_event_t *event)
{
    SessionStateImpl &impl = *static_cast<SessionStateImpl *>(user);
    if (event->type == RQFT_LINK_EVENT_ABORT) {
        end_session(impl, event->reason, event->from_peer);
    } else {
        on_message(impl, event->payload, event->payload_len);
    }
}

/** Link transmit sink; every link frame counts as keepalive traffic. */
void link_transmit_thunk(void *user, const uint8_t *wire, size_t wire_len)
{
    SessionStateImpl &impl = *static_cast<SessionStateImpl *>(user);
    impl.last_tx_ms = impl.now_ms;
    impl.config.transmit(impl.config.transmit_user, wire, wire_len);
}

/** Pull the next listable entry into the staged slot.
 *
 * Entries with invalid or over-long paths are skipped silently; files
 * the provider cannot open while hashing are skipped with a
 * best-effort informational ERR(E_FS_READ) (SPEC.md section 5.4).
 * Returns false when the listing ended (LIST_END queued).
 */
bool resp_list_advance(SessionStateImpl &impl, uint32_t now_ms)
{
    RespListState &op = impl.resp_list;
    const rqft_fs_ops_t *fs = impl.config.fs;
    while (true) {
        if (fs->list_next(impl.config.fs_user, &op.entry) != 1) {
            fs->list_close(impl.config.fs_user);
            impl.op = OpKind::None;
            rqft_msg_t msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.type = RQFT_MSG_LIST_END;
            msg.u.list_end.count = op.count;
            ctrl_send(impl, msg, now_ms);
            return false;
        }
        if (!rqft_path_valid(op.entry.path, op.entry.path_len, false)) {
            continue;
        }
        if (kListEntryOverhead + op.entry.path_len > impl.eff_max_payload) {
            continue;
        }
        op.have_entry = true;
        op.reading = false;
        op.hashed = 0u;
        op.crc = 0u;
        if (op.want_crc && op.entry.etype == 0u) {
            uint32_t size = 0u;
            if (!fs->open_read(impl.config.fs_user, op.entry.path, op.entry.path_len, &size)) {
                op.have_entry = false;
                ctrl_send_info_err(impl, RQFT_E_FS_READ, RQFT_MSG_LIST_REQ, now_ms);
                continue;
            }
            op.reading = true;
        }
        return true;
    }
}

/** Hash the staged file within budget; returns the budget left.
 *
 * A read error skips the entry with a best-effort informational
 * ERR(E_FS_READ) (SPEC.md section 5.4: files the responder cannot
 * read are skipped); the hashed byte count replaces the listed size
 * so size and CRC always agree.
 */
size_t resp_list_hash(SessionStateImpl &impl, uint32_t now_ms, size_t budget)
{
    RespListState &op = impl.resp_list;
    const rqft_fs_ops_t *fs = impl.config.fs;
    uint8_t buf[kHashReadMax];
    while (budget > 0u) {
        size_t cap = budget < kHashReadMax ? budget : kHashReadMax;
        int got = fs->read(impl.config.fs_user, buf, cap);
        if (got < 0) {
            fs->close_read(impl.config.fs_user);
            op.reading = false;
            op.have_entry = false;
            ctrl_send_info_err(impl, RQFT_E_FS_READ, RQFT_MSG_LIST_REQ, now_ms);
            return budget;
        }
        if (got == 0) {
            fs->close_read(impl.config.fs_user);
            op.reading = false;
            return budget;
        }
        op.crc = rqft_crc32_update(op.crc, buf, static_cast<size_t>(got));
        op.hashed += static_cast<uint32_t>(got);
        budget -= static_cast<size_t>(got);
    }
    return 0u;
}

/** Advance the responder listing: hash within budget, send entries
 * while the window has room, and finish with LIST_END. */
void pump_resp_list(SessionStateImpl &impl, uint32_t now_ms, size_t budget)
{
    RespListState &op = impl.resp_list;
    for (unsigned step = 0u; step < kPumpMaxSteps; step++) {
        if (!op.have_entry && !resp_list_advance(impl, now_ms)) {
            return;
        }
        if (op.reading) {
            budget = resp_list_hash(impl, now_ms, budget);
            if (op.reading) {
                return;
            }
            if (!op.have_entry) {
                continue;
            }
        }
        rqft_msg_t msg;
        std::memset(&msg, 0, sizeof(msg));
        msg.type = RQFT_MSG_LIST_ENTRY;
        msg.u.list_entry.etype = op.entry.etype;
        msg.u.list_entry.path = op.entry.path;
        msg.u.list_entry.path_len = op.entry.path_len;
        msg.u.list_entry.mtime = op.entry.mtime;
        if (op.want_crc && op.entry.etype == 0u) {
            msg.u.list_entry.crc_valid = true;
            msg.u.list_entry.size = op.hashed;
            msg.u.list_entry.crc32 = op.crc;
        } else {
            msg.u.list_entry.crc_valid = false;
            msg.u.list_entry.size = op.entry.size;
            msg.u.list_entry.crc32 = 0u;
        }
        if (!try_send(impl, msg, now_ms)) {
            return;
        }
        op.count++;
        op.have_entry = false;
    }
}

/** Advance the download stream: read full chunks within budget, send
 * them while the window has room, and finish with FILE_END.
 *
 * A read error or early end of file breaks the promised byte count,
 * so the stream ends with ERR(E_FS_READ) instead.
 */
void pump_resp_get(SessionStateImpl &impl, uint32_t now_ms, size_t budget)
{
    RespGetState &op = impl.resp_get;
    const rqft_fs_ops_t *fs = impl.config.fs;
    size_t chunk_size = static_cast<size_t>(impl.eff_max_payload) - 1u;
    for (unsigned step = 0u; step < kPumpMaxSteps; step++) {
        size_t remaining = op.size - op.sent;
        size_t target = chunk_size < remaining ? chunk_size : remaining;
        if (target > 0u && op.chunk_len == target) {
            rqft_msg_t msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.type = RQFT_MSG_FILE_DATA;
            msg.u.file_data.data = op.chunk;
            msg.u.file_data.len = op.chunk_len;
            if (!try_send(impl, msg, now_ms)) {
                return;
            }
            op.sent += static_cast<uint32_t>(op.chunk_len);
            op.chunk_len = 0u;
            continue;
        }
        if (op.sent == op.size) {
            fs->close_read(impl.config.fs_user);
            impl.op = OpKind::None;
            op.served_pending = true;
            rqft_msg_t msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.type = RQFT_MSG_FILE_END;
            msg.u.file_end.crc32 = op.crc;
            ctrl_send(impl, msg, now_ms);
            return;
        }
        if (budget == 0u) {
            return;
        }
        size_t want = target - op.chunk_len;
        if (want > budget) {
            want = budget;
        }
        int got = fs->read(impl.config.fs_user, op.chunk + op.chunk_len, want);
        if (got <= 0) {
            fs->close_read(impl.config.fs_user);
            impl.op = OpKind::None;
            ctrl_send_err(impl, RQFT_E_FS_READ, RQFT_MSG_GET_REQ, now_ms);
            return;
        }
        op.crc = rqft_crc32_update(op.crc, op.chunk + op.chunk_len, static_cast<size_t>(got));
        op.chunk_len += static_cast<size_t>(got);
        budget -= static_cast<size_t>(got);
    }
}

/** Hash the staged upload within budget; the hashed byte count becomes
 * PUT_REQ.size so size and CRC always agree.
 *
 * A read error fails the file before anything reaches the wire.
 */
void put_hash(SessionStateImpl &impl, uint32_t now_ms, size_t budget)
{
    CtrlPutState &op = impl.ctrl_put;
    const rqft_fs_ops_t *fs = impl.config.fs;
    uint8_t buf[kHashReadMax];
    while (budget > 0u) {
        size_t cap = budget < kHashReadMax ? budget : kHashReadMax;
        int got = fs->read(impl.config.fs_user, buf, cap);
        if (got < 0) {
            fs->close_read(impl.config.fs_user);
            op.reading = false;
            impl.op = OpKind::None;
            emit_op_failed(impl, RQFT_MSG_PUT_REQ, RQFT_E_FS_READ, 0u,
                           op.path, op.path_len);
            return;
        }
        if (got == 0) {
            fs->close_read(impl.config.fs_user);
            op.reading = false;
            op.size = op.hashed;
            op.phase = PutPhase::AwaitOk;
            rqft_msg_t msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.type = RQFT_MSG_PUT_REQ;
            msg.u.put_req.size = op.size;
            msg.u.put_req.crc32 = op.crc;
            msg.u.put_req.path = op.path;
            msg.u.put_req.path_len = op.path_len;
            ctrl_send(impl, msg, now_ms);
            return;
        }
        op.crc = rqft_crc32_update(op.crc, buf, static_cast<size_t>(got));
        op.hashed += static_cast<uint32_t>(got);
        budget -= static_cast<size_t>(got);
    }
}

/** Advance the upload stream: read full chunks within budget, send
 * them while the window has room, and finish with FILE_END carrying
 * the PUT_REQ CRC.
 *
 * A read error or early end of file breaks the promised byte count,
 * so the stream ends with ERR(E_FS_READ) and the file fails locally.
 */
void pump_put_stream(SessionStateImpl &impl, uint32_t now_ms, size_t budget)
{
    CtrlPutState &op = impl.ctrl_put;
    const rqft_fs_ops_t *fs = impl.config.fs;
    size_t chunk_size = static_cast<size_t>(impl.eff_max_payload) - 1u;
    for (unsigned step = 0u; step < kPumpMaxSteps; step++) {
        size_t remaining = op.size - op.sent;
        size_t target = chunk_size < remaining ? chunk_size : remaining;
        if (target > 0u && op.chunk_len == target) {
            rqft_msg_t msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.type = RQFT_MSG_FILE_DATA;
            msg.u.file_data.data = op.chunk;
            msg.u.file_data.len = op.chunk_len;
            if (!try_send(impl, msg, now_ms)) {
                return;
            }
            op.sent += static_cast<uint32_t>(op.chunk_len);
            op.chunk_len = 0u;
            continue;
        }
        if (op.sent == op.size) {
            fs->close_read(impl.config.fs_user);
            op.reading = false;
            op.phase = PutPhase::AwaitDone;
            rqft_msg_t msg;
            std::memset(&msg, 0, sizeof(msg));
            msg.type = RQFT_MSG_FILE_END;
            msg.u.file_end.crc32 = op.crc;
            ctrl_send(impl, msg, now_ms);
            return;
        }
        if (budget == 0u) {
            return;
        }
        size_t want = target - op.chunk_len;
        if (want > budget) {
            want = budget;
        }
        int got = fs->read(impl.config.fs_user, op.chunk + op.chunk_len, want);
        if (got <= 0) {
            fs->close_read(impl.config.fs_user);
            op.reading = false;
            impl.op = OpKind::None;
            ctrl_send_err(impl, RQFT_E_FS_READ, RQFT_MSG_PUT_REQ, now_ms);
            emit_op_failed(impl, RQFT_MSG_PUT_REQ, RQFT_E_FS_READ, 0u,
                           op.path, op.path_len);
            return;
        }
        op.chunk_len += static_cast<size_t>(got);
        budget -= static_cast<size_t>(got);
    }
}

/** Advance the upload: surface a staged open failure, hash within
 * budget toward PUT_REQ, or stream chunks while the window has room. */
void pump_ctrl_put(SessionStateImpl &impl, uint32_t now_ms, size_t budget)
{
    CtrlPutState &op = impl.ctrl_put;
    if (op.failed) {
        impl.op = OpKind::None;
        emit_op_failed(impl, RQFT_MSG_PUT_REQ, op.fail_code, 0u, op.path, op.path_len);
        return;
    }
    if (op.phase == PutPhase::Hash) {
        put_hash(impl, now_ms, budget);
    } else if (op.phase == PutPhase::Stream) {
        pump_put_stream(impl, now_ms, budget);
    }
}

/** Run queued sends and one bounded slice of operation work. */
void pump(SessionStateImpl &impl, uint32_t now_ms)
{
    if (impl.state != RQFT_SESSION_ACTIVE) {
        return;
    }
    if (impl.ctrl_overflow) {
        abort_session(impl, RQFT_ABORT_E_INTERNAL);
        return;
    }
    drain_ctrl(impl, now_ms);
    if (impl.op == OpKind::RespList) {
        pump_resp_list(impl, now_ms, RQFT_CRC_BUDGET_PER_POLL);
    } else if (impl.op == OpKind::RespGet) {
        pump_resp_get(impl, now_ms, RQFT_CRC_BUDGET_PER_POLL);
    } else if (impl.op == OpKind::CtrlPut) {
        pump_ctrl_put(impl, now_ms, RQFT_CRC_BUDGET_PER_POLL);
    }
}

void transmit_hello(SessionStateImpl &impl, uint32_t now_ms)
{
    rqft_hello_t hello;
    uint8_t body[RQFT_HELLO_BODY_LEN];
    hello.ver_min = impl.config.ver_min;
    hello.ver_max = impl.config.ver_max;
    hello.role = impl.config.role;
    hello.max_payload = impl.config.max_payload;
    hello.window = impl.config.window;
    hello.caps = impl.config.caps;
    if (rqft_hello_encode(&hello, body) == RQFT_OK) {
        transmit_frame(impl, RQFT_FRAME_HELLO, impl.sid, body, sizeof(body));
    }
    impl.last_hello_tx_ms = now_ms;
    impl.hello_attempts++;
}

void activate(SessionStateImpl &impl,
              uint8_t sid,
              uint8_t version,
              uint16_t peer_max_payload,
              uint8_t peer_window,
              uint8_t peer_caps)
{
    uint16_t max_payload = impl.config.max_payload < peer_max_payload
                               ? impl.config.max_payload
                               : peer_max_payload;
    uint8_t window = impl.config.window < peer_window ? impl.config.window : peer_window;

    rqft_link_config_t link_config;
    std::memset(&link_config, 0, sizeof(link_config));
    link_config.sid = sid;
    link_config.window = window;
    link_config.max_payload = max_payload;
    link_config.transmit = link_transmit_thunk;
    link_config.transmit_user = &impl;
    link_config.on_event = link_event_thunk;
    link_config.event_user = &impl;
    if (rqft_link_init(&impl.link, &link_config) != RQFT_OK) {
        end_session(impl, RQFT_ABORT_E_INTERNAL, false);
        return;
    }
    impl.link_ready = true;

    impl.sid = sid;
    rqft_frame_parser_set_max_payload(&impl.parser, max_payload);
    rqft_frame_parser_set_session_active(&impl.parser, true);
    impl.eff_max_payload = max_payload;
    impl.last_tx_ms = impl.now_ms;
    impl.last_rx_ms = impl.now_ms;
    impl.state = RQFT_SESSION_ACTIVE;

    rqft_session_event_t event{};
    event.type = RQFT_SESSION_EVENT_ESTABLISHED;
    event.u.established.sid = sid;
    event.u.established.version = version;
    event.u.established.role = impl.config.role;
    event.u.established.max_payload = max_payload;
    event.u.established.window = window;
    event.u.established.peer_caps = peer_caps;
    impl.config.on_event(impl.config.event_user, &event);
}

/**
 * Negotiate and answer a decoded HELLO as the replier.
 *
 * Returns true on success; on rejection returns false with the ABORT
 * reason sent back in *rejection, leaving this endpoint idle.
 */
bool answer_hello(SessionStateImpl &impl,
                  uint8_t sid,
                  const rqft_hello_t &hello,
                  rqft_abort_reason_t *rejection)
{
    uint8_t version = impl.config.ver_max < hello.ver_max ? impl.config.ver_max : hello.ver_max;
    uint8_t floor = impl.config.ver_min > hello.ver_min ? impl.config.ver_min : hello.ver_min;
    if (version < floor) {
        send_abort_frame(impl, sid, RQFT_ABORT_E_VERSION);
        *rejection = RQFT_ABORT_E_VERSION;
        return false;
    }
    if (hello.role == impl.config.role) {
        send_abort_frame(impl, sid, RQFT_ABORT_E_PROTO);
        *rejection = RQFT_ABORT_E_PROTO;
        return false;
    }

    rqft_hello_ok_t ok;
    uint8_t body[RQFT_HELLO_BODY_LEN];
    ok.ver = version;
    ok.role = impl.config.role;
    ok.max_payload = impl.config.max_payload;
    ok.window = impl.config.window;
    ok.caps = impl.config.caps;
    impl.hello_ok_wire_len = 0u;
    if (rqft_hello_ok_encode(&ok, body) == RQFT_OK) {
        size_t wire_len = 0u;
        if (rqft_frame_build(RQFT_FRAME_HELLO_OK, sid, 0u, 0u, body, sizeof(body),
                             impl.hello_ok_wire, sizeof(impl.hello_ok_wire),
                             &wire_len) == RQFT_OK) {
            impl.hello_ok_wire_len = wire_len;
            impl.config.transmit(impl.config.transmit_user, impl.hello_ok_wire, wire_len);
        }
    }

    activate(impl, sid, version, hello.max_payload, hello.window, hello.caps);
    return true;
}

void replier_on_hello(SessionStateImpl &impl, const rqft_frame_t *frame)
{
    rqft_hello_t hello;
    rqft_abort_reason_t rejection;
    if (rqft_hello_decode(frame->payload, frame->payload_len, &hello) != RQFT_OK) {
        return;
    }
    (void)answer_hello(impl, frame->sid, hello, &rejection);
}

void initiator_on_hello_ok(SessionStateImpl &impl, const rqft_frame_t *frame)
{
    rqft_hello_ok_t ok;
    if (rqft_hello_ok_decode(frame->payload, frame->payload_len, &ok) != RQFT_OK) {
        return;
    }
    if (ok.ver < impl.config.ver_min || ok.ver > impl.config.ver_max) {
        send_abort_frame(impl, impl.sid, RQFT_ABORT_E_VERSION);
        end_session(impl, RQFT_ABORT_E_VERSION, false);
        return;
    }
    if (ok.role == impl.config.role) {
        send_abort_frame(impl, impl.sid, RQFT_ABORT_E_PROTO);
        end_session(impl, RQFT_ABORT_E_PROTO, false);
        return;
    }

    /* The handshake round trip does not seed the RTO estimator (SPEC 4.4).
     * It is measured on an unloaded link, so it undershoots the RTT of a
     * full in-flight window and primes spurious full-window retransmissions
     * that Karn's rule then sustains. Start from RQFT_RTO_INITIAL_MS and let
     * data-frame ACKs train the estimator. */
    activate(impl, impl.sid, ok.ver, ok.max_payload, ok.window, ok.caps);
}

void initiator_on_collision(SessionStateImpl &impl, const rqft_frame_t *frame, uint32_t now_ms)
{
    if (frame->sid > impl.sid) {
        return;
    }
    if (frame->sid == impl.sid) {
        uint8_t sid = impl.config.next_sid(impl.config.sid_user);
        if (sid == 0u) {
            end_session(impl, RQFT_ABORT_E_INTERNAL, false);
            return;
        }
        impl.sid = sid;
        impl.hello_attempts = 0u;
        impl.last_hello_tx_ms = now_ms;
        return;
    }

    rqft_hello_t hello;
    rqft_abort_reason_t rejection;
    if (rqft_hello_decode(frame->payload, frame->payload_len, &hello) != RQFT_OK) {
        return;
    }
    impl.state = RQFT_SESSION_IDLE;
    if (!answer_hello(impl, frame->sid, hello, &rejection)) {
        end_session(impl, rejection, false);
    }
}

void handshake_on_frame(SessionStateImpl &impl, const rqft_frame_t *frame, uint32_t now_ms)
{
    if (frame->type == RQFT_FRAME_HELLO_OK && frame->sid == impl.sid) {
        initiator_on_hello_ok(impl, frame);
    } else if (frame->type == RQFT_FRAME_HELLO) {
        initiator_on_collision(impl, frame, now_ms);
    } else if (frame->type == RQFT_FRAME_ABORT && frame->sid == impl.sid) {
        end_session(impl, rqft_abort_reason_from_byte(frame->payload[0]), true);
    }
}

void active_on_frame(SessionStateImpl &impl, const rqft_frame_t *frame, uint32_t now_ms)
{
    if (frame->sid == impl.sid) {
        impl.last_rx_ms = now_ms;
    }
    if (frame->type == RQFT_FRAME_HELLO) {
        if (frame->sid == impl.sid) {
            if (impl.hello_ok_wire_len > 0u) {
                impl.last_tx_ms = now_ms;
                impl.config.transmit(impl.config.transmit_user,
                                     impl.hello_ok_wire, impl.hello_ok_wire_len);
            }
        } else {
            send_abort_frame(impl, frame->sid, RQFT_ABORT_E_BUSY);
        }
    } else if (frame->type == RQFT_FRAME_HELLO_OK) {
        return;
    } else if (impl.link_ready) {
        rqft_link_on_frame(&impl.link, frame, now_ms);
    }
}

void on_frame(SessionStateImpl &impl, const rqft_frame_t *frame, uint32_t now_ms)
{
    switch (impl.state) {
    case RQFT_SESSION_IDLE:
        if (frame->type == RQFT_FRAME_HELLO) {
            replier_on_hello(impl, frame);
        }
        break;
    case RQFT_SESSION_HELLO_SENT:
        handshake_on_frame(impl, frame, now_ms);
        break;
    case RQFT_SESSION_ACTIVE:
        active_on_frame(impl, frame, now_ms);
        break;
    case RQFT_SESSION_ENDED:
        break;
    }
}

void parser_event_thunk(void *user, const rqft_frame_event_t *event)
{
    SessionStateImpl &impl = *static_cast<SessionStateImpl *>(user);
    if (event->type == RQFT_FRAME_EVENT_PASSTHROUGH) {
        rqft_session_event_t out{};
        out.type = RQFT_SESSION_EVENT_PASSTHROUGH;
        out.u.passthrough.data = event->passthrough;
        out.u.passthrough.len = event->passthrough_len;
        impl.config.on_event(impl.config.event_user, &out);
        return;
    }
    on_frame(impl, &event->frame, impl.now_ms);
}

/** Whether the controller keepalive may send PING now (SPEC.md section
 * 4.5).
 *
 * A PING that reaches the peer inside a file stream is an E_PROTO
 * violation (SPEC.md section 5.3), so it is held back from GET_REQ until
 * the GET ends, and from PUT_REQ until our FILE_END. At every other
 * point it runs, including while a LIST or DEL awaits its reply and
 * while a PUT source is hashed: those can outlast T_DEAD on a large
 * file with nothing else on the wire.
 */
bool keepalive_allowed(const SessionStateImpl &impl)
{
    if (impl.config.role != RQFT_ROLE_CONTROLLER) {
        return false;
    }
    if (impl.op == OpKind::CtrlGet) {
        return false;
    }
    if (impl.op == OpKind::CtrlPut) {
        return impl.ctrl_put.phase == PutPhase::Hash ||
               impl.ctrl_put.phase == PutPhase::AwaitDone;
    }
    return true;
}

/** Run the keepalive and idle-death timers (SPEC.md section 4.5).
 *
 * T_DEAD without any valid in-session frame ends the session with a
 * best-effort ABORT(E_TIMEOUT). Otherwise the controller sends a PING
 * after T_PING of outbound silence whenever keepalive_allowed() says no
 * file stream can be open.
 */
void run_keepalive(SessionStateImpl &impl, uint32_t now_ms)
{
    if (now_ms - impl.last_rx_ms >= RQFT_T_DEAD_MS) {
        abort_session(impl, RQFT_ABORT_E_TIMEOUT);
        return;
    }
    if (!keepalive_allowed(impl) || now_ms - impl.last_tx_ms < RQFT_T_PING_MS) {
        return;
    }
    impl.ping_token++;
    impl.last_tx_ms = now_ms;
    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PING;
    msg.u.token.token = impl.ping_token;
    ctrl_send(impl, msg, now_ms);
}

void retry_hello(SessionStateImpl &impl, uint32_t now_ms)
{
    if (impl.hello_attempts >= RQFT_N_HELLO) {
        impl.state = RQFT_SESSION_ENDED;
        impl.end_reason = RQFT_ABORT_E_TIMEOUT;
        emit_ended(impl, RQFT_ABORT_E_TIMEOUT, false);
        return;
    }
    transmit_hello(impl, now_ms);
}

} // namespace

void rqft_session_config_init(rqft_session_config_t *config, rqft_role_t role)
{
    std::memset(config, 0, sizeof(*config));
    config->role = role;
    config->ver_min = RQFT_PROTOCOL_VERSION;
    config->ver_max = RQFT_PROTOCOL_VERSION;
    config->max_payload = RQFT_MAX_PAYLOAD;
    config->window = RQFT_WINDOW_MAX;
}

rqft_result_t rqft_session_init(rqft_session_t *session, const rqft_session_config_t *config)
{
    rqft_hello_t hello;
    uint8_t scratch[RQFT_HELLO_BODY_LEN];
    hello.ver_min = config->ver_min;
    hello.ver_max = config->ver_max;
    hello.role = config->role;
    hello.max_payload = config->max_payload;
    hello.window = config->window;
    hello.caps = config->caps;
    if ((config->role != RQFT_ROLE_CONTROLLER && config->role != RQFT_ROLE_RESPONDER) ||
        rqft_hello_encode(&hello, scratch) != RQFT_OK ||
        config->next_sid == nullptr || config->transmit == nullptr ||
        config->on_event == nullptr) {
        return RQFT_ERR_MALFORMED;
    }

    SessionStateImpl *impl = ::new (static_cast<void *>(&session->storage[0])) SessionStateImpl{};
    impl->config = *config;
    impl->state = RQFT_SESSION_IDLE;
    rqft_frame_parser_init(&impl->parser, config->max_payload);
    return RQFT_OK;
}

rqft_result_t rqft_session_start(rqft_session_t *session, uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    if (impl.state != RQFT_SESSION_IDLE) {
        return RQFT_ERR_MALFORMED;
    }
    uint8_t sid = impl.config.next_sid(impl.config.sid_user);
    if (sid == 0u) {
        return RQFT_ERR_MALFORMED;
    }
    impl.sid = sid;
    impl.hello_attempts = 0u;
    transmit_hello(impl, now_ms);
    impl.state = RQFT_SESSION_HELLO_SENT;
    return RQFT_OK;
}

void rqft_session_receive(rqft_session_t *session,
                          const uint8_t *data,
                          size_t len,
                          uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    rqft_frame_parser_feed(&impl.parser, data, len, now_ms, parser_event_thunk, &impl);
    pump(impl, now_ms);
}

void rqft_session_poll(rqft_session_t *session, uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    rqft_frame_parser_flush_idle(&impl.parser, now_ms, parser_event_thunk, &impl);
    if (impl.state == RQFT_SESSION_HELLO_SENT &&
        now_ms - impl.last_hello_tx_ms >= RQFT_T_HELLO_MS) {
        retry_hello(impl, now_ms);
    }
    if (impl.state == RQFT_SESSION_ACTIVE && impl.link_ready) {
        rqft_link_poll(&impl.link, now_ms);
    }
    if (impl.state == RQFT_SESSION_ACTIVE) {
        run_keepalive(impl, now_ms);
    }
    pump(impl, now_ms);
}

bool rqft_session_next_timeout(const rqft_session_t *session, uint32_t *deadline_ms)
{
    const SessionStateImpl &impl = session_impl(session);
    bool found = false;
    uint32_t best = 0u;
    uint32_t candidate = 0u;

    if (rqft_frame_parser_next_flush(&impl.parser, &candidate)) {
        best = candidate;
        found = true;
    }
    if (impl.state == RQFT_SESSION_HELLO_SENT) {
        candidate = impl.last_hello_tx_ms + RQFT_T_HELLO_MS;
        if (!found || candidate < best) {
            best = candidate;
        }
        found = true;
    }
    if (impl.state == RQFT_SESSION_ACTIVE) {
        candidate = impl.last_rx_ms + RQFT_T_DEAD_MS;
        if (!found || candidate < best) {
            best = candidate;
        }
        found = true;
        if (keepalive_allowed(impl)) {
            candidate = impl.last_tx_ms + RQFT_T_PING_MS;
            if (candidate < best) {
                best = candidate;
            }
        }
    }
    if (impl.state == RQFT_SESSION_ACTIVE && impl.link_ready &&
        rqft_link_next_timeout(&impl.link, &candidate)) {
        if (!found || candidate < best) {
            best = candidate;
        }
        found = true;
    }

    if (found) {
        *deadline_ms = best;
    }
    return found;
}

rqft_session_state_t rqft_session_state(const rqft_session_t *session)
{
    return session_impl(session).state;
}

bool rqft_session_active(const rqft_session_t *session)
{
    return session_impl(session).state == RQFT_SESSION_ACTIVE;
}

bool rqft_session_work_pending(const rqft_session_t *session)
{
    const SessionStateImpl &impl = session_impl(session);
    if (impl.state != RQFT_SESSION_ACTIVE) {
        return false;
    }
    if (impl.ctrl_count > 0u || impl.ctrl_overflow) {
        return true;
    }
    if (impl.op == OpKind::CtrlPut) {
        return impl.ctrl_put.failed || impl.ctrl_put.phase == PutPhase::Hash ||
               impl.ctrl_put.phase == PutPhase::Stream;
    }
    return impl.op == OpKind::RespList || impl.op == OpKind::RespGet;
}

bool rqft_session_progress(const rqft_session_t *session, rqft_transfer_progress_t *out)
{
    const SessionStateImpl &impl = session_impl(session);
    if (impl.state != RQFT_SESSION_ACTIVE) {
        return false;
    }
    switch (impl.op) {
    case OpKind::CtrlGet:
        out->request = RQFT_MSG_GET_REQ;
        out->phase = RQFT_PROGRESS_STREAM;
        out->done = impl.ctrl_get.streaming ? impl.ctrl_get.received : 0u;
        out->has_total = impl.ctrl_get.streaming;
        out->total = impl.ctrl_get.streaming ? impl.ctrl_get.size : 0u;
        return true;
    case OpKind::RespGet:
        out->request = RQFT_MSG_GET_REQ;
        out->phase = RQFT_PROGRESS_STREAM;
        out->done = impl.resp_get.sent;
        out->has_total = true;
        out->total = impl.resp_get.size;
        return true;
    case OpKind::CtrlPut:
        out->request = RQFT_MSG_PUT_REQ;
        if (impl.ctrl_put.phase == PutPhase::Hash) {
            out->phase = RQFT_PROGRESS_HASH;
            out->done = impl.ctrl_put.hashed;
            out->has_total = impl.ctrl_put.size_hint_known;
            out->total = impl.ctrl_put.size_hint_known ? impl.ctrl_put.size_hint : 0u;
        } else {
            out->phase = RQFT_PROGRESS_STREAM;
            out->done = impl.ctrl_put.sent;
            out->has_total = true;
            out->total = impl.ctrl_put.size;
        }
        return true;
    case OpKind::RespPut:
        out->request = RQFT_MSG_PUT_REQ;
        out->phase = RQFT_PROGRESS_STREAM;
        out->done = impl.resp_put.received;
        out->has_total = true;
        out->total = impl.resp_put.size;
        return true;
    default:
        return false;
    }
}

void rqft_session_abort(rqft_session_t *session,
                        rqft_abort_reason_t reason,
                        uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    if (impl.state == RQFT_SESSION_ACTIVE || impl.state == RQFT_SESSION_HELLO_SENT) {
        abort_session(impl, reason);
    }
}

rqft_result_t rqft_session_request_list(rqft_session_t *session,
                                        const uint8_t *root,
                                        size_t root_len,
                                        bool want_crc,
                                        uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    if (impl.state != RQFT_SESSION_ACTIVE ||
        impl.config.role != RQFT_ROLE_CONTROLLER ||
        impl.op != OpKind::None ||
        !rqft_path_valid(root, root_len, true)) {
        return RQFT_ERR_MALFORMED;
    }

    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_LIST_REQ;
    msg.u.list_req.want_crc = want_crc;
    msg.u.list_req.root = root;
    msg.u.list_req.root_len = root_len;
    impl.op = OpKind::CtrlList;
    impl.ctrl_list.received = 0u;
    ctrl_send(impl, msg, now_ms);
    return RQFT_OK;
}

rqft_result_t rqft_session_request_get(rqft_session_t *session,
                                       const uint8_t *path,
                                       size_t path_len,
                                       uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    const rqft_fs_ops_t *fs = impl.config.fs;
    if (impl.state != RQFT_SESSION_ACTIVE ||
        impl.config.role != RQFT_ROLE_CONTROLLER ||
        impl.op != OpKind::None ||
        !rqft_path_valid(path, path_len, false) ||
        fs == nullptr || fs->open_write == nullptr || fs->write == nullptr ||
        fs->commit == nullptr || fs->discard == nullptr ||
        kGetReqOverhead + path_len > impl.eff_max_payload) {
        return RQFT_ERR_MALFORMED;
    }

    impl.op = OpKind::CtrlGet;
    std::memset(&impl.ctrl_get, 0, sizeof(impl.ctrl_get));
    std::memcpy(impl.ctrl_get.path, path, path_len);
    impl.ctrl_get.path_len = path_len;

    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_GET_REQ;
    msg.u.get_req.offset = 0u;
    msg.u.get_req.path = impl.ctrl_get.path;
    msg.u.get_req.path_len = path_len;
    ctrl_send(impl, msg, now_ms);
    return RQFT_OK;
}

rqft_result_t rqft_session_request_put(rqft_session_t *session,
                                       const uint8_t *path,
                                       size_t path_len,
                                       uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    const rqft_fs_ops_t *fs = impl.config.fs;
    if (impl.state != RQFT_SESSION_ACTIVE ||
        impl.config.role != RQFT_ROLE_CONTROLLER ||
        impl.op != OpKind::None ||
        !rqft_path_valid(path, path_len, false) ||
        fs == nullptr || fs->open_read == nullptr || fs->read == nullptr ||
        fs->close_read == nullptr ||
        kPutReqOverhead + path_len > impl.eff_max_payload) {
        return RQFT_ERR_MALFORMED;
    }

    impl.op = OpKind::CtrlPut;
    std::memset(&impl.ctrl_put, 0, sizeof(impl.ctrl_put));
    std::memcpy(impl.ctrl_put.path, path, path_len);
    impl.ctrl_put.path_len = path_len;
    impl.ctrl_put.phase = PutPhase::Hash;

    uint32_t size = 0u;
    if (!fs->open_read(impl.config.fs_user, impl.ctrl_put.path, path_len, &size)) {
        impl.ctrl_put.failed = true;
        impl.ctrl_put.fail_code = RQFT_E_FS_OPEN;
    } else {
        impl.ctrl_put.reading = true;
        impl.ctrl_put.size_hint_known = true;
        impl.ctrl_put.size_hint = size;
    }
    return RQFT_OK;
}

rqft_result_t rqft_session_request_del(rqft_session_t *session,
                                       const uint8_t *path,
                                       size_t path_len,
                                       bool is_dir,
                                       uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    if (impl.state != RQFT_SESSION_ACTIVE ||
        impl.config.role != RQFT_ROLE_CONTROLLER ||
        impl.op != OpKind::None ||
        !rqft_path_valid(path, path_len, false) ||
        kDelOverhead + path_len > impl.eff_max_payload) {
        return RQFT_ERR_MALFORMED;
    }

    impl.op = OpKind::CtrlDel;
    std::memset(&impl.ctrl_del, 0, sizeof(impl.ctrl_del));
    std::memcpy(impl.ctrl_del.path, path, path_len);
    impl.ctrl_del.path_len = path_len;
    impl.ctrl_del.is_dir = is_dir;

    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = is_dir ? RQFT_MSG_DEL_DIR : RQFT_MSG_DEL_FILE;
    msg.u.del_path.path = impl.ctrl_del.path;
    msg.u.del_path.path_len = path_len;
    ctrl_send(impl, msg, now_ms);
    return RQFT_OK;
}

rqft_result_t rqft_session_send_plan(rqft_session_t *session,
                                     uint16_t nfiles,
                                     uint32_t nbytes,
                                     uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    if (impl.state != RQFT_SESSION_ACTIVE ||
        impl.config.role != RQFT_ROLE_CONTROLLER ||
        impl.op != OpKind::None) {
        return RQFT_ERR_MALFORMED;
    }

    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PLAN;
    msg.u.plan.nfiles = nfiles;
    msg.u.plan.nbytes = nbytes;
    ctrl_send(impl, msg, now_ms);
    return RQFT_OK;
}

rqft_result_t rqft_session_send_notify(rqft_session_t *session,
                                       uint32_t flags,
                                       uint32_t now_ms)
{
    SessionStateImpl &impl = session_impl(session);
    impl.now_ms = now_ms;
    /* Idle-slot gate: never queue NOTIFY while an operation runs, so it
     * cannot interleave into a FILE_DATA stream being served. */
    if (impl.state != RQFT_SESSION_ACTIVE ||
        impl.config.role != RQFT_ROLE_RESPONDER ||
        impl.op != OpKind::None ||
        (flags & ~RQFT_NOTIFY_DEFINED_MASK) != 0u) {
        return RQFT_ERR_MALFORMED;
    }

    rqft_msg_t msg;
    std::memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_NOTIFY;
    msg.u.notify.flags = flags;
    ctrl_send(impl, msg, now_ms);
    return RQFT_OK;
}
