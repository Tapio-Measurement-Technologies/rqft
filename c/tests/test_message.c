// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_message.c - session body and message codec tests for SPEC.md
 * sections 5.2 and 5.3. */
#include "rqft/message.h"
#include "test_support.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    return -1;
}

static size_t decode_hex(const char *hex, uint8_t *out, size_t out_cap)
{
    size_t out_len = 0u;
    while (hex[0] != '\0' && hex[1] != '\0') {
        int hi = hex_value(hex[0]);
        int lo = hex_value(hex[1]);
        CHECK(hi >= 0);
        CHECK(lo >= 0);
        CHECK(out_len < out_cap);
        out[out_len] = (uint8_t)(((unsigned int)hi << 4u) | (unsigned int)lo);
        out_len++;
        hex += 2;
    }
    return out_len;
}

static int field_int(const char *line, const char *field)
{
    const char *key = strstr(line, field);
    CHECK(key != NULL);
    if (key == NULL) {
        return 0;
    }
    return (int)strtol(key + strlen(field), NULL, 10);
}

static uint32_t field_u32(const char *line, const char *field)
{
    const char *key = strstr(line, field);
    CHECK(key != NULL);
    if (key == NULL) {
        return 0u;
    }
    return (uint32_t)strtoul(key + strlen(field), NULL, 10);
}

/* Copy the JSON string value following field into out. */
static void field_str(const char *line, const char *field, char *out, size_t out_cap)
{
    const char *begin = strstr(line, field);
    out[0] = '\0';
    CHECK(begin != NULL);
    if (begin == NULL) {
        return;
    }
    begin = strchr(begin + strlen(field), '"');
    CHECK(begin != NULL);
    if (begin == NULL) {
        return;
    }
    begin++;
    const char *end = strchr(begin, '"');
    CHECK(end != NULL);
    if (end == NULL) {
        return;
    }
    size_t len = (size_t)(end - begin);
    CHECK(len < out_cap);
    memcpy(out, begin, len);
    out[len] = '\0';
}

static void check_hello_vector(const char *line)
{
    char encoded_hex[64];
    uint8_t expected[RQFT_HELLO_BODY_LEN];
    uint8_t encoded[RQFT_HELLO_BODY_LEN];
    rqft_hello_t hello;
    rqft_hello_t decoded;

    field_str(line, "\"encoded_hex\":", encoded_hex, sizeof(encoded_hex));
    CHECK_EQ_INT(decode_hex(encoded_hex, expected, sizeof(expected)), RQFT_HELLO_BODY_LEN);

    hello.ver_min = (uint8_t)field_int(line, "\"ver_min\":");
    hello.ver_max = (uint8_t)field_int(line, "\"ver_max\":");
    hello.role = (rqft_role_t)field_int(line, "\"role\":");
    hello.max_payload = (uint16_t)field_int(line, "\"max_payload\":");
    hello.window = (uint8_t)field_int(line, "\"window\":");
    hello.caps = (uint8_t)field_int(line, "\"caps\":");

    CHECK_EQ_INT(rqft_hello_encode(&hello, encoded), RQFT_OK);
    CHECK(memcmp(encoded, expected, RQFT_HELLO_BODY_LEN) == 0);

    CHECK_EQ_INT(rqft_hello_decode(expected, RQFT_HELLO_BODY_LEN, &decoded), RQFT_OK);
    CHECK_EQ_INT(decoded.ver_min, hello.ver_min);
    CHECK_EQ_INT(decoded.ver_max, hello.ver_max);
    CHECK_EQ_INT(decoded.role, hello.role);
    CHECK_EQ_INT(decoded.max_payload, hello.max_payload);
    CHECK_EQ_INT(decoded.window, hello.window);
    CHECK_EQ_INT(decoded.caps, hello.caps);
}

static void check_hello_ok_vector(const char *line)
{
    char encoded_hex[64];
    uint8_t expected[RQFT_HELLO_BODY_LEN];
    uint8_t encoded[RQFT_HELLO_BODY_LEN];
    rqft_hello_ok_t ok;
    rqft_hello_ok_t decoded;

    field_str(line, "\"encoded_hex\":", encoded_hex, sizeof(encoded_hex));
    CHECK_EQ_INT(decode_hex(encoded_hex, expected, sizeof(expected)), RQFT_HELLO_BODY_LEN);

    ok.ver = (uint8_t)field_int(line, "\"ver\":");
    ok.role = (rqft_role_t)field_int(line, "\"role\":");
    ok.max_payload = (uint16_t)field_int(line, "\"max_payload\":");
    ok.window = (uint8_t)field_int(line, "\"window\":");
    ok.caps = (uint8_t)field_int(line, "\"caps\":");

    CHECK_EQ_INT(rqft_hello_ok_encode(&ok, encoded), RQFT_OK);
    CHECK(memcmp(encoded, expected, RQFT_HELLO_BODY_LEN) == 0);

    CHECK_EQ_INT(rqft_hello_ok_decode(expected, RQFT_HELLO_BODY_LEN, &decoded), RQFT_OK);
    CHECK_EQ_INT(decoded.ver, ok.ver);
    CHECK_EQ_INT(decoded.role, ok.role);
    CHECK_EQ_INT(decoded.max_payload, ok.max_payload);
    CHECK_EQ_INT(decoded.window, ok.window);
    CHECK_EQ_INT(decoded.caps, ok.caps);
}

/* Build the typed message a testvector line describes; false when the
 * kind is not a section 5.3 message. */
static bool vector_message(const char *line,
                           const char *kind,
                           rqft_msg_t *msg,
                           uint8_t *path_buf,
                           size_t *path_len)
{
    char hex[300];

    memset(msg, 0, sizeof(*msg));
    if (strcmp(kind, "list_req") == 0) {
        field_str(line, "\"root_hex\":", hex, sizeof(hex));
        *path_len = decode_hex(hex, path_buf, RQFT_MAX_PATH);
        msg->type = RQFT_MSG_LIST_REQ;
        msg->u.list_req.want_crc = field_int(line, "\"want_crc\":") != 0;
        msg->u.list_req.root = path_buf;
        msg->u.list_req.root_len = *path_len;
    } else if (strcmp(kind, "list_entry") == 0) {
        field_str(line, "\"path_hex\":", hex, sizeof(hex));
        *path_len = decode_hex(hex, path_buf, RQFT_MAX_PATH);
        msg->type = RQFT_MSG_LIST_ENTRY;
        msg->u.list_entry.etype = (uint8_t)field_int(line, "\"etype\":");
        msg->u.list_entry.crc_valid = field_int(line, "\"crc_valid\":") != 0;
        msg->u.list_entry.size = field_u32(line, "\"size\":");
        msg->u.list_entry.crc32 = field_u32(line, "\"crc32\":");
        msg->u.list_entry.mtime = field_u32(line, "\"mtime\":");
        msg->u.list_entry.path = path_buf;
        msg->u.list_entry.path_len = *path_len;
    } else if (strcmp(kind, "list_end") == 0) {
        msg->type = RQFT_MSG_LIST_END;
        msg->u.list_end.count = (uint16_t)field_int(line, "\"count\":");
    } else if (strcmp(kind, "get_req") == 0) {
        field_str(line, "\"path_hex\":", hex, sizeof(hex));
        *path_len = decode_hex(hex, path_buf, RQFT_MAX_PATH);
        msg->type = RQFT_MSG_GET_REQ;
        msg->u.get_req.offset = field_u32(line, "\"offset\":");
        msg->u.get_req.path = path_buf;
        msg->u.get_req.path_len = *path_len;
    } else if (strcmp(kind, "file_info") == 0) {
        msg->type = RQFT_MSG_FILE_INFO;
        msg->u.file_info.size = field_u32(line, "\"size\":");
    } else if (strcmp(kind, "file_data") == 0) {
        field_str(line, "\"data_hex\":", hex, sizeof(hex));
        *path_len = decode_hex(hex, path_buf, RQFT_MAX_PATH);
        msg->type = RQFT_MSG_FILE_DATA;
        msg->u.file_data.data = path_buf;
        msg->u.file_data.len = *path_len;
    } else if (strcmp(kind, "file_end") == 0) {
        msg->type = RQFT_MSG_FILE_END;
        msg->u.file_end.crc32 = field_u32(line, "\"crc32\":");
    } else if (strcmp(kind, "get_done") == 0) {
        msg->type = RQFT_MSG_GET_DONE;
        msg->u.get_done.status = (uint8_t)field_int(line, "\"status\":");
    } else if (strcmp(kind, "put_req") == 0) {
        field_str(line, "\"path_hex\":", hex, sizeof(hex));
        *path_len = decode_hex(hex, path_buf, RQFT_MAX_PATH);
        msg->type = RQFT_MSG_PUT_REQ;
        msg->u.put_req.size = field_u32(line, "\"size\":");
        msg->u.put_req.crc32 = field_u32(line, "\"crc32\":");
        msg->u.put_req.path = path_buf;
        msg->u.put_req.path_len = *path_len;
    } else if (strcmp(kind, "put_ok") == 0) {
        msg->type = RQFT_MSG_PUT_OK;
    } else if (strcmp(kind, "put_done") == 0) {
        msg->type = RQFT_MSG_PUT_DONE;
        msg->u.put_done.status = (uint8_t)field_int(line, "\"status\":");
    } else if (strcmp(kind, "del_file") == 0 || strcmp(kind, "del_dir") == 0) {
        field_str(line, "\"path_hex\":", hex, sizeof(hex));
        *path_len = decode_hex(hex, path_buf, RQFT_MAX_PATH);
        msg->type = strcmp(kind, "del_file") == 0 ? RQFT_MSG_DEL_FILE : RQFT_MSG_DEL_DIR;
        msg->u.del_path.path = path_buf;
        msg->u.del_path.path_len = *path_len;
    } else if (strcmp(kind, "del_ok") == 0) {
        msg->type = RQFT_MSG_DEL_OK;
    } else if (strcmp(kind, "plan") == 0) {
        msg->type = RQFT_MSG_PLAN;
        msg->u.plan.nfiles = (uint16_t)field_int(line, "\"nfiles\":");
        msg->u.plan.nbytes = field_u32(line, "\"nbytes\":");
    } else if (strcmp(kind, "notify") == 0) {
        msg->type = RQFT_MSG_NOTIFY;
        msg->u.notify.flags = field_u32(line, "\"flags\":");
    } else if (strcmp(kind, "ping") == 0 || strcmp(kind, "pong") == 0) {
        msg->type = strcmp(kind, "ping") == 0 ? RQFT_MSG_PING : RQFT_MSG_PONG;
        msg->u.token.token = field_u32(line, "\"token\":");
    } else if (strcmp(kind, "err") == 0) {
        msg->type = RQFT_MSG_ERR;
        msg->u.err.code = (rqft_err_code_t)field_int(line, "\"code\":");
        msg->u.err.ref_msgtype = (uint8_t)field_int(line, "\"ref_msgtype\":");
        msg->u.err.detail = (uint16_t)field_int(line, "\"detail\":");
    } else {
        return false;
    }
    return true;
}

static void check_message_vector(const char *line, const char *kind)
{
    char encoded_hex[600];
    uint8_t expected[300];
    size_t expected_len;
    uint8_t path_buf[RQFT_MAX_PATH];
    size_t path_len = 0u;
    rqft_msg_t msg;
    rqft_msg_t decoded;
    uint8_t out[300];
    size_t out_len = 0u;

    CHECK(vector_message(line, kind, &msg, path_buf, &path_len));

    field_str(line, "\"encoded_hex\":", encoded_hex, sizeof(encoded_hex));
    expected_len = decode_hex(encoded_hex, expected, sizeof(expected));

    /* Building the message from fields yields the golden bytes. */
    CHECK_EQ_INT(rqft_msg_encode(&msg, out, sizeof(out), &out_len), RQFT_OK);
    CHECK_EQ_INT(out_len, expected_len);
    CHECK(memcmp(out, expected, expected_len) == 0);

    /* Decoding the golden bytes round-trips back to them. */
    CHECK_EQ_INT(rqft_msg_decode(expected, expected_len, &decoded), RQFT_OK);
    CHECK_EQ_INT(decoded.type, msg.type);
    CHECK_EQ_INT(rqft_msg_encode(&decoded, out, sizeof(out), &out_len), RQFT_OK);
    CHECK_EQ_INT(out_len, expected_len);
    CHECK(memcmp(out, expected, expected_len) == 0);
}

static void test_golden_vectors(void)
{
    FILE *file = fopen(RQFT_REPO_ROOT "/testvectors/messages.json", "r");
    char line[600];
    char kind[32];
    unsigned int hello_cases = 0u;
    unsigned int hello_ok_cases = 0u;
    unsigned int message_cases = 0u;

    CHECK(file != NULL);
    if (file == NULL) {
        return;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "\"kind\":") == NULL) {
            continue;
        }
        field_str(line, "\"kind\":", kind, sizeof(kind));
        if (strcmp(kind, "hello") == 0) {
            check_hello_vector(line);
            hello_cases++;
        } else if (strcmp(kind, "hello_ok") == 0) {
            check_hello_ok_vector(line);
            hello_ok_cases++;
        } else {
            check_message_vector(line, kind);
            message_cases++;
        }
    }
    fclose(file);
    CHECK_EQ_INT(hello_cases, 3);
    CHECK_EQ_INT(hello_ok_cases, 2);
    CHECK_EQ_INT(message_cases, 25);
}

static void valid_hello_bytes(uint8_t out[RQFT_HELLO_BODY_LEN])
{
    rqft_hello_t hello;
    hello.ver_min = 1u;
    hello.ver_max = 1u;
    hello.role = RQFT_ROLE_RESPONDER;
    hello.max_payload = 512u;
    hello.window = 4u;
    hello.caps = RQFT_CAP_ALLOW_DELETE;
    CHECK_EQ_INT(rqft_hello_encode(&hello, out), RQFT_OK);
}

static void valid_hello_ok_bytes(uint8_t out[RQFT_HELLO_BODY_LEN])
{
    rqft_hello_ok_t ok;
    ok.ver = 1u;
    ok.role = RQFT_ROLE_CONTROLLER;
    ok.max_payload = 512u;
    ok.window = 4u;
    ok.caps = 0u;
    CHECK_EQ_INT(rqft_hello_ok_encode(&ok, out), RQFT_OK);
}

static void test_hello_decode_rejects_malformed(void)
{
    uint8_t data[RQFT_HELLO_BODY_LEN];
    rqft_hello_t out;

    valid_hello_bytes(data);
    CHECK_EQ_INT(rqft_hello_decode(data, 7u, &out), RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_hello_decode(data, 9u, &out), RQFT_ERR_MALFORMED);

    valid_hello_bytes(data);
    data[2] = 2u; /* undefined role */
    CHECK_EQ_INT(rqft_hello_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_bytes(data);
    data[0] = 3u; /* ver_min > ver_max */
    data[1] = 2u;
    CHECK_EQ_INT(rqft_hello_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_bytes(data);
    data[3] = 0u; /* max_payload 0 */
    data[4] = 0u;
    CHECK_EQ_INT(rqft_hello_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_bytes(data);
    data[3] = 0x01u; /* max_payload 513 */
    data[4] = 0x02u;
    CHECK_EQ_INT(rqft_hello_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_bytes(data);
    data[5] = 0u; /* window 0 */
    CHECK_EQ_INT(rqft_hello_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_bytes(data);
    data[5] = 9u; /* window 9 */
    CHECK_EQ_INT(rqft_hello_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_bytes(data);
    data[6] = 0x02u; /* reserved caps bit */
    CHECK_EQ_INT(rqft_hello_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_bytes(data);
    data[7] = 1u; /* reserved */
    CHECK_EQ_INT(rqft_hello_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);
}

static void test_hello_ok_decode_rejects_malformed(void)
{
    uint8_t data[RQFT_HELLO_BODY_LEN];
    rqft_hello_ok_t out;

    valid_hello_ok_bytes(data);
    CHECK_EQ_INT(rqft_hello_ok_decode(data, 7u, &out), RQFT_ERR_MALFORMED);

    valid_hello_ok_bytes(data);
    data[6] = 1u; /* reserved */
    CHECK_EQ_INT(rqft_hello_ok_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_ok_bytes(data);
    data[7] = 1u; /* reserved */
    CHECK_EQ_INT(rqft_hello_ok_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);

    valid_hello_ok_bytes(data);
    data[1] = 0xFFu; /* undefined role */
    CHECK_EQ_INT(rqft_hello_ok_decode(data, sizeof(data), &out), RQFT_ERR_MALFORMED);
}

static void test_encode_rejects_out_of_range_fields(void)
{
    uint8_t out[RQFT_HELLO_BODY_LEN];
    rqft_hello_t hello;
    rqft_hello_ok_t ok;

    hello.ver_min = 2u;
    hello.ver_max = 1u;
    hello.role = RQFT_ROLE_CONTROLLER;
    hello.max_payload = 512u;
    hello.window = 4u;
    hello.caps = 0u;
    CHECK_EQ_INT(rqft_hello_encode(&hello, out), RQFT_ERR_MALFORMED);

    hello.ver_min = 1u;
    hello.max_payload = 0u;
    CHECK_EQ_INT(rqft_hello_encode(&hello, out), RQFT_ERR_MALFORMED);

    ok.ver = 1u;
    ok.role = RQFT_ROLE_CONTROLLER;
    ok.max_payload = 512u;
    ok.window = 9u;
    ok.caps = 0u;
    CHECK_EQ_INT(rqft_hello_ok_encode(&ok, out), RQFT_ERR_MALFORMED);

    ok.window = 4u;
    ok.caps = 0x80u;
    CHECK_EQ_INT(rqft_hello_ok_encode(&ok, out), RQFT_ERR_MALFORMED);
}

static void test_unknown_msg_type_decodes_as_unknown(void)
{
    uint8_t payload[3] = {0x60u, 0x01u, 0x02u};
    rqft_msg_t msg;

    CHECK_EQ_INT(rqft_msg_decode(payload, sizeof(payload), &msg), RQFT_OK);
    CHECK_EQ_INT(msg.type, RQFT_MSG_UNKNOWN);
    CHECK_EQ_INT(msg.u.unknown.msg_type, 0x60);
    CHECK_EQ_INT(msg.u.unknown.len, 2);
    CHECK(memcmp(msg.u.unknown.body, payload + 1u, 2u) == 0);

    payload[0] = 0x00u;
    CHECK_EQ_INT(rqft_msg_decode(payload, 1u, &msg), RQFT_OK);
    CHECK_EQ_INT(msg.type, RQFT_MSG_UNKNOWN);
    CHECK_EQ_INT(msg.u.unknown.len, 0);

    {
        size_t out_len = 0u;
        CHECK_EQ_INT(rqft_msg_encode(&msg, payload, sizeof(payload), &out_len),
                     RQFT_ERR_MALFORMED);
    }
}

static void test_decode_rejects_structural_violations(void)
{
    rqft_msg_t msg;
    uint8_t buf[200] = {0};

    CHECK_EQ_INT(rqft_msg_decode(buf, 0u, &msg), RQFT_ERR_MALFORMED);

    /* LIST_END with a short count. */
    buf[0] = 0x12u;
    buf[1] = 0x03u;
    CHECK_EQ_INT(rqft_msg_decode(buf, 2u, &msg), RQFT_ERR_MALFORMED);

    /* Path length prefix overruns the body. */
    buf[0] = 0x10u;
    buf[1] = 0x01u;
    buf[2] = 0x05u;
    buf[3] = 'a';
    buf[4] = 'b';
    CHECK_EQ_INT(rqft_msg_decode(buf, 5u, &msg), RQFT_ERR_MALFORMED);

    /* Path length prefix above RQFT_MAX_PATH. */
    buf[0] = 0x10u;
    buf[1] = 0x01u;
    buf[2] = 0x81u;
    memset(buf + 3u, 'x', 0x81u);
    CHECK_EQ_INT(rqft_msg_decode(buf, 3u + 0x81u, &msg), RQFT_ERR_MALFORMED);

    /* Reserved LIST_REQ flag bit. */
    buf[0] = 0x10u;
    buf[1] = 0x02u;
    buf[2] = 0x00u;
    CHECK_EQ_INT(rqft_msg_decode(buf, 3u, &msg), RQFT_ERR_MALFORMED);

    /* Reserved LIST_ENTRY eflags bit. */
    buf[0] = 0x11u;
    buf[1] = 0x00u;
    buf[2] = 0x02u;
    memset(buf + 3u, 0, 13u);
    CHECK_EQ_INT(rqft_msg_decode(buf, 16u, &msg), RQFT_ERR_MALFORMED);

    /* Trailing byte after a complete body. */
    buf[0] = 0x12u;
    buf[1] = 0x03u;
    buf[2] = 0x00u;
    buf[3] = 0xFFu;
    CHECK_EQ_INT(rqft_msg_decode(buf, 4u, &msg), RQFT_ERR_MALFORMED);

    /* Undefined error code. */
    buf[0] = 0x7Fu;
    buf[1] = 0x63u;
    buf[2] = 0x20u;
    buf[3] = 0x00u;
    buf[4] = 0x00u;
    CHECK_EQ_INT(rqft_msg_decode(buf, 5u, &msg), RQFT_ERR_MALFORMED);

    /* PUT_DONE status that is neither 0 nor a defined error code. */
    buf[0] = 0x2Au;
    buf[1] = 0x63u;
    CHECK_EQ_INT(rqft_msg_decode(buf, 2u, &msg), RQFT_ERR_MALFORMED);

    /* GET_DONE status that is neither 0 nor a defined error code. */
    buf[0] = 0x24u;
    buf[1] = 0x63u;
    CHECK_EQ_INT(rqft_msg_decode(buf, 2u, &msg), RQFT_ERR_MALFORMED);
}

static void test_encode_rejects_long_path(void)
{
    uint8_t path[129];
    uint8_t out[300];
    size_t out_len = 0u;
    rqft_msg_t msg;

    memset(path, 'a', sizeof(path));
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_DEL_FILE;
    msg.u.del_path.path = path;
    msg.u.del_path.path_len = sizeof(path);
    CHECK_EQ_INT(rqft_msg_encode(&msg, out, sizeof(out), &out_len), RQFT_ERR_MALFORMED);
}

static void test_encode_rejects_undefined_put_status(void)
{
    uint8_t out[8];
    size_t out_len = 0u;
    rqft_msg_t msg;

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_PUT_DONE;
    msg.u.put_done.status = 0x63u;
    CHECK_EQ_INT(rqft_msg_encode(&msg, out, sizeof(out), &out_len), RQFT_ERR_MALFORMED);
}

static void test_encode_rejects_undefined_get_status(void)
{
    uint8_t out[8];
    size_t out_len = 0u;
    rqft_msg_t msg;

    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_GET_DONE;
    msg.u.get_done.status = 0x63u;
    CHECK_EQ_INT(rqft_msg_encode(&msg, out, sizeof(out), &out_len), RQFT_ERR_MALFORMED);
}

static void test_notify_encode_rejects_undefined_flags(void)
{
    uint8_t out[8];
    size_t out_len = 0u;
    rqft_msg_t msg;

    /* Senders must zero undefined NOTIFY flag bits (spec 5.4). */
    memset(&msg, 0, sizeof(msg));
    msg.type = RQFT_MSG_NOTIFY;
    msg.u.notify.flags = 0x04u;
    CHECK_EQ_INT(rqft_msg_encode(&msg, out, sizeof(out), &out_len), RQFT_ERR_MALFORMED);

    msg.u.notify.flags = 0x80000000u;
    CHECK_EQ_INT(rqft_msg_encode(&msg, out, sizeof(out), &out_len), RQFT_ERR_MALFORMED);

    msg.u.notify.flags = RQFT_NOTIFY_SYNC_INCREMENTAL | RQFT_NOTIFY_DELETE_AFTER_SYNC;
    CHECK_EQ_INT(rqft_msg_encode(&msg, out, sizeof(out), &out_len), RQFT_OK);
}

static void test_notify_decode_is_forward_compatible(void)
{
    rqft_msg_t msg;
    const uint8_t unknown_bits[] = {0x41u, 0x07u, 0x00u, 0x00u, 0x00u};
    const uint8_t longer_body[] = {0x41u, 0x01u, 0x00u, 0x00u, 0x00u, 0xFFu, 0xFFu};
    const uint8_t short_body[] = {0x41u, 0x01u, 0x00u};

    /* Receivers mask undefined flag bits. */
    CHECK_EQ_INT(rqft_msg_decode(unknown_bits, sizeof(unknown_bits), &msg), RQFT_OK);
    CHECK_EQ_INT(msg.type, RQFT_MSG_NOTIFY);
    CHECK_EQ_INT(msg.u.notify.flags,
                 RQFT_NOTIFY_SYNC_INCREMENTAL | RQFT_NOTIFY_DELETE_AFTER_SYNC);

    /* Receivers ignore appended future fields. */
    CHECK_EQ_INT(rqft_msg_decode(longer_body, sizeof(longer_body), &msg), RQFT_OK);
    CHECK_EQ_INT(msg.type, RQFT_MSG_NOTIFY);
    CHECK_EQ_INT(msg.u.notify.flags, RQFT_NOTIFY_SYNC_INCREMENTAL);

    /* A body shorter than the flags field is malformed. */
    CHECK_EQ_INT(rqft_msg_decode(short_body, sizeof(short_body), &msg), RQFT_ERR_MALFORMED);
}

static void test_path_valid_accepts_spec_paths(void)
{
    uint8_t long_path[128];
    /* UTF-8 for a Finnish file name. */
    const uint8_t utf8[] = {0x6Du, 0xC3u, 0xA4u, 0xC3u, 0xA4u, 0x72u, 0xC3u, 0xA4u,
                            0x79u, 0x73u, 0x2Eu, 0x74u, 0x78u, 0x74u};

    CHECK(rqft_path_valid((const uint8_t *)"a.data", 6u, false));
    CHECK(rqft_path_valid((const uint8_t *)"logs/2025/run1.data", 19u, false));
    CHECK(rqft_path_valid(utf8, sizeof(utf8), false));
    memset(long_path, 'a', sizeof(long_path));
    CHECK(rqft_path_valid(long_path, sizeof(long_path), false));
    CHECK(rqft_path_valid(NULL, 0u, true));
}

static void test_path_valid_rejects_violations(void)
{
    uint8_t long_path[129];
    const uint8_t bad_utf8[] = {0xFFu, 0xFEu};
    const uint8_t overlong[] = {0xC0u, 0xAFu};
    const uint8_t nul_path[] = {'a', 0x00u, 'b'};

    CHECK(!rqft_path_valid(NULL, 0u, false));
    memset(long_path, 'a', sizeof(long_path));
    CHECK(!rqft_path_valid(long_path, sizeof(long_path), false));
    CHECK(!rqft_path_valid((const uint8_t *)"/etc/passwd", 11u, false));
    CHECK(!rqft_path_valid((const uint8_t *)"a//b", 4u, false));
    CHECK(!rqft_path_valid((const uint8_t *)"a/", 2u, false));
    CHECK(!rqft_path_valid((const uint8_t *)"./a", 3u, false));
    CHECK(!rqft_path_valid((const uint8_t *)"a/./b", 5u, false));
    CHECK(!rqft_path_valid((const uint8_t *)"../a", 4u, false));
    CHECK(!rqft_path_valid((const uint8_t *)"a/../b", 6u, false));
    CHECK(!rqft_path_valid((const uint8_t *)"a\\b", 3u, false));
    CHECK(!rqft_path_valid(nul_path, sizeof(nul_path), false));
    CHECK(!rqft_path_valid(bad_utf8, sizeof(bad_utf8), false));
    CHECK(!rqft_path_valid(overlong, sizeof(overlong), false));
}

int main(void)
{
    test_golden_vectors();
    test_hello_decode_rejects_malformed();
    test_hello_ok_decode_rejects_malformed();
    test_encode_rejects_out_of_range_fields();
    test_unknown_msg_type_decodes_as_unknown();
    test_decode_rejects_structural_violations();
    test_encode_rejects_long_path();
    test_encode_rejects_undefined_put_status();
    test_encode_rejects_undefined_get_status();
    test_notify_encode_rejects_undefined_flags();
    test_notify_decode_is_forward_compatible();
    test_path_valid_accepts_spec_paths();
    test_path_valid_rejects_violations();
    TEST_MAIN_END();
}
