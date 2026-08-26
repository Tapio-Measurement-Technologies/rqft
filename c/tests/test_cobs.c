// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_cobs.c - shared golden COBS vectors for SPEC.md section 3.1. */
#include "rqft/cobs.h"
#include "test_support.h"

#include <stdint.h>

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static size_t decode_hex(const char *hex, size_t hex_len, uint8_t *out, size_t out_cap)
{
    CHECK((hex_len % 2u) == 0u);
    CHECK((hex_len / 2u) <= out_cap);

    size_t out_len = 0u;
    for (size_t i = 0u; i < hex_len; i += 2u) {
        int hi = hex_value(hex[i]);
        int lo = hex_value(hex[i + 1u]);
        CHECK(hi >= 0);
        CHECK(lo >= 0);
        out[out_len] = (uint8_t)(((unsigned int)hi << 4u) | (unsigned int)lo);
        out_len++;
    }
    return out_len;
}

static const char *field_value(const char *line, const char *field)
{
    const char *key = strstr(line, field);
    CHECK(key != NULL);
    if (key == NULL) {
        return NULL;
    }
    const char *value = strchr(key + strlen(field), '"');
    CHECK(value != NULL);
    if (value == NULL) {
        return NULL;
    }
    return value + 1;
}

static size_t field_hex(const char *line, const char *field, uint8_t *out, size_t out_cap)
{
    const char *begin = field_value(line, field);
    if (begin == NULL) {
        return 0u;
    }
    const char *end = strchr(begin, '"');
    CHECK(end != NULL);
    if (end == NULL) {
        return 0u;
    }
    return decode_hex(begin, (size_t)(end - begin), out, out_cap);
}

static void check_streaming_decode(const uint8_t *encoded,
                                   size_t encoded_len,
                                   const uint8_t *expected,
                                   size_t expected_len)
{
    rqft_cobs_decoder_t decoder;
    uint8_t decoded[600];
    size_t decoded_len = 0u;
    rqft_cobs_decoder_init(&decoder);

    for (size_t i = 0u; i < encoded_len; i++) {
        size_t chunk_len = 0u;
        CHECK_EQ_INT(rqft_cobs_decoder_feed(&decoder, encoded + i, 1u, false,
                                            decoded + decoded_len,
                                            sizeof(decoded) - decoded_len,
                                            &chunk_len),
                     RQFT_OK);
        decoded_len += chunk_len;
    }

    size_t final_len = 0u;
    CHECK_EQ_INT(rqft_cobs_decoder_feed(&decoder, encoded + encoded_len, 0u, true,
                                        decoded + decoded_len,
                                        sizeof(decoded) - decoded_len,
                                        &final_len),
                 RQFT_OK);
    decoded_len += final_len;
    CHECK_EQ_INT(decoded_len, expected_len);
    CHECK(memcmp(decoded, expected, expected_len) == 0);
}

static void run_vector_line(const char *line, unsigned int *seen)
{
    if (strstr(line, "\"decoded_hex\":") == NULL) {
        return;
    }

    uint8_t decoded[600];
    uint8_t encoded[600];
    uint8_t actual[600];
    size_t decoded_len = field_hex(line, "\"decoded_hex\":", decoded, sizeof(decoded));
    size_t encoded_len = field_hex(line, "\"encoded_hex\":", encoded, sizeof(encoded));

    size_t actual_len = 0u;
    CHECK_EQ_INT(rqft_cobs_encode(decoded, decoded_len, actual, sizeof(actual), &actual_len), RQFT_OK);
    CHECK_EQ_INT(actual_len, encoded_len);
    CHECK(memcmp(actual, encoded, encoded_len) == 0);

    actual_len = 0u;
    CHECK_EQ_INT(rqft_cobs_decode(encoded, encoded_len, actual, sizeof(actual), &actual_len), RQFT_OK);
    CHECK_EQ_INT(actual_len, decoded_len);
    CHECK(memcmp(actual, decoded, decoded_len) == 0);

    check_streaming_decode(encoded, encoded_len, decoded, decoded_len);
    (*seen)++;
}

static void test_round_trip_patterns(void)
{
    uint8_t decoded[520];
    uint8_t encoded[RQFT_MAX_ENCODED];
    uint8_t actual[520];

    for (size_t len = 0u; len <= sizeof(decoded); len++) {
        for (size_t i = 0u; i < len; i++) {
            decoded[i] = (uint8_t)((i * 37u + len) & 0xffu);
        }

        size_t encoded_len = 0u;
        size_t actual_len = 0u;
        CHECK_EQ_INT(rqft_cobs_encode(decoded, len, encoded, sizeof(encoded), &encoded_len), RQFT_OK);
        CHECK(encoded_len <= RQFT_MAX_ENCODED);
        CHECK_EQ_INT(rqft_cobs_decode(encoded, encoded_len, actual, sizeof(actual), &actual_len), RQFT_OK);
        CHECK_EQ_INT(actual_len, len);
        CHECK(memcmp(actual, decoded, len) == 0);
    }
}

static void test_malformed_inputs(void)
{
    const uint8_t empty[] = {0u};
    const uint8_t zero_code[] = {0u};
    const uint8_t overrun_one[] = {2u};
    const uint8_t overrun_two[] = {3u, 0x11u};
    const uint8_t zero_inside[] = {2u, 0u};
    uint8_t out[8];
    size_t out_len = 99u;

    CHECK_EQ_INT(rqft_cobs_decode(empty, 0u, out, sizeof(out), &out_len), RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_cobs_decode(zero_code, sizeof(zero_code), out, sizeof(out), &out_len),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_cobs_decode(overrun_one, sizeof(overrun_one), out, sizeof(out), &out_len),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_cobs_decode(overrun_two, sizeof(overrun_two), out, sizeof(out), &out_len),
                 RQFT_ERR_MALFORMED);
    CHECK_EQ_INT(rqft_cobs_decode(zero_inside, sizeof(zero_inside), out, sizeof(out), &out_len),
                 RQFT_ERR_MALFORMED);
}

static void test_output_too_small(void)
{
    const uint8_t decoded[] = {1u, 2u, 3u};
    const uint8_t encoded[] = {4u, 1u, 2u, 3u};
    uint8_t out[3];
    size_t out_len = 0u;

    CHECK_EQ_INT(rqft_cobs_encode(decoded, sizeof(decoded), out, sizeof(out), &out_len),
                 RQFT_ERR_OUTPUT_TOO_SMALL);
    CHECK_EQ_INT(rqft_cobs_decode(encoded, sizeof(encoded), out, 2u, &out_len),
                 RQFT_ERR_OUTPUT_TOO_SMALL);
}

int main(void)
{
    FILE *file = fopen(RQFT_REPO_ROOT "/testvectors/cobs.json", "r");
    CHECK(file != NULL);
    if (file == NULL) {
        return 1;
    }

    char line[2600];
    unsigned int seen = 0u;
    while (fgets(line, sizeof(line), file) != NULL) {
        run_vector_line(line, &seen);
    }
    fclose(file);

    CHECK_EQ_INT(seen, 9);
    test_round_trip_patterns();
    test_malformed_inputs();
    test_output_too_small();
    TEST_MAIN_END();
}
