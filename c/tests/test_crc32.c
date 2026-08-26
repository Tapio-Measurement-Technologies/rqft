// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_crc32.c - shared golden CRC32 vectors for SPEC.md section 3.2. */
#include "rqft/crc32.h"
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

    size_t out_len = 0;
    for (size_t i = 0; i < hex_len; i += 2u) {
        int hi = hex_value(hex[i]);
        int lo = hex_value(hex[i + 1u]);
        CHECK(hi >= 0);
        CHECK(lo >= 0);
        out[out_len++] = (uint8_t)(((unsigned int)hi << 4u) | (unsigned int)lo);
    }
    return out_len;
}

static void run_vector_line(const char *line, unsigned int *seen)
{
    const char *key = strstr(line, "\"input_hex\":");
    if (key == NULL) {
        return;
    }

    const char *hex_begin = strchr(key + strlen("\"input_hex\":"), '"');
    CHECK(hex_begin != NULL);
    if (hex_begin == NULL) {
        return;
    }
    hex_begin++;
    const char *hex_end = strchr(hex_begin, '"');
    CHECK(hex_end != NULL);
    if (hex_end == NULL) {
        return;
    }

    const char *crc_key = strstr(hex_end, "\"crc32\":");
    CHECK(crc_key != NULL);
    if (crc_key == NULL) {
        return;
    }

    uint8_t input[512];
    size_t input_len = decode_hex(hex_begin, (size_t)(hex_end - hex_begin), input, sizeof(input));
    uint32_t expected = (uint32_t)strtoul(crc_key + strlen("\"crc32\":"), NULL, 10);
    uint32_t actual = rqft_crc32(input, input_len);
    CHECK_EQ_INT(actual, expected);

    size_t split = input_len < 17u ? input_len : 17u;
    uint32_t incremental = rqft_crc32_update(0u, input, split);
    incremental = rqft_crc32_update(incremental, input + split, input_len - split);
    CHECK_EQ_INT(incremental, expected);
    (*seen)++;
}

int main(void)
{
    FILE *file = fopen(RQFT_REPO_ROOT "/testvectors/crc32.json", "r");
    CHECK(file != NULL);
    if (file == NULL) {
        return 1;
    }

    char line[1400];
    unsigned int seen = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        run_vector_line(line, &seen);
    }
    fclose(file);

    CHECK_EQ_INT(seen, 5);
    TEST_MAIN_END();
}
