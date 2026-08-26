// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_rto.c - adaptive RTO estimator tests for SPEC.md section 4.4. */
#include "rqft/rto.h"
#include "test_support.h"

#include <stdint.h>
#include <stdlib.h>

static int field_int(const char *line, const char *field)
{
    const char *key = strstr(line, field);
    CHECK(key != NULL);
    if (key == NULL) {
        return 0;
    }
    return (int)strtol(key + strlen(field), NULL, 10);
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

static void test_initial_state_before_any_sample(void)
{
    rqft_rto_t rto;
    rqft_rto_init(&rto);

    CHECK_EQ_INT(rto.srtt_ms, -1);
    CHECK_EQ_INT(rto.rttvar_ms, 0);
    CHECK_EQ_INT(rto.rto_ms, RQFT_RTO_INITIAL_MS);
    CHECK_EQ_INT(RQFT_RTO_MIN_MS, 100);
    CHECK_EQ_INT(RQFT_RTO_MAX_MS, 3000);
}

static void test_golden_vectors(void)
{
    FILE *file = fopen(RQFT_REPO_ROOT "/testvectors/rto.json", "r");
    CHECK(file != NULL);
    if (file == NULL) {
        return;
    }

    char line[300];
    char current_case[64] = "";
    char line_case[64];
    unsigned int cases = 0u;
    unsigned int steps = 0u;
    rqft_rto_t rto;

    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "\"case\":") == NULL) {
            continue;
        }
        field_str(line, "\"case\":", line_case, sizeof(line_case));
        if (strcmp(line_case, current_case) != 0) {
            strcpy(current_case, line_case);
            rqft_rto_init(&rto);
            cases++;
        }

        rqft_rto_sample(&rto, (uint32_t)field_int(line, "\"rtt\":"));
        CHECK_EQ_INT(rto.srtt_ms, field_int(line, "\"srtt\":"));
        CHECK_EQ_INT(rto.rttvar_ms, field_int(line, "\"rttvar\":"));
        CHECK_EQ_INT(rto.rto_ms, field_int(line, "\"rto\":"));
        steps++;
    }
    fclose(file);
    CHECK_EQ_INT(cases, 6);
    CHECK_EQ_INT(steps, 29);
}

int main(void)
{
    test_initial_state_before_any_sample();
    test_golden_vectors();
    TEST_MAIN_END();
}
