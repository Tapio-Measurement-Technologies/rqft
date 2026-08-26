// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/*
 * test_support.h - minimal assert-based test harness for librqft ctest
 * binaries. No framework dependency: each test file is a standalone
 * executable; a non-zero exit or abort fails the test.
 */
#ifndef RQFT_TEST_SUPPORT_H
#define RQFT_TEST_SUPPORT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int rqft_test_failures = 0;

#define CHECK(cond)                                                                     \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);             \
            rqft_test_failures++;                                                       \
        }                                                                               \
    } while (0)

#define CHECK_EQ_INT(a, b)                                                              \
    do {                                                                                \
        long long _a = (long long)(a), _b = (long long)(b);                             \
        if (_a != _b) {                                                                 \
            fprintf(stderr, "FAIL %s:%d: %s == %s (%lld != %lld)\n", __FILE__,          \
                    __LINE__, #a, #b, _a, _b);                                          \
            rqft_test_failures++;                                                       \
        }                                                                               \
    } while (0)

#define CHECK_EQ_STR(a, b)                                                              \
    do {                                                                                \
        const char *_a = (a), *_b = (b);                                                \
        if (strcmp(_a, _b) != 0) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s == %s (\"%s\" != \"%s\")\n", __FILE__,      \
                    __LINE__, #a, #b, _a, _b);                                          \
            rqft_test_failures++;                                                       \
        }                                                                               \
    } while (0)

#define TEST_MAIN_END()                                                                 \
    do {                                                                                \
        if (rqft_test_failures) {                                                       \
            fprintf(stderr, "%d check(s) failed\n", rqft_test_failures);                \
            return 1;                                                                   \
        }                                                                               \
        printf("OK\n");                                                                 \
        return 0;                                                                       \
    } while (0)

#endif /* RQFT_TEST_SUPPORT_H */
