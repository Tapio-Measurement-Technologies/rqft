// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/* test_version.c - library links, header constants are sane, version string matches macros. */
#include "rqft/common.h"
#include "test_support.h"

int main(void)
{
    CHECK_EQ_STR(rqft_lib_version(), RQFT_LIB_VERSION_STRING);
    CHECK_EQ_INT(RQFT_PROTOCOL_VERSION, 1);
    CHECK_EQ_INT(RQFT_MAX_PAYLOAD, 512);
    /* max decoded = 4 hdr + payload + 4 crc; COBS overhead = ceil(520/254) */
    CHECK_EQ_INT(RQFT_MAX_ENCODED, 4 + RQFT_MAX_PAYLOAD + 4 + 3);
    TEST_MAIN_END();
}
