// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Library version API for the SPEC.md version 1 implementation.
 */
#include "rqft/common.h"

const char *rqft_lib_version(void)
{
    return RQFT_LIB_VERSION_STRING;
}
