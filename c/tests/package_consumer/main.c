// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

#include <rqft/rqft.h>

#include <string.h>

int main(void)
{
    return strcmp(rqft_lib_version(), RQFT_LIB_VERSION_STRING) == 0 ? 0 : 1;
}
