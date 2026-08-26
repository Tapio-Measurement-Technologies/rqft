// SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file
 * @brief Complete public API umbrella for librqft.
 *
 * Embedded integrations normally include rqft/driver.h. Advanced hosts may
 * include rqft/session.h or individual protocol-layer headers instead.
 */
#ifndef RQFT_H
#define RQFT_H

#include "rqft/common.h"
#include "rqft/crc32.h"
#include "rqft/cobs.h"
#include "rqft/frame.h"
#include "rqft/rto.h"
#include "rqft/link.h"
#include "rqft/message.h"
#include "rqft/session.h"
#include "rqft/driver.h"

#endif /* RQFT_H */
