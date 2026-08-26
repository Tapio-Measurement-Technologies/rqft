# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Package import smoke test and protocol constant checks."""

from importlib.metadata import version

import rqft


def test_version() -> None:
    assert rqft.__version__ == version("rqft")


def test_protocol_constants() -> None:
    assert rqft.PROTOCOL_VERSION == 1
    assert rqft.MAX_PAYLOAD == 512
    # max decoded = 4 header + payload + 4 crc; COBS overhead = ceil(520/254)
    assert rqft.MAX_ENCODED == 4 + rqft.MAX_PAYLOAD + 4 + 3
    assert rqft.MAX_PATH == 128
