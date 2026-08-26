# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Python implementation of the RQFT protocol from SPEC.md.

The package exposes protocol constants and pure sans-io layers shared with
librqft's wire format.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from typing import Final


def _load_package_version() -> str:
    """Return installed distribution version or source-tree fallback."""
    try:
        return distribution_version("rqft")
    except PackageNotFoundError:
        return "0.0.0"


# Installed package semantic version, derived from release Git tag.
__version__: Final = _load_package_version()

# Wire protocol version implemented by this package.
PROTOCOL_VERSION: Final = 1

# Maximum decoded frame payload bytes accepted by the protocol.
MAX_PAYLOAD: Final = 512

# Maximum COBS-encoded frame body bytes accepted by the parser.
MAX_ENCODED: Final = 523

# Maximum path bytes accepted by the session protocol.
MAX_PATH: Final = 128

# Highest send window an endpoint may buffer or advertise.
WINDOW_MAX: Final = 8
