# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Pytest path setup for interop tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_SRC = ROOT / "python" / "src"

if str(PY_SRC) not in sys.path:
    sys.path.insert(0, str(PY_SRC))
