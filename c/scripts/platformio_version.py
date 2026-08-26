# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Inject library version into PlatformIO compilation."""

import json
import re
import subprocess
from pathlib import Path

Import("env", "pio_lib_builder")

_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_TAG_PATTERN = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

library_root = Path(pio_lib_builder.path)
manifest = json.loads((library_root / "library.json").read_text(encoding="utf-8"))
version = str(manifest["version"])

if version == "0.0.0":
    result = subprocess.run(
        ("git", "-C", str(library_root), "tag", "--points-at", "HEAD"),
        check=False,
        capture_output=True,
        text=True,
    )
    release_tags = [
        tag
        for tag in result.stdout.splitlines()
        if _TAG_PATTERN.fullmatch(tag) is not None
    ]
    if len(release_tags) == 1:
        version = release_tags[0][1:]

match = _VERSION_PATTERN.fullmatch(version)
if match is None:
    raise ValueError(f"RQFT version must match MAJOR.MINOR.PATCH: {version!r}")

major, minor, patch = (int(part) for part in match.groups())
env.AppendUnique(
    CPPDEFINES=[
        ("RQFT_LIB_VERSION_MAJOR", major),
        ("RQFT_LIB_VERSION_MINOR", minor),
        ("RQFT_LIB_VERSION_PATCH", patch),
        ("RQFT_LIB_VERSION_STRING", env.StringifyMacro(version)),
    ]
)
