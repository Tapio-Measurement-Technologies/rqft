# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Release-version parsing and C package preparation tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from tools.release import (
    ReleaseVersion,
    discover_release_tag,
    parse_release_tag,
    prepare_release_assets,
    prepare_c_package,
)


def test_parse_release_tag() -> None:
    assert parse_release_tag("v12.34.56") == ReleaseVersion(
        tag="v12.34.56",
        value="12.34.56",
        major=12,
        minor=34,
        patch=56,
    )


@pytest.mark.parametrize(
    "tag",
    ("1.2.3", "v1.2", "v1.2.3-rc1", "version-1.2.3", "v01.2.3"),
)
def test_parse_release_tag_rejects_non_release_tags(tag: str) -> None:
    with pytest.raises(ValueError, match="vMAJOR.MINOR.PATCH"):
        parse_release_tag(tag)


def test_discover_release_tag_at_head(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(("git", "init", "-q", str(repository)), check=True)
    subprocess.run(
        ("git", "-C", str(repository), "config", "user.name", "RQFT Test"),
        check=True,
    )
    subprocess.run(
        (
            "git",
            "-C",
            str(repository),
            "config",
            "user.email",
            "rqft-test@example.invalid",
        ),
        check=True,
    )
    (repository / "tracked").write_text("release\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(repository), "add", "tracked"), check=True)
    subprocess.run(
        ("git", "-C", str(repository), "commit", "-q", "-m", "Release"),
        check=True,
    )
    subprocess.run(
        ("git", "-C", str(repository), "tag", "v7.8.9"),
        check=True,
    )

    assert discover_release_tag(repository) == ReleaseVersion(
        tag="v7.8.9",
        value="7.8.9",
        major=7,
        minor=8,
        patch=9,
    )


def test_prepare_c_package_injects_version_and_excludes_tests(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    (source / "src").mkdir(parents=True)
    (source / "include" / "rqft").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "build-local").mkdir()
    (source / "src" / "version.cpp").write_text("source\n", encoding="utf-8")
    (source / "include" / "rqft" / "version.h").write_text(
        "development version\n",
        encoding="utf-8",
    )
    (source / "tests" / "test_version.c").write_text("test\n", encoding="utf-8")
    (source / "build-local" / "cache").write_text("cache\n", encoding="utf-8")
    (source / "library.json").write_text(
        json.dumps(
            {
                "name": "rqft",
                "version": "0.0.0",
                "build": {"flags": ["-std=gnu++17"]},
            }
        ),
        encoding="utf-8",
    )

    version = parse_release_tag("v2.3.4")
    prepare_c_package(source, output, version)

    manifest = json.loads((output / "library.json").read_text(encoding="utf-8"))
    assert manifest["version"] == "2.3.4"
    assert manifest["build"]["flags"] == ["-std=gnu++17"]
    assert (output / "VERSION").read_text(encoding="ascii") == "2.3.4\n"
    version_header = (output / "include" / "rqft" / "version.h").read_text(
        encoding="utf-8"
    )
    assert "#define RQFT_LIB_VERSION_MAJOR 2" in version_header
    assert "#define RQFT_LIB_VERSION_MINOR 3" in version_header
    assert "#define RQFT_LIB_VERSION_PATCH 4" in version_header
    assert '#define RQFT_LIB_VERSION_STRING "2.3.4"' in version_header
    assert (output / "src" / "version.cpp").is_file()
    assert not (output / "tests").exists()
    assert not (output / "build-local").exists()
    source_manifest = json.loads(
        (source / "library.json").read_text(encoding="utf-8")
    )
    assert source_manifest["version"] == "0.0.0"


def test_prepare_release_assets_copies_packages_and_writes_checksums(
    tmp_path: Path,
) -> None:
    version = parse_release_tag("v2.3.4")
    python_dist = tmp_path / "python-dist"
    python_dist.mkdir()
    packages = {
        "rqft-2.3.4-py3-none-any.whl": b"wheel\n",
        "rqft-2.3.4.tar.gz": b"sdist\n",
    }
    for name, content in packages.items():
        (python_dist / name).write_bytes(content)
    platformio_archive = tmp_path / "rqft-platformio-2.3.4.tar.gz"
    packages[platformio_archive.name] = b"platformio\n"
    platformio_archive.write_bytes(packages[platformio_archive.name])
    output = tmp_path / "release-assets"

    prepare_release_assets(
        python_dist,
        platformio_archive,
        output,
        version,
    )

    assert {
        path.name for path in output.iterdir()
    } == set(packages) | {"SHA256SUMS"}
    for name, content in packages.items():
        assert (output / name).read_bytes() == content
    expected_checksums = "".join(
        f"{hashlib.sha256(packages[name]).hexdigest()}  {name}\n"
        for name in sorted(packages)
    )
    assert (output / "SHA256SUMS").read_text(
        encoding="ascii"
    ) == expected_checksums


def test_prepare_release_assets_requires_all_packages(tmp_path: Path) -> None:
    version = parse_release_tag("v2.3.4")
    python_dist = tmp_path / "python-dist"
    python_dist.mkdir()
    (python_dist / "rqft-2.3.4.tar.gz").write_bytes(b"sdist\n")
    platformio_archive = tmp_path / "rqft-platformio-2.3.4.tar.gz"
    platformio_archive.write_bytes(b"platformio\n")
    output = tmp_path / "release-assets"

    with pytest.raises(
        FileNotFoundError,
        match="rqft-2.3.4-py3-none-any.whl",
    ):
        prepare_release_assets(
            python_dist,
            platformio_archive,
            output,
            version,
        )

    assert not output.exists()
