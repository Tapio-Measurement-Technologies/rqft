# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve release tags and prepare versioned C distribution sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence, cast

_TAG_PATTERN = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)

_VERSION_HEADER_TEMPLATE = """\
/**
 * @file
 * @brief Library version generated from release Git tag.
 */
#ifndef RQFT_VERSION_H
#define RQFT_VERSION_H

#ifndef RQFT_LIB_VERSION_MAJOR
#define RQFT_LIB_VERSION_MAJOR {major}
#endif
#ifndef RQFT_LIB_VERSION_MINOR
#define RQFT_LIB_VERSION_MINOR {minor}
#endif
#ifndef RQFT_LIB_VERSION_PATCH
#define RQFT_LIB_VERSION_PATCH {patch}
#endif
#ifndef RQFT_LIB_VERSION_STRING
#define RQFT_LIB_VERSION_STRING "{value}"
#endif

#endif /* RQFT_VERSION_H */
"""


@dataclass(frozen=True)
class ReleaseVersion:
    """Semantic release version parsed from one Git tag."""

    tag: str
    value: str
    major: int
    minor: int
    patch: int


def parse_release_tag(tag: str) -> ReleaseVersion:
    """Parse strict ``vMAJOR.MINOR.PATCH`` release tag.

    Args:
        tag: Git tag to parse.

    Returns:
        Parsed semantic version and numeric components.

    Raises:
        ValueError: Tag is not strict three-component release tag.
    """
    match = _TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ValueError(f"release tag must match vMAJOR.MINOR.PATCH: {tag!r}")
    major, minor, patch = (int(part) for part in match.groups())
    return ReleaseVersion(
        tag=tag,
        value=f"{major}.{minor}.{patch}",
        major=major,
        minor=minor,
        patch=patch,
    )


def discover_release_tag(repository: Path) -> ReleaseVersion:
    """Return unique release tag pointing at repository HEAD.

    Args:
        repository: Git worktree or subdirectory inside it.

    Returns:
        Unique strict release tag attached to HEAD.

    Raises:
        ValueError: HEAD has zero or multiple strict release tags.
        subprocess.CalledProcessError: Git cannot inspect repository.
    """
    result = subprocess.run(
        ("git", "-C", str(repository), "tag", "--points-at", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    )
    versions: list[ReleaseVersion] = []
    for candidate in result.stdout.splitlines():
        try:
            versions.append(parse_release_tag(candidate))
        except ValueError:
            continue
    if len(versions) != 1:
        tags = ", ".join(version.tag for version in versions) or "none"
        raise ValueError(
            f"HEAD must have exactly one vMAJOR.MINOR.PATCH tag; found {tags}"
        )
    return versions[0]


def prepare_c_package(
    source: Path,
    output: Path,
    version: ReleaseVersion,
) -> None:
    """Copy C distribution sources and inject release version.

    Args:
        source: C library source directory.
        output: New staging directory to create.
        version: Release version written into package metadata.

    Raises:
        FileExistsError: Output already exists.
        FileNotFoundError: Source manifest is missing.
        ValueError: Source manifest is not a JSON object.
    """
    source_root = source.resolve()

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = {
            name
            for name in names
            if name == "__pycache__" or name.endswith((".pyc", ".pyo"))
        }
        if Path(directory).resolve() == source_root:
            ignored.update(
                name
                for name in names
                if name == "tests" or name == "build" or name.startswith("build-")
            )
        return ignored

    shutil.copytree(source, output, ignore=ignore)
    manifest_path = output / "library.json"
    manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest_data, dict):
        raise ValueError("c/library.json must contain a JSON object")
    manifest = cast(dict[str, object], manifest_data)
    manifest["version"] = version.value
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "VERSION").write_text(version.value + "\n", encoding="ascii")
    (output / "include" / "rqft" / "version.h").write_text(
        _VERSION_HEADER_TEMPLATE.format(
            major=version.major,
            minor=version.minor,
            patch=version.patch,
            value=version.value,
        ),
        encoding="utf-8",
    )


def prepare_release_assets(
    python_dist: Path,
    platformio_archive: Path,
    output: Path,
    version: ReleaseVersion,
) -> None:
    """Collect release packages and write their SHA-256 checksums.

    Args:
        python_dist: Directory containing versioned Python wheel and sdist.
        platformio_archive: Versioned PlatformIO package archive.
        output: New release-asset directory to create.
        version: Release version expected in every package filename.

    Raises:
        FileExistsError: Output already exists.
        FileNotFoundError: An expected package does not exist.
        ValueError: PlatformIO archive name does not match release version.
    """
    sources = (
        python_dist / f"rqft-{version.value}-py3-none-any.whl",
        python_dist / f"rqft-{version.value}.tar.gz",
        platformio_archive,
    )
    expected_platformio_name = (
        f"rqft-platformio-{version.value}.tar.gz"
    )
    if platformio_archive.name != expected_platformio_name:
        raise ValueError(
            f"expected PlatformIO archive named {expected_platformio_name}: "
            f"{platformio_archive}"
        )
    for source in sources:
        if not source.is_file():
            raise FileNotFoundError(source)

    output.mkdir()
    targets: list[Path] = []
    for source in sources:
        target = output / source.name
        shutil.copy2(source, target)
        targets.append(target)

    checksum_lines: list[str] = []
    for target in sorted(targets, key=lambda path: path.name):
        with target.open("rb") as package:
            digest = hashlib.file_digest(package, "sha256").hexdigest()
        checksum_lines.append(f"{digest}  {target.name}\n")
    (output / "SHA256SUMS").write_text(
        "".join(checksum_lines),
        encoding="ascii",
    )


def _resolve_version(tag: str | None, repository: Path) -> ReleaseVersion:
    """Resolve explicit tag or inspect repository HEAD."""
    return parse_release_tag(tag) if tag is not None else discover_release_tag(repository)


def _create_parser() -> argparse.ArgumentParser:
    """Build release command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser(
        "version",
        help="print version from explicit tag or tag at HEAD",
    )
    version_parser.add_argument("--tag")
    version_parser.add_argument("--repository", type=Path, default=Path("."))

    package_parser = subparsers.add_parser(
        "prepare-c",
        help="prepare versioned C/PlatformIO package source",
    )
    package_parser.add_argument("--tag")
    package_parser.add_argument("--repository", type=Path, default=Path("."))
    package_parser.add_argument("--source", type=Path, default=Path("c"))
    package_parser.add_argument("--output", type=Path, required=True)

    assets_parser = subparsers.add_parser(
        "prepare-assets",
        help="collect versioned packages for a GitHub release",
    )
    assets_parser.add_argument("--tag")
    assets_parser.add_argument("--repository", type=Path, default=Path("."))
    assets_parser.add_argument(
        "--python-dist",
        type=Path,
        default=Path("python/dist"),
    )
    assets_parser.add_argument(
        "--platformio-archive",
        type=Path,
        required=True,
    )
    assets_parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run release helper command.

    Args:
        argv: Command arguments without program name, or ``None`` for process
            arguments.

    Returns:
        Zero on success.
    """
    parser = _create_parser()
    args = parser.parse_args(argv)
    try:
        version = _resolve_version(args.tag, args.repository)
        if args.command == "version":
            print(version.value)
        elif args.command == "prepare-c":
            prepare_c_package(args.source, args.output, version)
        elif args.command == "prepare-assets":
            prepare_release_assets(
                args.python_dist,
                args.platformio_archive,
                args.output,
                version,
            )
        else:
            parser.error(f"unknown command: {args.command}")
    except (FileNotFoundError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
