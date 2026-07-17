#!/usr/bin/env python3
"""Fail-closed staging, publication, and verification of GitHub Releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Sequence


MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_ASSETS = 1000
MAX_NOTES_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 60 * 60
SEMVER_TAG = re.compile(
    r"^v(?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)$"
)
CHECKSUM_LINE = re.compile(r"^(?P<digest>[0-9a-f]{64}) [ *](?P<name>[^/\\]+)$")
PAYLOAD_SUFFIXES = (
    ".aab",
    ".apk",
    ".deb",
    ".dmg",
    ".exe",
    ".msi",
    ".msix",
    ".pkg",
    ".rpm",
    ".tar.gz",
    ".tgz",
    ".zip",
)
FORBIDDEN_SUFFIXES = (
    ".env",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
    ".secret",
    ".seed",
    ".token",
)
FORBIDDEN_NAMES = {
    ".vault-token",
    "application_default_credentials.json",
    "credentials.json",
    "vault-token",
}


class ReleaseError(RuntimeError):
    """A release invariant was not satisfied."""


@dataclass(frozen=True)
class ReleaseAsset:
    path: pathlib.Path
    size: int
    sha256: str

    @property
    def name(self) -> str:
        return self.path.name


def version_from_tag(tag: str) -> str:
    match = SEMVER_TAG.fullmatch(tag)
    if not match:
        raise ReleaseError("tag must be immutable SemVer in the form vMAJOR.MINOR.PATCH[-PRERELEASE]")
    return match.group("version")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_checksums(path: pathlib.Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = CHECKSUM_LINE.fullmatch(raw_line)
        if not match:
            raise ReleaseError(f"invalid SHA256SUMS entry at line {line_number}")
        name = match.group("name")
        if name in checksums:
            raise ReleaseError(f"duplicate SHA256SUMS entry: {name}")
        checksums[name] = match.group("digest")
    if not checksums:
        raise ReleaseError("SHA256SUMS must not be empty")
    return checksums


def collect_assets(directory: pathlib.Path, tag: str) -> tuple[ReleaseAsset, ...]:
    version = version_from_tag(tag)
    directory = directory.resolve()
    if not directory.is_dir():
        raise ReleaseError(f"asset directory does not exist: {directory}")

    assets: list[ReleaseAsset] = []
    for path in sorted(directory.iterdir(), key=lambda candidate: candidate.name):
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"asset directory may contain regular files only: {path.name}")
        lower_name = path.name.lower()
        if (
            lower_name.startswith(".env")
            or lower_name in FORBIDDEN_NAMES
            or lower_name.startswith("service-account")
            or lower_name.endswith(FORBIDDEN_SUFFIXES)
        ):
            raise ReleaseError(f"secret-like release asset is forbidden: {path.name}")
        size = path.stat().st_size
        if size == 0:
            raise ReleaseError(f"empty release asset is forbidden: {path.name}")
        if size >= MAX_ASSET_BYTES:
            raise ReleaseError(f"release asset must be smaller than 2 GiB: {path.name}")
        assets.append(ReleaseAsset(path=path.resolve(), size=size, sha256=sha256_file(path)))

    if len(assets) > MAX_ASSETS:
        raise ReleaseError(f"release has more than {MAX_ASSETS} assets")

    by_name = {asset.name: asset for asset in assets}
    if len(by_name) != len(assets):
        raise ReleaseError("release asset names must be unique")
    for required in ("SHA256SUMS", "SHA256SUMS.sig"):
        if required not in by_name:
            raise ReleaseError(f"required release asset is missing: {required}")

    payloads = [asset for asset in assets if asset.name.lower().endswith(PAYLOAD_SUFFIXES)]
    if not payloads:
        raise ReleaseError("release must contain at least one packaged installer or archive")
    if not any(version in payload.name for payload in payloads):
        raise ReleaseError("at least one packaged asset name must contain the tag version")
    for payload in payloads:
        if f"{payload.name}.sig" not in by_name:
            raise ReleaseError(f"detached signature is missing for payload: {payload.name}")

    declared = _read_checksums(by_name["SHA256SUMS"].path)
    expected_names = set(by_name) - {"SHA256SUMS", "SHA256SUMS.sig"}
    if set(declared) != expected_names:
        missing = sorted(expected_names - set(declared))
        extra = sorted(set(declared) - expected_names)
        raise ReleaseError(f"SHA256SUMS asset set mismatch; missing={missing}, extra={extra}")
    for name, expected_digest in declared.items():
        if by_name[name].sha256 != expected_digest:
            raise ReleaseError(f"SHA256SUMS digest mismatch: {name}")

    return tuple(assets)


def assert_asset_sets_equal(local_assets: Sequence[ReleaseAsset], downloaded: pathlib.Path) -> None:
    remote_files = sorted(downloaded.iterdir(), key=lambda candidate: candidate.name)
    if any(path.is_symlink() or not path.is_file() for path in remote_files):
        raise ReleaseError("downloaded release contains a non-regular asset")
    local = {asset.name: (asset.size, asset.sha256) for asset in local_assets}
    remote = {path.name: (path.stat().st_size, sha256_file(path)) for path in remote_files}
    if local != remote:
        raise ReleaseError("downloaded draft assets differ from the locally verified asset set")


def _repo_arguments(repository: str | None) -> list[str]:
    return ["--repo", repository] if repository else []


def build_stage_command(
    tag: str,
    assets: Sequence[ReleaseAsset],
    notes_file: pathlib.Path,
    title: str,
    repository: str | None,
    prerelease: bool,
) -> list[str]:
    command = ["gh", "release", "create", tag]
    command.extend(str(asset.path) for asset in assets)
    command.extend(
        ["--draft", "--verify-tag", "--title", title, "--notes-file", str(notes_file.resolve())]
    )
    if prerelease:
        command.append("--prerelease")
    command.extend(_repo_arguments(repository))
    return command


def build_publish_command(tag: str, repository: str | None) -> list[str]:
    return [
        "gh",
        "release",
        "edit",
        tag,
        "--draft=false",
        "--verify-tag",
        *_repo_arguments(repository),
    ]


def _format_command(command: Sequence[str]) -> str:
    return " ".join(json.dumps(argument) if " " in argument else argument for argument in command)


def _run(command: Sequence[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=capture,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise ReleaseError(f"command timed out: {command[0]} {command[1]}") from error
    if completed.returncode != 0:
        raise ReleaseError(f"command failed with exit code {completed.returncode}: {command[0]} {command[1]}")
    return completed


def _require_tools(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise ReleaseError(f"required tools are missing: {', '.join(missing)}")


def _verify_checksum_signature(assets: Sequence[ReleaseAsset], verification_key: pathlib.Path) -> None:
    by_name = {asset.name: asset.path for asset in assets}
    _run(
        [
            "cosign",
            "verify-blob",
            "--key",
            str(verification_key.resolve()),
            "--signature",
            str(by_name["SHA256SUMS.sig"]),
            str(by_name["SHA256SUMS"]),
        ]
    )


def _verify_repository_is_clean() -> None:
    status = _run(
        ["git", "status", "--porcelain"],
        capture=True,
    ).stdout
    if status.strip():
        raise ReleaseError("tracked repository state must be clean before staging or publishing a release")


def _view_draft(tag: str, repository: str | None) -> dict[str, object]:
    command = [
        "gh",
        "release",
        "view",
        tag,
        "--json",
        "isDraft,assets,tagName",
        *_repo_arguments(repository),
    ]
    output = _run(command, capture=True).stdout
    try:
        result = json.loads(output)
    except json.JSONDecodeError as error:
        raise ReleaseError("GitHub CLI returned invalid release JSON") from error
    if not isinstance(result, dict):
        raise ReleaseError("GitHub CLI release response must be an object")
    return result


def _validate_common(arguments: argparse.Namespace) -> tuple[tuple[ReleaseAsset, ...], pathlib.Path]:
    assets = collect_assets(arguments.assets, arguments.tag)
    verification_key = arguments.verification_key.resolve()
    if not verification_key.is_file() or verification_key.is_symlink():
        raise ReleaseError("verification key must be a regular public-key file")
    return assets, verification_key


def stage(arguments: argparse.Namespace) -> None:
    assets, verification_key = _validate_common(arguments)
    notes_file = arguments.notes_file.resolve()
    if not notes_file.is_file() or notes_file.is_symlink():
        raise ReleaseError("release notes must be a regular file")
    if notes_file.stat().st_size > MAX_NOTES_BYTES:
        raise ReleaseError("release notes must not exceed 1 MiB")
    command = build_stage_command(
        arguments.tag,
        assets,
        notes_file,
        arguments.title or f"OnionRoute {arguments.tag}",
        arguments.repository,
        arguments.prerelease,
    )
    if arguments.dry_run:
        print(f"DRY RUN: {_format_command(command)}")
        return
    _require_tools("cosign", "gh", "git")
    _verify_repository_is_clean()
    _verify_checksum_signature(assets, verification_key)
    _run(["gh", "auth", "status"])
    _run(command)


def publish(arguments: argparse.Namespace) -> None:
    assets, verification_key = _validate_common(arguments)
    publish_command = build_publish_command(arguments.tag, arguments.repository)
    if arguments.dry_run:
        print(f"DRY RUN: verify draft assets for {arguments.tag}")
        print(f"DRY RUN: {_format_command(publish_command)}")
        return
    _require_tools("cosign", "gh", "git")
    _verify_repository_is_clean()
    _verify_checksum_signature(assets, verification_key)
    release = _view_draft(arguments.tag, arguments.repository)
    if release.get("tagName") != arguments.tag or release.get("isDraft") is not True:
        raise ReleaseError("target release must exist as a draft for the exact requested tag")
    remote_assets = release.get("assets")
    if not isinstance(remote_assets, list) or len(remote_assets) > MAX_ASSETS:
        raise ReleaseError("GitHub draft returned an invalid asset list")
    remote_names = {asset.get("name") for asset in remote_assets if isinstance(asset, dict)}
    local_names = {asset.name for asset in assets}
    if remote_names != local_names:
        raise ReleaseError("GitHub draft asset names differ from the locally verified set")
    with tempfile.TemporaryDirectory(prefix="onionroute-release-") as temporary_directory:
        download_command = [
            "gh",
            "release",
            "download",
            arguments.tag,
            "--dir",
            temporary_directory,
            *_repo_arguments(arguments.repository),
        ]
        _run(download_command)
        assert_asset_sets_equal(assets, pathlib.Path(temporary_directory))
    _run(publish_command)


def verify(arguments: argparse.Namespace) -> None:
    assets, verification_key = _validate_common(arguments)
    if arguments.dry_run:
        print(f"DRY RUN: gh release verify {arguments.tag}")
        for asset in assets:
            print(f"DRY RUN: gh release verify-asset {arguments.tag} {asset.path}")
        return
    _require_tools("cosign", "gh")
    _verify_checksum_signature(assets, verification_key)
    _run(["gh", "release", "verify", arguments.tag, *_repo_arguments(arguments.repository)])
    for asset in assets:
        _run(
            [
                "gh",
                "release",
                "verify-asset",
                arguments.tag,
                str(asset.path),
                *_repo_arguments(arguments.repository),
            ]
        )


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tag", required=True)
    parser.add_argument("--assets", required=True, type=pathlib.Path)
    parser.add_argument("--verification-key", required=True, type=pathlib.Path)
    parser.add_argument("--repo", dest="repository")
    parser.add_argument("--dry-run", action="store_true")


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    stage_parser = subparsers.add_parser("stage", help="create a draft release and upload assets")
    _add_common_arguments(stage_parser)
    stage_parser.add_argument("--notes-file", required=True, type=pathlib.Path)
    stage_parser.add_argument("--title")
    stage_parser.add_argument("--prerelease", action="store_true")
    stage_parser.set_defaults(handler=stage)

    publish_parser = subparsers.add_parser("publish", help="verify and publish an existing draft")
    _add_common_arguments(publish_parser)
    publish_parser.set_defaults(handler=publish)

    verify_parser = subparsers.add_parser("verify", help="verify immutable-release attestations")
    _add_common_arguments(verify_parser)
    verify_parser.set_defaults(handler=verify)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = parse_arguments(argv)
        arguments.handler(arguments)
    except ReleaseError as error:
        print(f"BLOCK: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
