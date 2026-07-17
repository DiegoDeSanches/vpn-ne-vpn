#!/usr/bin/env python3
"""Scan exported JSON/reports for identity dimensions and synthetic canaries."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Iterable


FORBIDDEN_KEYS = {
    "ip", "ip_address", "source_ip", "client_ip", "domain", "hostname",
    "destination", "destination_address", "destination_port", "account_id",
    "token_id", "device_id", "stable_device_id", "user_id", "timeline", "timestamp",
}


def forbidden_json_paths(value: object, prefix: str = "$") -> list[str]:
    failures: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}"
            if str(key).lower() in FORBIDDEN_KEYS:
                failures.append(path)
            failures.extend(forbidden_json_paths(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            failures.extend(forbidden_json_paths(child, f"{prefix}[{index}]"))
    return failures


def scan(paths: Iterable[pathlib.Path], canaries: list[bytes]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        data = path.read_bytes()
        for index, canary in enumerate(canaries):
            if canary and canary in data:
                failures.append(f"{path.name}: canary-{index} present")
        if path.suffix.lower() == ".json":
            try:
                document = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError):
                failures.append(f"{path.name}: invalid JSON")
                continue
            for forbidden_path in forbidden_json_paths(document):
                failures.append(f"{path.name}: forbidden field at {forbidden_path}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=pathlib.Path)
    parser.add_argument("--canary", action="append", default=[])
    arguments = parser.parse_args()
    missing = [path for path in arguments.paths if not path.is_file()]
    if missing:
        print("FAIL: one or more artifact paths are missing", file=sys.stderr)
        return 2
    failures = scan(arguments.paths, [value.encode("utf-8") for value in arguments.canary])
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if not failures:
        print("PASS: exported artifacts contain no forbidden dimensions or supplied canaries")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
