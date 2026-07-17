#!/usr/bin/env python3
"""Validate that every mobile scenario has fail-closed evidence and clean pcap."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    parser.add_argument("--policy", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent
    matrix = json.loads((root / "scenario-matrix.json").read_text(encoding="utf-8"))
    failures: list[str] = []

    for scenario in matrix["scenarios"]:
        for platform in matrix["platforms"]:
            case = arguments.evidence / f"{scenario['id']}-{platform}"
            result_path = case / "result.json"
            pcap_path = case / "physical.pcapng"
            if not result_path.is_file() or not pcap_path.is_file():
                failures.append(f"{case.name}: missing result.json or physical.pcapng")
                continue
            result = json.loads(result_path.read_text(encoding="utf-8"))
            if result.get("scenario") != scenario["id"] or result.get("platform") != platform:
                failures.append(f"{case.name}: evidence identity mismatch")
            observed = result.get("assertions", {})
            for required in scenario["required"]:
                if observed.get(required) is not True:
                    failures.append(f"{case.name}: assertion not true: {required}")
            check = subprocess.run(
                [sys.executable, str(root / "assert_no_leaks.py"), str(pcap_path), str(arguments.policy)],
                check=False,
            )
            if check.returncode != 0:
                failures.append(f"{case.name}: pcap policy failed")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("PASS: complete Android/iOS mobile leak matrix")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

