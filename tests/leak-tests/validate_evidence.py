#!/usr/bin/env python3
"""Require complete pcap evidence for a platform/mode/state/vector matrix."""

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
    parser.add_argument("--platform", required=True)
    arguments = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent
    matrix = json.loads((root / "scenario-matrix.json").read_text(encoding="utf-8"))
    analyzer = root / "mobile/assert_no_leaks.py"
    failures: list[str] = []
    for mode in matrix["modes"]:
        for state in matrix["states"]:
            for vector in matrix["vectors"]:
                case = arguments.evidence / arguments.platform / mode / state / vector["id"]
                result_path = case / "result.json"
                pcap_path = case / "physical.pcapng"
                if not result_path.is_file() or not pcap_path.is_file():
                    failures.append(f"missing evidence: {mode}/{state}/{vector['id']}")
                    continue
                result = json.loads(result_path.read_text(encoding="utf-8"))
                if result.get("schema_version") != 1 or result.get("passed") is not True:
                    failures.append(f"case did not pass: {mode}/{state}/{vector['id']}")
                assertions = result.get("assertions", {})
                if any(assertions.get(name) is not True for name in vector["required"]):
                    failures.append(f"required assertion missing: {mode}/{state}/{vector['id']}")
                completed = subprocess.run(
                    [sys.executable, str(analyzer), str(pcap_path), str(arguments.policy)],
                    check=False,
                )
                if completed.returncode != 0:
                    failures.append(f"pcap rejected: {mode}/{state}/{vector['id']}")
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if not failures:
        print(f"PASS: complete leak evidence matrix for {arguments.platform}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
