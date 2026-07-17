#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.release import qualify


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path)
    arguments = parser.parse_args()
    evidence = json.loads(arguments.evidence.read_text(encoding="utf-8"))
    if not isinstance(evidence, dict):
        print("BLOCK: release evidence root must be an object", file=sys.stderr)
        return 2
    result = qualify(evidence)
    report = {"schema_version": 1, "qualified": result.qualified, "blockers": list(result.blockers)}
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if result.qualified:
        print("PASS: release evidence satisfies all fail-closed gates")
        return 0
    for blocker in result.blockers:
        print(f"BLOCK: {blocker}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
