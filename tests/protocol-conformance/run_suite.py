#!/usr/bin/env python3
"""Run black-box Rust conformance suites and write a privacy-safe report."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import time


ROOT = pathlib.Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=pathlib.Path, default=ROOT / "test-results/protocol-conformance.json")
    parser.add_argument("--include-daemon", action="store_true")
    parser.add_argument("--cargo", default=os.environ.get("CARGO") or shutil.which("cargo"))
    arguments = parser.parse_args()
    if not arguments.cargo:
        parser.error("cargo was not found; provide --cargo or set CARGO")
    manifest = json.loads((pathlib.Path(__file__).parent / "manifest.json").read_text(encoding="utf-8"))
    selected = [
        suite for suite in manifest["suites"]
        if arguments.include_daemon or "gateway-daemon" not in suite["manifest"]
    ]
    results: list[dict[str, object]] = []
    failed = False
    for suite in selected:
        command = [
            arguments.cargo, "test", "--quiet", "--manifest-path", suite["manifest"],
            "--test", suite["test"],
        ]
        started = time.monotonic()
        completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True)
        duration_ms = round((time.monotonic() - started) * 1000.0, 3)
        passed = completed.returncode == 0
        failed |= not passed
        results.append({"id": suite["id"], "passed": passed, "duration_ms": duration_ms})
        print(f"{'PASS' if passed else 'FAIL'} {suite['id']} ({duration_ms:.1f} ms)")
    report = {
        "schema_version": 1,
        "suite": "gateway-v1-protocol-conformance",
        "passed": not failed,
        "results": results,
    }
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
