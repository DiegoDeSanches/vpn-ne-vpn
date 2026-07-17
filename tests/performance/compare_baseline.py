#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.performance import compare_metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=pathlib.Path)
    parser.add_argument("observed", type=pathlib.Path)
    parser.add_argument("--tier", choices=("all", "gateway_lab", "mobile_device"), default="all")
    arguments = parser.parse_args()
    policy = json.loads((pathlib.Path(__file__).parent / "thresholds.json").read_text(encoding="utf-8"))
    baseline = json.loads(arguments.baseline.read_text(encoding="utf-8"))
    observed = json.loads(arguments.observed.read_text(encoding="utf-8"))
    if baseline.get("environment_fingerprint") != observed.get("environment_fingerprint"):
        print("FAIL: baseline and observation environments differ", file=sys.stderr)
        return 2
    if arguments.tier != "all" and baseline.get("environment_fingerprint", {}).get("class") == "simulation":
        print("FAIL: simulation baseline cannot satisfy device or gateway lab tiers", file=sys.stderr)
        return 2
    if baseline.get("sample_count", 0) < policy["minimum_baseline_samples"]:
        print("FAIL: baseline has too few samples", file=sys.stderr)
        return 2
    selected = {
        name: item for name, item in policy["metrics"].items()
        if item["tier"] in {"all", arguments.tier}
    }
    regressions = compare_metrics(baseline["metrics"], observed["metrics"], selected)
    for regression in regressions:
        print(
            f"FAIL {regression.metric}: observed={regression.observed:.3f} "
            f"baseline={regression.baseline:.3f} limit={regression.limit:.3f}"
        )
    if not regressions:
        print("PASS: no performance regression beyond the environment-matched thresholds")
    return 1 if regressions else 0


if __name__ == "__main__":
    raise SystemExit(main())
