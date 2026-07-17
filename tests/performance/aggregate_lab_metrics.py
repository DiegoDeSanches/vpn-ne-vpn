#!/usr/bin/env python3
"""Derive capacity/overhead/resource metrics from aggregate synthetic counters."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Mapping


ALLOWED = {
    "schema_version", "environment_class", "measurement_window_seconds",
    "application_payload_bytes", "gateway_wire_bytes", "successful_streams",
    "cpu_time_seconds", "peak_rss_bytes", "battery_energy_joules",
}


def aggregate(document: Mapping[str, object]) -> dict[str, float]:
    if set(document) - ALLOWED or document.get("schema_version") != 1:
        raise ValueError("lab counter schema mismatch")
    if document.get("environment_class") not in {"gateway_lab", "mobile_device"}:
        raise ValueError("metrics require a real gateway lab or physical mobile device")
    numeric: dict[str, float] = {}
    for key in ALLOWED - {"schema_version", "environment_class", "battery_energy_joules"}:
        value = document.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"invalid aggregate counter: {key}")
        numeric[key] = float(value)
    window = numeric["measurement_window_seconds"]
    payload = numeric["application_payload_bytes"]
    wire = numeric["gateway_wire_bytes"]
    if window <= 0 or payload <= 0 or wire < payload:
        raise ValueError("invalid measurement denominators")
    result = {
        "throughput_mbps_p50": (payload * 8.0) / window / 1_000_000.0,
        "cpu_percent_p95": (numeric["cpu_time_seconds"] / window) * 100.0,
        "memory_mb_peak": numeric["peak_rss_bytes"] / (1024.0 * 1024.0),
        "simultaneous_streams": numeric["successful_streams"],
        "gateway_capacity_streams_per_second": numeric["successful_streams"] / window,
        "protocol_overhead_percent": ((wire - payload) / payload) * 100.0,
    }
    energy = document.get("battery_energy_joules")
    if energy is not None:
        if (
            document["environment_class"] != "mobile_device"
            or not isinstance(energy, (int, float))
            or isinstance(energy, bool)
            or energy < 0
        ):
            raise ValueError("battery energy is valid only for a physical mobile device")
        result["battery_energy_joules_per_10min"] = float(energy) * (600.0 / window)
    return {name: round(value, 4) for name, value in result.items()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("counters", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()
    document = json.loads(arguments.counters.read_text(encoding="utf-8"))
    try:
        result = {"schema_version": 1, "metrics": aggregate(document)}
    except ValueError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
