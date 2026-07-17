#!/usr/bin/env python3
"""Capture an aggregated Mock Tor baseline.

This benchmark is useful for harness regressions only. Real Tor, gateway, OS,
mobile battery, and multi-region baselines must be captured in their matching
environments and can never be replaced by these numbers.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import platform
import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.mock_route import MockRouteEnvironment
from qa_harness.model import AnonymityMode


def percentile(samples: list[float], quantile: float) -> float:
    if not samples:
        raise ValueError("cannot aggregate empty sample set")
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * quantile + 0.999999)))
    return ordered[index]


async def capture(runs: int, concurrent_streams: int) -> dict[str, object]:
    bootstraps: list[float] = []
    connects: list[float] = []
    first_bytes: list[float] = []
    latencies: list[float] = []
    throughputs: list[float] = []
    reconnects: list[float] = []
    rotations: list[float] = []
    cpu_samples: list[float] = []
    payload = b"p" * (256 * 1024)

    tracemalloc.start()
    for _ in range(runs):
        run_wall_started = time.perf_counter()
        run_cpu_started = time.process_time()
        async with MockRouteEnvironment(AnonymityMode.STANDARD) as environment:
            evidence = await environment.probe(payload)
            bootstraps.append(evidence.bootstrap_ms)
            connects.append(evidence.connect_ms)
            first_bytes.append(evidence.time_to_first_byte_ms)
            latencies.append(evidence.total_ms)
            transfer_seconds = max((evidence.total_ms - evidence.connect_ms) / 1000.0, 0.000001)
            throughputs.append((evidence.bytes_round_trip * 8.0) / transfer_seconds / 1_000_000.0)
            rotation_started = time.perf_counter()
            await environment.probe(b"rotation-probe")
            rotations.append((time.perf_counter() - rotation_started) * 1000.0)
        reconnect_started = time.perf_counter()
        async with MockRouteEnvironment(AnonymityMode.STANDARD) as replacement:
            await replacement.probe(b"reconnect-probe")
        reconnects.append((time.perf_counter() - reconnect_started) * 1000.0)
        run_wall = max(time.perf_counter() - run_wall_started, 0.000001)
        cpu_samples.append(((time.process_time() - run_cpu_started) / run_wall) * 100.0)

    async with MockRouteEnvironment(AnonymityMode.STANDARD) as capacity_environment:
        capacity_started = time.perf_counter()
        results = await asyncio.gather(
            *(capacity_environment.probe(b"capacity-probe") for _ in range(concurrent_streams))
        )
        capacity_seconds = max(time.perf_counter() - capacity_started, 0.000001)
    current_memory, peak_memory = tracemalloc.get_traced_memory()
    del current_memory
    tracemalloc.stop()
    return {
        "schema_version": 1,
        "environment_fingerprint": {
            "class": "simulation",
            "os_family": platform.system().lower(),
            "architecture": platform.machine().lower(),
            "hardware_class": "developer-workstation",
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "profile": "mock-loopback-v1"
        },
        "sample_count": runs,
        "metrics": {
            "tor_bootstrap_time_ms_p95": round(percentile(bootstraps, 0.95), 3),
            "connect_time_ms_p95": round(percentile(connects, 0.95), 3),
            "time_to_first_byte_ms_p95": round(percentile(first_bytes, 0.95), 3),
            "latency_ms_p95": round(percentile(latencies, 0.95), 3),
            "throughput_mbps_p50": round(statistics.median(throughputs), 3),
            "cpu_percent_p95": round(percentile(cpu_samples, 0.95), 3),
            "memory_mb_peak": round(peak_memory / (1024.0 * 1024.0), 3),
            "reconnect_time_ms_p95": round(percentile(reconnects, 0.95), 3),
            "rotation_time_ms_p95": round(percentile(rotations, 0.95), 3),
            "simultaneous_streams": float(len(results)),
            "gateway_capacity_streams_per_second": round(len(results) / capacity_seconds, 3)
        },
        "unavailable_metrics": {
            "battery_energy_joules_per_10min": "requires a physical Android/iOS device power harness",
            "protocol_overhead_percent": "requires application and gateway-v1 wire counters in gateway_lab"
        },
        "qualification": "mock baseline only; never valid for product release"
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--concurrent-streams", type=int, default=16)
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()
    if arguments.runs < 3 or arguments.concurrent_streams < 1:
        parser.error("runs must be >= 3 and concurrent streams must be >= 1")
    result = asyncio.run(capture(arguments.runs, arguments.concurrent_streams))
    rendered = json.dumps(result, indent=2) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
