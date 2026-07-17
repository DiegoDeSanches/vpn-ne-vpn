from __future__ import annotations

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from qa_harness.performance import compare_metrics
from aggregate_lab_metrics import aggregate


class PerformanceRegressionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        document = json.loads((pathlib.Path(__file__).parent / "thresholds.json").read_text(encoding="utf-8"))
        self.thresholds = document["metrics"]

    def test_every_required_metric_has_a_relative_regression_policy(self) -> None:
        expected = {
            "tor_bootstrap_time_ms_p95", "connect_time_ms_p95", "time_to_first_byte_ms_p95",
            "latency_ms_p95", "throughput_mbps_p50", "cpu_percent_p95", "memory_mb_peak",
            "battery_energy_joules_per_10min", "simultaneous_streams", "reconnect_time_ms_p95",
            "rotation_time_ms_p95", "gateway_capacity_streams_per_second", "protocol_overhead_percent",
        }
        self.assertEqual(set(self.thresholds), expected)
        for policy in self.thresholds.values():
            self.assertIn(policy["direction"], {"lower", "higher"})
            self.assertGreater(policy["relative"], 0)

    def test_comparator_allows_noise_and_blocks_a_real_regression(self) -> None:
        policies = {"connect": {"direction": "lower", "relative": 0.25, "absolute": 10}}
        self.assertEqual(compare_metrics({"connect": 100}, {"connect": 130}, policies), [])
        regressions = compare_metrics({"connect": 100}, {"connect": 140}, policies)
        self.assertEqual([item.metric for item in regressions], ["connect"])

    def test_higher_is_better_metrics_regress_downward(self) -> None:
        policies = {"throughput": {"direction": "higher", "relative": 0.15, "absolute": 0}}
        self.assertEqual(compare_metrics({"throughput": 100}, {"throughput": 90}, policies), [])
        self.assertEqual(len(compare_metrics({"throughput": 100}, {"throughput": 80}, policies)), 1)

    def test_committed_mock_baseline_is_large_enough_and_cannot_claim_release(self) -> None:
        baseline_path = pathlib.Path(__file__).parent / "baselines/mock-loopback-windows-amd64-python312.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        self.assertGreaterEqual(baseline["sample_count"], 30)
        self.assertEqual(baseline["environment_fingerprint"]["class"], "simulation")
        self.assertIn("never valid for product release", baseline["qualification"])
        self.assertIn("battery_energy_joules_per_10min", baseline["unavailable_metrics"])

    def test_lab_counter_aggregation_measures_capacity_and_protocol_overhead(self) -> None:
        counters = {
            "schema_version": 1,
            "environment_class": "gateway_lab",
            "measurement_window_seconds": 10.0,
            "application_payload_bytes": 1_000_000,
            "gateway_wire_bytes": 1_050_000,
            "successful_streams": 100,
            "cpu_time_seconds": 2.0,
            "peak_rss_bytes": 104_857_600,
        }
        metrics = aggregate(counters)
        self.assertEqual(metrics["protocol_overhead_percent"], 5.0)
        self.assertEqual(metrics["gateway_capacity_streams_per_second"], 10.0)
        self.assertEqual(metrics["memory_mb_peak"], 100.0)

    def test_lab_counter_schema_rejects_destination_dimensions(self) -> None:
        counters = {
            "schema_version": 1,
            "environment_class": "gateway_lab",
            "measurement_window_seconds": 1,
            "application_payload_bytes": 1,
            "gateway_wire_bytes": 1,
            "successful_streams": 1,
            "cpu_time_seconds": 1,
            "peak_rss_bytes": 1,
            "destination": "forbidden.invalid",
        }
        with self.assertRaises(ValueError):
            aggregate(counters)


if __name__ == "__main__":
    unittest.main()
