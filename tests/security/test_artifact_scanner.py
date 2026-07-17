from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from scan_privacy_artifacts import forbidden_json_paths


class ArtifactScannerTests(unittest.TestCase):
    def test_nested_forbidden_dimensions_are_found(self) -> None:
        document = {"metrics": [{"labels": {"destination_address": "synthetic"}}]}
        self.assertEqual(
            forbidden_json_paths(document),
            ["$.metrics[0].labels.destination_address"],
        )

    def test_closed_aggregate_report_has_no_forbidden_key(self) -> None:
        document = {
            "schema_version": 1,
            "component_health": {"gateway": "healthy"},
            "latency_buckets": {"100_500ms": 4},
            "aggregate_throughput_buckets": {"10_50mbps": 3},
        }
        self.assertEqual(forbidden_json_paths(document), [])


if __name__ == "__main__":
    unittest.main()
