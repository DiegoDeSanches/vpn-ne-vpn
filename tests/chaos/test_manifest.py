from __future__ import annotations

import json
import pathlib
import unittest


class ChaosManifestTests(unittest.TestCase):
    def test_all_required_faults_have_mechanism_and_external_environment(self) -> None:
        document = json.loads((pathlib.Path(__file__).parent / "manifest.json").read_text(encoding="utf-8"))
        required = {
            "packet_loss", "high_latency", "bandwidth_limitation", "process_kill",
            "malformed_frames", "expired_certificates", "clock_skew", "dns_failures",
            "partial_gateway_outage", "database_outage", "kms_outage",
            "directory_signing_outage", "disk_full", "memory_pressure",
        }
        self.assertEqual({fault["name"] for fault in document["faults"]}, required)
        for fault in document["faults"]:
            self.assertTrue(fault["mechanism"])
            self.assertTrue(any(environment != "simulation" for environment in fault["environments"]))


if __name__ == "__main__":
    unittest.main()
