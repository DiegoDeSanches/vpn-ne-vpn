from __future__ import annotations

import json
import pathlib
import unittest


DIRECTORY = pathlib.Path(__file__).parent


class StagingDefinitionTests(unittest.TestCase):
    def test_real_onion_compose_has_no_host_published_port(self) -> None:
        compose = (DIRECTORY / "compose.yaml").read_text(encoding="utf-8")
        self.assertNotIn("\n    ports:", compose)
        self.assertIn('network_mode: "service:gateway"', compose)
        self.assertIn("OR_DIRECTORY_ENDPOINT", compose)
        self.assertIn("NET_ADMIN", compose)
        self.assertNotIn("privileged: true", compose)
        self.assertIn("OR_CONTROLLED_FIXTURE", compose)
        for image in ("OR_GATEWAY_IMAGE", "OR_TOR_IMAGE", "OR_CLIENT_TEST_IMAGE"):
            self.assertIn(f"${{{image}:?", compose)

    def test_onion_service_is_v3_and_targets_only_loopback(self) -> None:
        torrc = (DIRECTORY / "torrc.onion").read_text(encoding="utf-8")
        self.assertIn("HiddenServiceVersion 3", torrc)
        self.assertIn("HiddenServicePort 443 127.0.0.1:8443", torrc)
        self.assertIn("SocksPort 0", torrc)

    def test_gateway_protocol_and_allocation_limits_are_explicit(self) -> None:
        config = json.loads((DIRECTORY / "gateway.staging.json").read_text(encoding="utf-8"))
        limits = config["limits"]
        self.assertEqual(limits["max_frame_bytes"], 65536)
        self.assertLessEqual(limits["max_data_bytes"], 32768)
        self.assertGreater(limits["outbound_event_queue"], 0)
        self.assertLessEqual(limits["max_stream_window"], 4194304)
        self.assertIn(25, config["acl"]["blocked_ports"])

    def test_multi_region_plan_refuses_implicit_colocation(self) -> None:
        plan = json.loads((DIRECTORY / "multi-region.plan.json").read_text(encoding="utf-8"))
        self.assertEqual(len(plan["regions"]), 4)
        self.assertTrue(any("distinct failure domains" in item for item in plan["hard_constraints"]))
        self.assertTrue(any("independent admin" in item for item in plan["hard_constraints"]))


if __name__ == "__main__":
    unittest.main()
