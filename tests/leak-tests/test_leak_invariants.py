from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.model import AnonymityMode, TrafficKind, TunnelModel


class LeakInvariantTests(unittest.TestCase):
    def test_required_leak_vectors_are_blocked_or_protected(self) -> None:
        expected = {
            TrafficKind.DNS: "protected",
            TrafficKind.IPV4_TCP: "protected",
            TrafficKind.IPV6: "blocked",
            TrafficKind.WEBRTC: "blocked",
            TrafficKind.QUIC: "blocked",
            TrafficKind.DOH: "protected",
            TrafficKind.DOT: "protected",
            TrafficKind.APPLICATION_FALLBACK: "blocked",
            TrafficKind.LOCAL_NETWORK: "blocked",
        }
        for mode in AnonymityMode:
            model = TunnelModel(mode=mode)
            model.connect()
            for kind, outcome in expected.items():
                with self.subTest(mode=mode.value, vector=kind.value):
                    observation = model.observe(kind)
                    self.assertEqual(observation.outcome, outcome)
                    self.assertFalse(observation.leaked)
                    self.assertEqual(observation.system_dns_calls, 0)

    def test_startup_shutdown_and_rotation_have_no_route_gap(self) -> None:
        model = TunnelModel()
        model.begin_connect()
        model.assert_fail_closed()
        model.tor_alive = True
        model.complete_connect()
        model.begin_rotation()
        model.assert_fail_closed()
        model.complete_rotation(True)
        model.begin_disconnect()
        model.assert_fail_closed()

    def test_network_transition_blocks_before_new_interface_use(self) -> None:
        model = TunnelModel()
        model.connect()
        for transition in ("wifi_to_ethernet", "wifi_to_cellular", "ipv4_to_dual_stack"):
            with self.subTest(transition=transition):
                model.inject_failure("network_loss")
                observation = model.observe(TrafficKind.IPV4_TCP)
                self.assertEqual(observation.outcome, "blocked")
                self.assertEqual(observation.physical_traffic, ())
                model.tor_alive = True
                model.catalog = type(model.catalog)()
                model.token_valid = True
                self.assertTrue(model.attempt_reconnect())

    def test_dns_never_uses_system_resolver(self) -> None:
        model = TunnelModel()
        model.connect()
        for kind in (TrafficKind.DNS, TrafficKind.DOH, TrafficKind.DOT):
            self.assertEqual(model.observe(kind).system_dns_calls, 0)


if __name__ == "__main__":
    unittest.main()
