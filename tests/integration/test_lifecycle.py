from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.model import AnonymityMode, ConnectionState, TrafficKind, TunnelModel


class LifecycleTests(unittest.TestCase):
    def test_first_launch_connect_and_disconnect_ordering(self) -> None:
        model = TunnelModel()
        model.first_launch()
        self.assertEqual(model.state, ConnectionState.CONNECTING)
        self.assertTrue(model.kill_switch)
        self.assertEqual(model.observe(TrafficKind.IPV4_TCP).outcome, "blocked")
        model.tor_alive = True
        self.assertTrue(model.complete_connect())
        self.assertEqual(model.observe(TrafficKind.IPV4_TCP).outcome, "protected")
        model.begin_disconnect()
        self.assertEqual(model.observe(TrafficKind.DNS).outcome, "blocked")
        model.complete_disconnect()
        self.assertEqual(model.state, ConnectionState.DISCONNECTED)
        self.assertEqual(
            model.events[-2:], ["cleanup_verified", "kill_switch_released"]
        )

    def test_every_mode_connects_only_through_tor(self) -> None:
        for mode in AnonymityMode:
            with self.subTest(mode=mode.value):
                model = TunnelModel(mode=mode)
                self.assertTrue(model.connect())
                observation = model.observe(TrafficKind.IPV4_TCP)
                self.assertEqual(observation.physical_traffic, ("tor_transport",))
                self.assertFalse(observation.leaked)

    def test_country_soft_hard_and_identity_rotations_are_make_before_break(self) -> None:
        model = TunnelModel()
        model.connect()
        initial_route = model.route_generation
        model.begin_rotation()
        self.assertEqual(model.observe(TrafficKind.IPV4_TCP).outcome, "protected")
        self.assertTrue(model.complete_rotation(replacement_ready=True))
        self.assertGreater(model.route_generation, initial_route)
        self.assertTrue(model.change_country("DE"))
        self.assertEqual(model.country, "DE")
        dns_before = model.dns_generation
        self.assertTrue(model.reset_identity())
        self.assertGreater(model.dns_generation, dns_before)
        self.assertIn("identity_reset", model.events)

    def test_failed_rotation_retains_old_healthy_route_or_blocks(self) -> None:
        model = TunnelModel()
        model.connect()
        model.begin_rotation()
        self.assertFalse(model.complete_rotation(False, old_path_healthy=True))
        self.assertEqual(model.state, ConnectionState.CONNECTED)
        self.assertEqual(model.observe(TrafficKind.IPV4_TCP).outcome, "protected")
        model.begin_rotation(hard=True)
        self.assertFalse(model.complete_rotation(False, old_path_healthy=False))
        self.assertEqual(model.state, ConnectionState.RECONNECTING)
        self.assertEqual(model.observe(TrafficKind.IPV4_TCP).outcome, "blocked")

    def test_sleep_resume_captive_portal_and_network_loss_fail_closed(self) -> None:
        for fault in ("network_loss", "sleep", "captive_portal"):
            with self.subTest(fault=fault):
                model = TunnelModel()
                model.connect()
                model.inject_failure(fault)
                model.assert_fail_closed()
                self.assertEqual(model.state, ConnectionState.RECONNECTING)

    def test_ui_crash_does_not_own_the_kill_switch(self) -> None:
        model = TunnelModel()
        model.connect()
        model.inject_failure("ui_crash")
        self.assertTrue(model.kill_switch)
        self.assertEqual(model.state, ConnectionState.CONNECTED)
        self.assertFalse(model.observe(TrafficKind.IPV4_TCP).leaked)

    def test_daemon_crash_and_reboot_recover_under_persistent_block(self) -> None:
        for fault in ("daemon_crash", "system_reboot"):
            with self.subTest(fault=fault):
                model = TunnelModel()
                model.connect()
                model.inject_failure(fault)
                self.assertTrue(model.kill_switch)
                self.assertEqual(model.state, ConnectionState.RECONNECTING)
                model.assert_fail_closed()


if __name__ == "__main__":
    unittest.main()
