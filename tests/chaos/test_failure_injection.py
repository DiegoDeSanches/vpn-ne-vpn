from __future__ import annotations

import asyncio
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.mock_route import FaultProfile, MockRouteEnvironment
from qa_harness.model import AnonymityMode, CatalogState, ConnectionState, TrafficKind, TunnelModel


class FailureInjectionTests(unittest.TestCase):
    def test_data_plane_failures_never_create_fallback(self) -> None:
        faults = (
            "gateway_failure", "tor_crash", "network_loss", "dns_failure",
            "partial_gateway_outage", "process_kill_tor", "daemon_crash",
            "expired_certificate", "clock_skew", "malformed_frame",
        )
        for fault in faults:
            with self.subTest(fault=fault):
                model = TunnelModel()
                model.connect()
                model.inject_failure(fault)
                model.assert_fail_closed()
                self.assertEqual(model.direct_fallback_attempts, 0)

    def test_directory_and_token_negative_states_are_rejected(self) -> None:
        cases = (
            (CatalogState(signed=False), True, "unsigned"),
            (CatalogState(expired=True), True, "expired_directory"),
            (CatalogState(revoked=True), True, "revoked_directory"),
            (CatalogState(), False, "expired_token"),
        )
        for catalog, token_valid, name in cases:
            with self.subTest(case=name):
                model = TunnelModel(catalog=catalog, token_valid=token_valid)
                model.begin_connect()
                model.tor_alive = True
                self.assertFalse(model.complete_connect())
                self.assertEqual(model.state, ConnectionState.BLOCKED)
                model.assert_fail_closed()

    def test_control_plane_outages_do_not_weaken_active_data_plane(self) -> None:
        for fault in ("database_outage", "kms_outage", "directory_signing_outage"):
            with self.subTest(fault=fault):
                model = TunnelModel()
                model.connect()
                model.inject_failure(fault)
                self.assertEqual(model.state, ConnectionState.CONNECTED)
                self.assertFalse(model.observe(TrafficKind.IPV4_TCP).leaked)

    def test_resource_pressure_denies_new_allocation_without_shedding_kill_switch(self) -> None:
        for fault in ("disk_full", "memory_pressure"):
            with self.subTest(fault=fault):
                model = TunnelModel()
                model.connect()
                model.inject_failure(fault)
                self.assertTrue(model.kill_switch)
                self.assertIn("new_allocations_blocked", model.events)

    def test_packet_loss_latency_and_bandwidth_fault_proxy(self) -> None:
        async def exercise() -> None:
            slow = FaultProfile(latency_ms=2, bandwidth_bytes_per_second=256 * 1024)
            async with MockRouteEnvironment(
                AnonymityMode.STANDARD, hop_faults={"exit": slow}
            ) as environment:
                evidence = await environment.probe(b"x" * 16 * 1024)
                self.assertEqual(evidence.bytes_round_trip, 16 * 1024)
                self.assertGreater(evidence.time_to_first_byte_ms, 0)
            async with MockRouteEnvironment(
                AnonymityMode.STANDARD,
                hop_faults={"exit": FaultProfile(drop_connection=True)},
            ) as environment:
                with self.assertRaises((ConnectionError, AssertionError)):
                    await environment.probe()

        asyncio.run(exercise())

    def test_process_kill_breaks_route_without_alternate_socket(self) -> None:
        async def exercise() -> None:
            async with MockRouteEnvironment(AnonymityMode.MAXIMUM) as environment:
                await environment.kill("relay")
                with self.assertRaises((ConnectionError, AssertionError, asyncio.IncompleteReadError)):
                    await environment.probe()

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
