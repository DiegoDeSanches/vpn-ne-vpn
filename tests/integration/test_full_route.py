from __future__ import annotations

import asyncio
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.mock_route import MockRouteEnvironment
from qa_harness.model import AnonymityMode


EXPECTED_ROLES = {
    AnonymityMode.STANDARD: ("exit",),
    AnonymityMode.ENHANCED: ("entry", "exit"),
    AnonymityMode.MAXIMUM: ("entry", "relay", "exit"),
    AnonymityMode.DIRECT_TOR: (),
}


class FullRouteTests(unittest.TestCase):
    def test_all_route_modes_reach_only_the_controlled_fixture(self) -> None:
        async def exercise() -> None:
            for mode, expected_roles in EXPECTED_ROLES.items():
                with self.subTest(mode=mode.value):
                    async with MockRouteEnvironment(mode) as environment:
                        evidence = await environment.probe()
                    self.assertEqual(evidence.gateway_roles, expected_roles)
                    self.assertEqual(evidence.physical_traffic, ("tor_transport",))
                    expected_target = "public_tor_exit" if mode is AnonymityMode.DIRECT_TOR else "onion_service"
                    self.assertEqual(evidence.tor_target_class, expected_target)
                    self.assertGreater(evidence.bytes_round_trip, 0)

        asyncio.run(exercise())

    def test_private_modes_never_enable_direct_tor_mapping(self) -> None:
        async def exercise() -> None:
            async with MockRouteEnvironment(AnonymityMode.STANDARD) as environment:
                assert environment.tor is not None
                self.assertFalse(environment.tor.allow_direct_tor)
                self.assertNotIn("fixture.invalid", environment.tor.routes)

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
