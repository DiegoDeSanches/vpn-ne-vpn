from __future__ import annotations

import json
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
COMPOSE = ROOT / "compose.yaml"


class LocalPrototypeDefinitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        completed = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE), "config", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.definition = json.loads(completed.stdout)

    def test_only_client_tor_publishes_fixed_loopback_ports(self) -> None:
        for name, service in self.definition["services"].items():
            ports = service.get("ports") or []
            if name != "client-tor":
                self.assertFalse(ports, name)
                continue
            self.assertEqual(
                {(item["host_ip"], item["target"], item["published"]) for item in ports},
                {("127.0.0.1", 19050, "19050"), ("127.0.0.1", 19091, "19091")},
            )

    def test_fixture_egress_network_is_internal(self) -> None:
        network = self.definition["networks"]["fixture-egress"]
        self.assertTrue(network["internal"])
        self.assertEqual(network["ipam"]["config"][0]["subnet"], "192.175.48.0/28")

    def test_onion_and_probe_share_only_intended_namespaces(self) -> None:
        services = self.definition["services"]
        self.assertEqual(services["onion-service"]["network_mode"], "service:gateway")
        self.assertEqual(services["probe"]["network_mode"], "service:client-tor")

    def test_runtime_secrets_are_not_environment_values(self) -> None:
        for name, service in self.definition["services"].items():
            environment = service.get("environment") or {}
            flattened = json.dumps(environment).lower()
            self.assertNotIn("token", flattened, name)
            self.assertNotIn("private_key", flattened, name)


if __name__ == "__main__":
    unittest.main()
