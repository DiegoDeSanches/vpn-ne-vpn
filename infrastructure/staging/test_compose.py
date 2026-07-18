from __future__ import annotations

import json
import os
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "infrastructure" / "staging" / "compose.yaml"


class StagingComposeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        environment = dict(os.environ)
        environment["OR_CONTROL_PLANE_IMAGE"] = (
            "onionroute/control-plane:" + ("a" * 40)
        )
        environment["OR_MIGRATION_SQL_FILE"] = str(
            ROOT / "services" / "migrations" / "0001_control_plane.sql"
        )
        completed = subprocess.run(
            [
                "docker",
                "compose",
                "--file",
                str(COMPOSE),
                "--profile",
                "migration",
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        cls.definition = json.loads(completed.stdout)

    def test_only_postgres_has_a_host_port_and_it_is_loopback(self) -> None:
        published: list[tuple[str, str, int, str]] = []
        for name, service in self.definition["services"].items():
            for port in service.get("ports") or []:
                published.append(
                    (
                        name,
                        port["host_ip"],
                        port["target"],
                        str(port["published"]),
                    )
                )
        self.assertEqual(
            published,
            [("postgres", "127.0.0.1", 5432, "55432")],
        )

    def test_unsafe_production_components_are_not_deployed(self) -> None:
        services = self.definition["services"]
        for forbidden in (
            "gateway-daemon",
            "signing-service",
            "token-service",
            "entry-gateway",
            "relay-gateway",
        ):
            self.assertNotIn(forbidden, services)

    def test_rust_ingresses_bind_only_host_loopback(self) -> None:
        expectations = {
            "directory-service": ("OR_CLIENT_BIND", "127.0.0.1:18080"),
            "health-collector": ("OR_HEALTH_BIND", "127.0.0.1:18081"),
            "admin-api": ("OR_ADMIN_BIND", "127.0.0.1:18082"),
            "revocation-service": ("OR_REVOCATION_BIND", "127.0.0.1:18084"),
        }
        for name, (variable, expected) in expectations.items():
            service = self.definition["services"][name]
            self.assertEqual(service["network_mode"], "host", name)
            self.assertEqual(service["environment"][variable], expected, name)
            self.assertEqual(service["user"], "10001:10001", name)
            self.assertTrue(service["read_only"], name)
            self.assertIn("ALL", service["cap_drop"], name)

    def test_runtime_password_is_a_file_secret(self) -> None:
        expectations = {
            "directory-service": "/run/secrets/directory-service-password",
            "health-collector": "/run/secrets/health-collector-password",
            "admin-api": "/run/secrets/admin-api-password",
            "revocation-service": "/run/secrets/revocation-service-password",
        }
        password_files: set[str] = set()
        for name, expected_password_file in expectations.items():
            service = self.definition["services"][name]
            environment = service.get("environment") or {}
            self.assertEqual(
                environment["OR_DATABASE_PASSWORD_FILE"],
                expected_password_file,
                name,
            )
            password_files.add(environment["OR_DATABASE_PASSWORD_FILE"])
            flattened = json.dumps(environment).lower()
            self.assertNotIn("postgresql://", flattened, name)
            self.assertNotIn("password=", flattened, name)
            self.assertEqual(service["pull_policy"], "never", name)

        self.assertEqual(len(password_files), len(expectations))

        migration = self.definition["services"]["migrate"]
        self.assertIn("10001", [str(group) for group in migration["group_add"]])
        self.assertEqual(
            self.definition["services"]["tor-directory"]["pull_policy"],
            "never",
        )

    def test_postgres_18_volume_covers_its_declared_data_root(self) -> None:
        mounts = self.definition["services"]["postgres"]["volumes"]
        self.assertEqual(
            [mount["target"] for mount in mounts],
            ["/var/lib/postgresql"],
        )
        command = self.definition["services"]["postgres"]["command"]
        self.assertIn("shared_buffers=32MB", command)
        self.assertIn("max_connections=50", command)
        environment = self.definition["services"]["postgres"]["environment"]
        self.assertEqual(
            environment["POSTGRES_INITDB_ARGS"],
            "--auth-host=scram-sha-256",
        )
        health_test = " ".join(
            self.definition["services"]["postgres"]["healthcheck"]["test"]
        )
        self.assertIn("/proc/1/comm", health_test)
        self.assertIn("SELECT 1", health_test)

    def test_directory_reads_only_public_onion_hostname_volume(self) -> None:
        mounts = self.definition["services"]["directory-service"]["volumes"]
        targets = {mount["target"] for mount in mounts}
        self.assertIn("/var/lib/onionroute-directory", targets)
        self.assertNotIn("/var/lib/tor-directory", targets)

    def test_tor_has_only_the_capabilities_needed_for_volume_ownership(self) -> None:
        tor = self.definition["services"]["tor-directory"]
        self.assertIn("ALL", tor["cap_drop"])
        self.assertEqual(
            set(tor["cap_add"]),
            {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
        )


if __name__ == "__main__":
    unittest.main()
