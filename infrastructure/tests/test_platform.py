import importlib.util
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INFRA = ROOT / "infrastructure"


def load_module(name, path):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deploy = load_module("onionroute_deploy", INFRA / "deploy" / "onionroute_deploy.py")
privacy = load_module(
    "onionroute_privacy_exporter",
    INFRA / "ansible" / "roles" / "onionroute_node" / "files" / "onionroute-privacy-exporter",
)
platform_metrics = load_module(
    "onionroute_platform_metrics",
    INFRA / "ansible" / "roles" / "onionroute_node" / "files" / "onionroute-platform-metrics",
)


class StaticPolicyTests(unittest.TestCase):
    def test_json_artifacts_are_valid_and_bounded(self):
        for path in INFRA.rglob("*.json"):
            self.assertLess(path.stat().st_size, 1_048_576, path)
            json.loads(path.read_text(encoding="utf-8"))

    def test_no_secret_material_or_state_file_is_committed(self):
        forbidden_suffixes = {".tfstate", ".tfplan", ".p12", ".token"}
        secret_markers = (
            "BEGIN " + "PRIVATE KEY",
            "BEGIN RSA " + "PRIVATE KEY",
            "BEGIN OPENSSH " + "PRIVATE KEY",
            "VAULT_" + "TOKEN=hvs.",
        )
        for path in INFRA.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix in {".pyc", ".pyo"} or "__pycache__" in path.parts:
                continue
            self.assertNotIn(path.suffix, forbidden_suffixes, path)
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker in secret_markers:
                self.assertNotIn(marker, text, path)

    def test_cloud_nodes_have_no_public_ingress_or_address(self):
        cloud = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (INFRA / "opentofu").rglob("*.tf")
        )
        self.assertIn("associate_public_ip_address = false", cloud)
        self.assertIn("# No access_config", cloud)
        self.assertNotIn("associate_public_ip_address = true", cloud)
        self.assertNotRegex(cloud, r'resource\s+"aws_vpc_security_group_ingress_rule"')

    def test_topology_and_scope_checks_are_present(self):
        main = (INFRA / "opentofu" / "main.tf").read_text(encoding="utf-8")
        for invariant in (
            "entry_exit_separation",
            "setintersection(local.entry_providers, local.exit_providers)",
            "setintersection(local.entry_asns, local.exit_asns)",
            "setintersection(local.entry_admin, local.exit_admin)",
            "setintersection(local.entry_mgmt, local.exit_mgmt)",
            "secret_scope_separation",
            "all_vault_roles",
        ):
            self.assertIn(invariant, main)

    def test_supply_chain_binds_and_verifies_the_whole_release_bundle(self):
        build = (INFRA / "images" / "build-image.sh").read_text(encoding="utf-8")
        prepare = (INFRA / "images" / "scripts" / "prepare-image.sh").read_text(encoding="utf-8")
        packer = (INFRA / "images" / "onionroute.pkr.hcl").read_text(encoding="utf-8")
        self.assertIn("! -type d ! -type f", build)
        self.assertIn("release_bundle_signature", packer)
        self.assertIn("onionroute-release.tar.gz.sig", prepare)
        self.assertIn("cosign verify-blob", prepare)

    def test_provider_network_logging_cannot_capture_exit_destinations(self):
        gcp = (INFRA / "opentofu" / "modules" / "gcp_fleet" / "main.tf").read_text(encoding="utf-8")
        self.assertNotIn("log_config", gcp)

    def test_vault_roles_are_node_bound_short_lived_and_revocable(self):
        configure = (INFRA / "vault" / "configure-node-roles.sh").read_text(encoding="utf-8")
        revoke = (INFRA / "vault" / "vault-revoke-adapter").read_text(encoding="utf-8")
        variables = (INFRA / "opentofu" / "variables.tf").read_text(encoding="utf-8")
        self.assertEqual(configure.count("ttl=2m max_ttl=2m token_type=batch"), 2)
        self.assertIn("node.vault_auth_role == name", variables)
        self.assertIn('role/$node_id"', revoke)
        self.assertIn('role/$node_id-onion"', revoke)

    def test_nftables_is_default_deny_and_blocks_high_risk_paths(self):
        nft = (INFRA / "nftables" / "onionroute-node.nft.j2").read_text(encoding="utf-8")
        self.assertEqual(nft.count("policy drop;"), 3)
        for value in ("169.254.0.0/16", "fc00::/7", "udp dport 53", "dport @dangerous_tcp_ports drop"):
            self.assertIn(value, nft)
        self.assertNotIn("udp accept", nft)

    def test_systemd_services_apply_required_hardening(self):
        paths = list((INFRA / "systemd").glob("*.service*")) + list((INFRA / "systemd").glob("*.conf"))
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for directive in (
                "NoNewPrivileges=yes",
                "ProtectSystem=strict",
                "ProtectHome=yes",
                "PrivateDevices=yes",
                "RestrictSUIDSGID=yes",
                "SystemCallFilter=",
            ):
                self.assertIn(directive, text, path)

    def test_monitoring_configuration_has_no_user_or_destination_labels(self):
        monitoring = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (INFRA / "monitoring").rglob("*") if path.is_file()
        ).lower()
        for forbidden in ("user_ip", "client_ip", "source_ip", "destination_domain", "account_id", "device_id"):
            self.assertNotIn(forbidden, monitoring)
        self.assertIn("active_session_bucket", monitoring)


class PrivacyExporterTests(unittest.TestCase):
    def setUp(self):
        self.values = {
            "onionroute_gateway_active_sessions": 31.0,
            "onionroute_gateway_ready": 1.0,
            "onionroute_gateway_streams_opened_total": 100.0,
            "onionroute_gateway_egress_failures_total": 2.0,
            "onionroute_gateway_protocol_violations_total": 1.0,
            "onionroute_gateway_client_to_egress_bytes_total": 1_000_000.0,
            "onionroute_gateway_egress_to_client_bytes_total": 2_000_000.0,
            "onionroute_gateway_dns_failures_total": 0.0,
        }

    def test_exact_usage_is_replaced_with_buckets(self):
        view = privacy.PrivacyView()
        output = view.render(self.values, now=10.0)
        self.assertIn("onionroute_gateway_active_session_bucket 3", output)
        self.assertIn("onionroute_gateway_bandwidth_bucket 0", output)
        self.assertNotIn("active_sessions", output)
        self.assertNotIn("bytes_total", output)

    def test_source_labels_are_rejected(self):
        body = b"onionroute_gateway_ready{client_ip=\"x\"} 1\n"
        with self.assertRaises(ValueError):
            privacy.parse_metrics(body)

    def test_nonfinite_source_values_are_rejected(self):
        body = b"onionroute_gateway_ready NaN\n"
        with self.assertRaises(ValueError):
            privacy.parse_metrics(body)


class PlatformMetricTests(unittest.TestCase):
    def test_tor_bootstrap_uses_bounded_control_protocol_progress(self):
        response = '250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=73 TAG=loading SUMMARY="Loading"\r\n250 OK\r\n'
        self.assertEqual(platform_metrics.parse_tor_bootstrap(response), 73)
        self.assertEqual(platform_metrics.parse_tor_bootstrap("250 PROGRESS=999 OK"), 100)
        self.assertEqual(platform_metrics.parse_tor_bootstrap("250 OK"), 0)


class FakeRunner:
    def __init__(self, health_values):
        self.commands = []
        self.health_values = iter(health_values)

    def run(self, argv, cwd=None):
        self.commands.append(tuple(argv))
        if argv[0] == "health-adapter":
            return json.dumps(next(self.health_values))
        return ""


def healthy(**overrides):
    value = {
        "ready": True,
        "active_session_bucket": 0,
        "tor_bootstrap_percent": 100,
        "onion_available": True,
        "stream_error_rate": 0.0,
        "egress_failures_5m": 0,
        "key_expiry_seconds": 1_000_000,
        "clock_drift_seconds": 0.01,
    }
    value.update(overrides)
    return value


class DeploymentTests(unittest.TestCase):
    def config(self, root):
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"builds": [{
            "artifact_id": "image-1",
            "custom_data": {"release_digest": "sha256:" + "a" * 64},
        }]}), encoding="utf-8")
        for name in ("manifest.sig", "release.pub", "backend", "canary.tfvars", "rollout.tfvars", "rollback.tfvars"):
            (root / name).write_text("test", encoding="utf-8")
        return {
            "tofu_dir": str(root),
            "backend_config": str(root / "backend"),
            "canary_tfvars": str(root / "canary.tfvars"),
            "rollout_tfvars": str(root / "rollout.tfvars"),
            "rollback_tfvars": str(root / "rollback.tfvars"),
            "canary_node": "exit-1",
            "rollout_nodes": [],
            "role": "exit",
            "image_manifest": str(manifest),
            "image_manifest_signature": str(root / "manifest.sig"),
            "release_public_key": str(root / "release.pub"),
            "expected_image_id": "image-1",
            "expected_release_digest": "sha256:" + "a" * 64,
            "directory_command": ["directory-adapter", "v1"],
            "health_command": ["health-adapter", "v1"],
            "lifecycle_command": ["lifecycle-adapter", "v1"],
            "isolate_command": ["isolate-adapter", "v1"],
            "vault_revoke_command": ["vault-adapter", "v1"],
            "drain_timeout_seconds": 1,
            "health_timeout_seconds": 1,
            "poll_interval_seconds": 1,
            "canary_observations": 1,
            "max_stream_error_rate": 0.05,
            "max_egress_failures_5m": 5,
            "max_clock_drift_seconds": 1.0,
            "min_key_expiry_seconds": 604800,
        }

    def test_health_schema_rejects_identity_fields(self):
        value = healthy(user_ip="192.0.2.1")
        with self.assertRaises(deploy.DeploymentError):
            deploy.Health.parse(json.dumps(value))

    def test_config_paths_are_resolved_against_the_config_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = self.config(root)
            for field in deploy.PATH_FIELDS:
                config[field] = Path(config[field]).name
            path = root / "deployment.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            loaded = deploy.load_config(path)
            for field in deploy.PATH_FIELDS:
                self.assertEqual(Path(loaded[field]).parent, root.resolve())

    def test_failed_canary_is_automatically_revoked_and_rolled_back(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            runner = FakeRunner([healthy(), healthy(), healthy(ready=False), healthy()])
            controller = deploy.Deployment(config, runner, sleep=lambda _seconds: None)
            with self.assertRaisesRegex(deploy.DeploymentError, "rollback completed"):
                controller.deploy()
            self.assertIn(("directory-adapter", "v1", "revoke", "exit-1"), runner.commands)
            self.assertIn(("lifecycle-adapter", "v1", "drain", "exit-1"), runner.commands)
            self.assertIn(("lifecycle-adapter", "v1", "restart", "exit-1"), runner.commands)
            apply_count = sum(command[:2] == ("tofu", "apply") for command in runner.commands)
            self.assertEqual(apply_count, 2)

    def test_failed_drain_is_revoked_and_rolled_back(self):
        class FailDrainRunner(FakeRunner):
            def run(self, argv, cwd=None):
                self.commands.append(tuple(argv))
                if argv[:3] == ["directory-adapter", "v1", "drain"]:
                    raise deploy.DeploymentError("directory drain failed")
                if argv[0] == "health-adapter":
                    return json.dumps(next(self.health_values))
                return ""

        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            runner = FailDrainRunner([healthy()])
            controller = deploy.Deployment(config, runner, sleep=lambda _seconds: None)
            with self.assertRaisesRegex(deploy.DeploymentError, "rollback completed"):
                controller.deploy()
            self.assertIn(("directory-adapter", "v1", "revoke", "exit-1"), runner.commands)
            apply_count = sum(command[:2] == ("tofu", "apply") for command in runner.commands)
            self.assertEqual(apply_count, 1)

    def test_emergency_revoke_hits_all_three_control_planes(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            runner = FakeRunner([])
            deploy.Deployment(config, runner).emergency_revoke("exit-1")
            self.assertIn(("directory-adapter", "v1", "revoke", "exit-1"), runner.commands)
            self.assertIn(("vault-adapter", "v1", "revoke", "exit-1"), runner.commands)
            self.assertIn(("isolate-adapter", "v1", "isolate", "exit-1"), runner.commands)


if __name__ == "__main__":
    unittest.main()
