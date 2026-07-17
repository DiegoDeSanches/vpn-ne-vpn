#!/usr/bin/env python3
"""Fail-closed OnionRoute image deployment orchestration.

All external control/directory operations are versioned adapters. This file does
not implement or alter the protected gateway directory format.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any, Callable

MAX_CONFIG_BYTES = 262_144
NODE_ROLES = {
    "entry", "exit", "relay", "directory", "token", "health-collector",
    "signing", "monitoring", "management",
}
CONTROL_ROLES = {"directory", "token", "health-collector", "signing"}
HEALTH_FIELDS = {
    "ready",
    "active_session_bucket",
    "tor_bootstrap_percent",
    "onion_available",
    "stream_error_rate",
    "egress_failures_5m",
    "key_expiry_seconds",
    "clock_drift_seconds",
}
COMMAND_FIELDS = {
    "directory_command",
    "health_command",
    "lifecycle_command",
    "isolate_command",
    "vault_revoke_command",
    "migration_command",
}
PATH_FIELDS = {
    "tofu_dir", "backend_config", "canary_tfvars", "rollout_tfvars",
    "rollback_tfvars", "image_manifest", "image_manifest_signature",
    "release_public_key",
}
CONFIG_FIELDS = {
    "tofu_dir",
    "backend_config",
    "canary_tfvars",
    "rollout_tfvars",
    "rollback_tfvars",
    "canary_node",
    "rollout_nodes",
    "role",
    "image_manifest",
    "image_manifest_signature",
    "release_public_key",
    "expected_image_id",
    "expected_release_digest",
    "drain_timeout_seconds",
    "health_timeout_seconds",
    "poll_interval_seconds",
    "canary_observations",
    "max_stream_error_rate",
    "max_egress_failures_5m",
    "max_clock_drift_seconds",
    "min_key_expiry_seconds",
} | COMMAND_FIELDS


class DeploymentError(RuntimeError):
    pass


class Runner:
    def run(self, argv: list[str], cwd: Path | None = None) -> str:
        if not argv or len(argv) > 64 or any(len(arg) > 4096 for arg in argv):
            raise DeploymentError("invalid bounded command")
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=900,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DeploymentError(f"command unavailable or timed out: {argv[0]}") from error
        if result.returncode != 0:
            # Do not echo adapter output: it may contain provider details.
            raise DeploymentError(f"command failed: {argv[0]} (exit {result.returncode})")
        if len(result.stdout) > MAX_CONFIG_BYTES:
            raise DeploymentError("command output exceeds limit")
        return result.stdout


@dataclass(frozen=True)
class Health:
    ready: bool
    active_session_bucket: int
    tor_bootstrap_percent: int
    onion_available: bool
    stream_error_rate: float
    egress_failures_5m: int
    key_expiry_seconds: int
    clock_drift_seconds: float

    @classmethod
    def parse(cls, value: str) -> "Health":
        try:
            raw = json.loads(value)
        except (TypeError, json.JSONDecodeError) as error:
            raise DeploymentError("health adapter returned invalid JSON") from error
        if not isinstance(raw, dict) or set(raw) != HEALTH_FIELDS:
            raise DeploymentError("health response must use the closed privacy schema")
        try:
            health = cls(**raw)
        except TypeError as error:
            raise DeploymentError("health response has invalid fields") from error
        if type(health.ready) is not bool or type(health.onion_available) is not bool:
            raise DeploymentError("health booleans are invalid")
        if any(type(value) is not int for value in (
            health.active_session_bucket,
            health.tor_bootstrap_percent,
            health.egress_failures_5m,
            health.key_expiry_seconds,
        )):
            raise DeploymentError("health integer is invalid")
        if any(type(value) not in (int, float) for value in (
            health.stream_error_rate, health.clock_drift_seconds
        )):
            raise DeploymentError("health rate is invalid")
        if not 0 <= health.active_session_bucket <= 6:
            raise DeploymentError("session bucket is invalid")
        if not 0 <= health.tor_bootstrap_percent <= 100:
            raise DeploymentError("Tor progress is invalid")
        if not 0 <= health.stream_error_rate <= 1:
            raise DeploymentError("stream error rate is invalid")
        if health.egress_failures_5m < 0 or health.key_expiry_seconds < 0:
            raise DeploymentError("health counter is invalid")
        return health


def load_config(path: Path) -> dict[str, Any]:
    config_path = path.resolve()
    if not config_path.is_file():
        raise DeploymentError("deployment config is missing")
    if config_path.stat().st_size > MAX_CONFIG_BYTES:
        raise DeploymentError("deployment config exceeds size limit")
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise DeploymentError("deployment config is invalid JSON") from error
    if not isinstance(raw, dict) or not set(raw).issubset(CONFIG_FIELDS):
        raise DeploymentError("deployment config contains unknown fields")
    required = CONFIG_FIELDS - {"migration_command"}
    missing = required - set(raw)
    if missing:
        raise DeploymentError("deployment config is incomplete")
    for field in COMMAND_FIELDS:
        command = raw.get(field)
        if field == "migration_command" and command is None:
            continue
        if (
            not isinstance(command, list)
            or not command
            or len(command) > 64
            or not all(isinstance(item, str) and item and len(item) <= 4096 for item in command)
        ):
            raise DeploymentError(f"{field} must be a non-empty argv array")
    if raw["role"] not in NODE_ROLES:
        raise DeploymentError("deployment role is invalid")
    if raw["role"] in CONTROL_ROLES and not raw.get("migration_command"):
        raise DeploymentError("control-plane deployment requires an expand-only migration check")
    node_pattern = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
    if not isinstance(raw["canary_node"], str) or not node_pattern.fullmatch(raw["canary_node"]):
        raise DeploymentError("canary node ID is invalid")
    if (
        not isinstance(raw["rollout_nodes"], list)
        or len(raw["rollout_nodes"]) > 1000
        or not all(isinstance(node, str) and node_pattern.fullmatch(node) for node in raw["rollout_nodes"])
        or len(raw["rollout_nodes"]) != len(set(raw["rollout_nodes"]))
        or raw["canary_node"] in raw["rollout_nodes"]
    ):
        raise DeploymentError("rollout_nodes must exclude the canary")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(raw["expected_release_digest"])):
        raise DeploymentError("expected release digest is invalid")
    if not isinstance(raw["expected_image_id"], str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}", raw["expected_image_id"]
    ):
        raise DeploymentError("expected image ID is invalid")
    for field in ("drain_timeout_seconds", "health_timeout_seconds", "poll_interval_seconds", "canary_observations"):
        if type(raw[field]) is not int or not 0 < raw[field] <= 86400:
            raise DeploymentError(f"{field} is out of bounds")
    for field in ("max_stream_error_rate", "max_clock_drift_seconds"):
        if type(raw[field]) not in (int, float) or not 0 <= raw[field] <= 10:
            raise DeploymentError(f"{field} is out of bounds")
    if type(raw["max_egress_failures_5m"]) is not int or not 0 <= raw["max_egress_failures_5m"] <= 1_000_000:
        raise DeploymentError("max_egress_failures_5m is out of bounds")
    if type(raw["min_key_expiry_seconds"]) is not int or not 0 <= raw["min_key_expiry_seconds"] <= 31_536_000:
        raise DeploymentError("min_key_expiry_seconds is out of bounds")
    for field in PATH_FIELDS:
        if not isinstance(raw[field], str) or not raw[field] or len(raw[field]) > 4096:
            raise DeploymentError(f"{field} is invalid")
        candidate = Path(raw[field])
        if not candidate.is_absolute():
            candidate = config_path.parent / candidate
        raw[field] = str(candidate.resolve())
    return raw


class Deployment:
    def __init__(self, config: dict[str, Any], runner: Runner, sleep: Callable[[float], None] = time.sleep):
        self.config = config
        self.runner = runner
        self.sleep = sleep
        self.tofu_dir = Path(config["tofu_dir"]).resolve()

    def adapter(self, name: str, *args: str) -> str:
        command = list(self.config[name]) + list(args)
        return self.runner.run(command)

    def preflight(self) -> None:
        if not self.tofu_dir.is_dir():
            raise DeploymentError("OpenTofu directory is missing")
        for field in PATH_FIELDS - {"tofu_dir"}:
            if not Path(self.config[field]).is_file():
                raise DeploymentError(f"required deployment file is missing: {field}")
        manifest = Path(self.config["image_manifest"]).resolve()
        signature = Path(self.config["image_manifest_signature"]).resolve()
        public_key = Path(self.config["release_public_key"]).resolve()
        for path in (manifest, signature, public_key):
            if not path.is_file():
                raise DeploymentError("signed image evidence is missing")
        self.runner.run([
            "cosign", "verify-blob", "--key", str(public_key),
            "--signature", str(signature), str(manifest),
        ])
        if manifest.stat().st_size > MAX_CONFIG_BYTES:
            raise DeploymentError("image manifest exceeds size limit")
        evidence = json.loads(manifest.read_text(encoding="utf-8"))
        builds = evidence.get("builds") if isinstance(evidence, dict) else None
        if not isinstance(builds, list) or not builds:
            raise DeploymentError("Packer manifest contains no builds")
        image_id = self.config["expected_image_id"]
        digest = self.config["expected_release_digest"]
        matching = [
            build for build in builds
            if isinstance(build, dict)
            and build.get("custom_data", {}).get("release_digest") == digest
            and (build.get("artifact_id") == image_id or str(build.get("artifact_id", "")).endswith(":" + image_id))
        ]
        if not matching:
            raise DeploymentError("image ID and release digest are not bound by signed evidence")
        self.runner.run(["tofu", "fmt", "-check", "-recursive"], cwd=self.tofu_dir)
        self.runner.run([
            "tofu", "init", "-input=false", "-backend-config=" + str(Path(self.config["backend_config"]).resolve())
        ], cwd=self.tofu_dir)
        self.runner.run(["tofu", "validate"], cwd=self.tofu_dir)
        if self.config.get("migration_command"):
            migration = json.loads(self.adapter("migration_command"))
            if set(migration) != {"safe", "expand_only", "schema_version"}:
                raise DeploymentError("migration adapter response is not closed-schema")
            if migration["safe"] is not True or migration["expand_only"] is not True:
                raise DeploymentError("migration is not backward-compatible expand-only")

    def health(self, node: str) -> Health:
        return Health.parse(self.adapter("health_command", "health", node))

    def wait_drained(self, node: str) -> None:
        self.adapter("directory_command", "drain", node)
        self.adapter("lifecycle_command", "drain", node)
        deadline = time.monotonic() + self.config["drain_timeout_seconds"]
        while time.monotonic() < deadline:
            if self.health(node).active_session_bucket == 0:
                return
            self.sleep(self.config["poll_interval_seconds"])
        raise DeploymentError("drain deadline expired")

    def healthy(self, health: Health) -> bool:
        return (
            health.ready
            and health.onion_available
            and health.tor_bootstrap_percent == 100
            and health.stream_error_rate <= self.config["max_stream_error_rate"]
            and health.egress_failures_5m <= self.config["max_egress_failures_5m"]
            and abs(health.clock_drift_seconds) <= self.config["max_clock_drift_seconds"]
            and health.key_expiry_seconds >= self.config["min_key_expiry_seconds"]
        )

    def wait_healthy(self, node: str) -> None:
        deadline = time.monotonic() + self.config["health_timeout_seconds"]
        while time.monotonic() < deadline:
            if self.healthy(self.health(node)):
                return
            self.sleep(self.config["poll_interval_seconds"])
        raise DeploymentError("health deadline expired")

    def observe(self, node: str) -> None:
        for _ in range(self.config["canary_observations"]):
            if not self.healthy(self.health(node)):
                raise DeploymentError("canary failed observation window")
            self.sleep(self.config["poll_interval_seconds"])

    def tofu_apply(self, tfvars: str) -> None:
        with tempfile.TemporaryDirectory(prefix="onionroute-plan-") as temp:
            plan = str(Path(temp) / "deployment.tfplan")
            self.runner.run([
                "tofu", "plan", "-input=false", "-lock-timeout=5m",
                "-var-file=" + str(Path(tfvars).resolve()), "-out=" + plan,
            ], cwd=self.tofu_dir)
            self.runner.run(["tofu", "apply", "-input=false", "-auto-approve", plan], cwd=self.tofu_dir)

    def rollback(self, nodes: list[str]) -> None:
        for node in nodes:
            self.adapter("directory_command", "revoke", node)
        self.tofu_apply(self.config["rollback_tfvars"])
        for node in nodes:
            # A drain signal is intentionally irreversible in-process. Restarting is
            # required even when the old image was never replaced and the plan is empty.
            self.adapter("lifecycle_command", "restart", node)
            self.wait_healthy(node)
            self.adapter("directory_command", "activate", node)

    def deploy(self) -> None:
        self.preflight()
        changed: list[str] = []
        try:
            canary = self.config["canary_node"]
            changed.append(canary)
            self.wait_drained(canary)
            self.tofu_apply(self.config["canary_tfvars"])
            self.wait_healthy(canary)
            self.adapter("directory_command", "activate", canary)
            self.observe(canary)

            for node in self.config["rollout_nodes"]:
                changed.append(node)
                self.wait_drained(node)
            self.tofu_apply(self.config["rollout_tfvars"])
            for node in self.config["rollout_nodes"]:
                self.wait_healthy(node)
                self.adapter("directory_command", "activate", node)
        except Exception as error:
            if changed:
                try:
                    self.rollback(changed)
                except Exception as rollback_error:
                    raise DeploymentError("deployment and automatic rollback both failed") from rollback_error
            raise DeploymentError("deployment failed; rollback completed") from error

    def emergency_revoke(self, node: str) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", node):
            raise DeploymentError("node ID is invalid")
        errors = []
        for command, action in (
            ("directory_command", "revoke"),
            ("vault_revoke_command", "revoke"),
            ("isolate_command", "isolate"),
        ):
            try:
                self.adapter(command, action, node)
            except DeploymentError as error:
                errors.append(error)
        if errors:
            raise DeploymentError("emergency revoke was only partially completed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    subcommands = parser.add_subparsers(dest="operation", required=True)
    subcommands.add_parser("deploy")
    subcommands.add_parser("rollback")
    revoke = subcommands.add_parser("revoke")
    revoke.add_argument("node")
    args = parser.parse_args()

    config = load_config(args.config)
    deployment = Deployment(config, Runner())
    if args.operation == "deploy":
        deployment.deploy()
    elif args.operation == "rollback":
        deployment.preflight()
        deployment.rollback([config["canary_node"], *config["rollout_nodes"]])
    else:
        deployment.emergency_revoke(args.node)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
