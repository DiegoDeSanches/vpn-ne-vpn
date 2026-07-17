"""Closed-schema, privacy-safe aggregation and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Mapping


SCHEMA_KEYS = {
    "schema_version",
    "component_health",
    "error_codes",
    "coarse_os_family",
    "client_versions",
    "gateway_load_buckets",
    "latency_buckets",
    "aggregate_throughput_buckets",
    "crash_count",
}
COMPONENTS = {
    "client_core", "tor_backend", "packet_engine", "dns_engine",
    "gateway_protocol", "gateway", "directory", "token_service",
}
HEALTH = {"healthy", "degraded", "unhealthy", "unknown"}
OS_FAMILIES = {"windows", "macos", "linux", "android", "ios", "other"}
LOAD_BUCKETS = {"unknown", "low", "medium", "high", "saturated"}
LATENCY_BUCKETS = {"lt_100ms", "100_500ms", "500_2000ms", "gte_2000ms", "timeout"}
THROUGHPUT_BUCKETS = {"lt_1mbps", "1_10mbps", "10_50mbps", "gte_50mbps"}
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z]+(?:\.[0-9]+)?)?$")
ERROR_CODE = re.compile(r"^OR_[A-Z0-9_]{1,48}$")


class PrivacyViolation(ValueError):
    """Raised before a forbidden telemetry value can be serialized."""


def _bounded_counts(value: object, name: str, allowed: set[str] | None = None) -> None:
    if not isinstance(value, dict) or len(value) > 64:
        raise PrivacyViolation(f"{name} must be a bounded aggregate object")
    for key, count in value.items():
        if not isinstance(key, str) or not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise PrivacyViolation(f"invalid aggregate in {name}")
        if allowed is not None and key not in allowed:
            raise PrivacyViolation(f"unapproved {name} bucket")


def validate_telemetry(payload: Mapping[str, object], crash_consent: bool = False) -> None:
    unknown = set(payload) - SCHEMA_KEYS
    missing = SCHEMA_KEYS - set(payload)
    if unknown or missing:
        raise PrivacyViolation("telemetry schema mismatch")
    if payload["schema_version"] != 1:
        raise PrivacyViolation("unsupported telemetry schema")

    health = payload["component_health"]
    if not isinstance(health, dict) or len(health) > len(COMPONENTS):
        raise PrivacyViolation("component health must be bounded")
    for component, state in health.items():
        if component not in COMPONENTS or state not in HEALTH:
            raise PrivacyViolation("unapproved component health dimension")

    _bounded_counts(payload["error_codes"], "error_codes")
    if any(not ERROR_CODE.fullmatch(code) for code in payload["error_codes"]):
        raise PrivacyViolation("error codes must use the closed OR_* namespace")
    _bounded_counts(payload["coarse_os_family"], "coarse_os_family", OS_FAMILIES)
    _bounded_counts(payload["client_versions"], "client_versions")
    if any(not VERSION.fullmatch(version) for version in payload["client_versions"]):
        raise PrivacyViolation("client version must be semantic and contain no build identity")
    _bounded_counts(payload["gateway_load_buckets"], "gateway_load_buckets", LOAD_BUCKETS)
    _bounded_counts(payload["latency_buckets"], "latency_buckets", LATENCY_BUCKETS)
    _bounded_counts(
        payload["aggregate_throughput_buckets"],
        "aggregate_throughput_buckets",
        THROUGHPUT_BUCKETS,
    )

    crashes = payload["crash_count"]
    if crashes is not None and (
        not crash_consent or not isinstance(crashes, int) or isinstance(crashes, bool) or crashes < 0
    ):
        raise PrivacyViolation("crash count requires explicit consent and a non-negative count")


@dataclass
class AggregateTelemetry:
    component_health: dict[str, str] = field(default_factory=dict)
    error_codes: dict[str, int] = field(default_factory=dict)
    coarse_os_family: dict[str, int] = field(default_factory=dict)
    client_versions: dict[str, int] = field(default_factory=dict)
    gateway_load_buckets: dict[str, int] = field(default_factory=dict)
    latency_buckets: dict[str, int] = field(default_factory=dict)
    aggregate_throughput_buckets: dict[str, int] = field(default_factory=dict)
    crash_count: int | None = None

    def to_dict(self, crash_consent: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": 1,
            "component_health": dict(self.component_health),
            "error_codes": dict(self.error_codes),
            "coarse_os_family": dict(self.coarse_os_family),
            "client_versions": dict(self.client_versions),
            "gateway_load_buckets": dict(self.gateway_load_buckets),
            "latency_buckets": dict(self.latency_buckets),
            "aggregate_throughput_buckets": dict(self.aggregate_throughput_buckets),
            "crash_count": self.crash_count,
        }
        validate_telemetry(payload, crash_consent=crash_consent)
        return payload

    def serialize(self, crash_consent: bool = False) -> bytes:
        return json.dumps(
            self.to_dict(crash_consent=crash_consent),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
