from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.privacy import AggregateTelemetry, PrivacyViolation, validate_telemetry


def valid_payload() -> dict[str, object]:
    return AggregateTelemetry(
        component_health={"client_core": "healthy", "tor_backend": "degraded"},
        error_codes={"OR_TOR_UNAVAILABLE": 2},
        coarse_os_family={"windows": 10},
        client_versions={"0.1.0": 10},
        gateway_load_buckets={"medium": 3},
        latency_buckets={"100_500ms": 9},
        aggregate_throughput_buckets={"10_50mbps": 4},
    ).to_dict()


class PrivacyObservabilityTests(unittest.TestCase):
    def test_only_allowlisted_aggregates_serialize(self) -> None:
        payload = valid_payload()
        validate_telemetry(payload)
        rendered = AggregateTelemetry().serialize()
        for forbidden in (b"destination", b"account_id", b"token_id", b"device_id", b"timeline"):
            self.assertNotIn(forbidden, rendered)

    def test_forbidden_dimensions_are_rejected(self) -> None:
        for key, value in (
            ("ip", "192.0.2.1"),
            ("domain", "canary.invalid"),
            ("destination_address", "198.51.100.2"),
            ("account_id", "acct-test"),
            ("token_id", "token-test"),
            ("stable_device_id", "device-test"),
            ("timestamp", 1234567890),
        ):
            with self.subTest(key=key):
                payload = valid_payload()
                payload[key] = value
                with self.assertRaises(PrivacyViolation):
                    validate_telemetry(payload)

    def test_crash_count_requires_consent(self) -> None:
        payload = valid_payload()
        payload["crash_count"] = 1
        with self.assertRaises(PrivacyViolation):
            validate_telemetry(payload, crash_consent=False)
        validate_telemetry(payload, crash_consent=True)

    def test_exact_os_and_build_identifiers_are_rejected(self) -> None:
        payload = valid_payload()
        payload["coarse_os_family"] = {"Windows 11 24H2 build 26100": 1}
        with self.assertRaises(PrivacyViolation):
            validate_telemetry(payload)
        payload = valid_payload()
        payload["client_versions"] = {"0.1.0+device-7342": 1}
        with self.assertRaises(PrivacyViolation):
            validate_telemetry(payload)


if __name__ == "__main__":
    unittest.main()
