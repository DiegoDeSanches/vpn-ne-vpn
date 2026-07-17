from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from qa_harness.release import BLOCKING_GATES, REQUIRED_ENVIRONMENTS, qualify


def clean_evidence() -> dict[str, object]:
    candidate = "sha256:" + "1" * 64
    return {
        "release_candidate_digest": candidate,
        "environments": sorted(REQUIRED_ENVIRONMENTS),
        "blocking_gates": {gate: False for gate in BLOCKING_GATES},
        "security_regressions": [],
        "reports": [
            {
                "environment": environment,
                "kind": "release_evidence_bundle",
                "artifact_digest": "sha256:" + str(index + 2) * 64,
                "release_candidate_digest": candidate,
                "passed": True,
                "synthetic_traffic": True,
            }
            for index, environment in enumerate(sorted(REQUIRED_ENVIRONMENTS))
        ],
    }


class ReleaseQualificationTests(unittest.TestCase):
    def test_complete_clean_external_evidence_qualifies(self) -> None:
        result = qualify(clean_evidence())
        self.assertTrue(result.qualified)
        self.assertEqual(result.blockers, ())

    def test_each_mandatory_condition_blocks_release(self) -> None:
        for gate in BLOCKING_GATES:
            with self.subTest(gate=gate):
                evidence = clean_evidence()
                evidence["blocking_gates"][gate] = True
                self.assertFalse(qualify(evidence).qualified)

    def test_unproven_gate_and_mock_only_evidence_block_release(self) -> None:
        evidence = clean_evidence()
        del evidence["blocking_gates"]["clearnet_leak"]
        evidence["environments"] = ["mock_tor"]
        result = qualify(evidence)
        self.assertFalse(result.qualified)
        self.assertTrue(any("unproven" in item for item in result.blockers))
        self.assertTrue(any("environment" in item for item in result.blockers))

    def test_security_regression_requires_owner(self) -> None:
        evidence = clean_evidence()
        evidence["security_regressions"] = [{"id": "SEC-TEST", "owner": ""}]
        self.assertFalse(qualify(evidence).qualified)

    def test_report_for_a_different_candidate_is_rejected(self) -> None:
        evidence = clean_evidence()
        evidence["reports"][0]["release_candidate_digest"] = "sha256:" + "9" * 64
        self.assertFalse(qualify(evidence).qualified)

    def test_malformed_environment_inventory_fails_closed(self) -> None:
        evidence = clean_evidence()
        evidence["environments"] = [{"name": "adversarial"}]
        self.assertFalse(qualify(evidence).qualified)


if __name__ == "__main__":
    unittest.main()
