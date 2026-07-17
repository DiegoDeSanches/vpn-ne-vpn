"""Fail-closed release qualification rules."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping, Sequence


BLOCKING_GATES = {
    "clearnet_leak",
    "isp_dns",
    "ipv6_bypass",
    "unsigned_directory_accepted",
    "expired_token_accepted",
    "unbounded_protocol_allocation",
    "kill_switch_lost_on_ui_crash",
    "direct_reconnect_fallback",
    "destination_in_telemetry",
}
REQUIRED_ENVIRONMENTS = {"staging_real_onion", "multi_region_staging", "adversarial"}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class Qualification:
    qualified: bool
    blockers: tuple[str, ...]


def qualify(evidence: Mapping[str, object]) -> Qualification:
    blockers: list[str] = []
    candidate_digest = evidence.get("release_candidate_digest")
    if not isinstance(candidate_digest, str) or not DIGEST.fullmatch(candidate_digest):
        blockers.append("immutable release candidate digest is missing")
    raw_environments = evidence.get("environments")
    if (
        not isinstance(raw_environments, Sequence)
        or isinstance(raw_environments, (str, bytes))
        or any(not isinstance(item, str) for item in raw_environments)
    ):
        blockers.append("release environment inventory is invalid")
        environments: set[str] = set()
    else:
        environments = set(raw_environments)
    missing_environments = REQUIRED_ENVIRONMENTS - environments
    if missing_environments:
        blockers.append("missing release environment evidence: " + ", ".join(sorted(missing_environments)))

    gates = evidence.get("blocking_gates")
    if not isinstance(gates, dict):
        blockers.append("blocking gate results are missing")
    else:
        for gate in sorted(BLOCKING_GATES):
            if gates.get(gate) is not False:
                blockers.append(f"blocking condition present or unproven: {gate}")

    findings = evidence.get("security_regressions")
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        blockers.append("security regression inventory is missing")
    else:
        for finding in findings:
            if not isinstance(finding, dict) or not finding.get("owner"):
                blockers.append("security regression has no owner")
                break

    reports = evidence.get("reports")
    if not isinstance(reports, Sequence) or isinstance(reports, (str, bytes)) or not reports:
        blockers.append("automated test reports are missing")
    else:
        proven_environments: set[str] = set()
        for report in reports:
            if not isinstance(report, dict):
                blockers.append("invalid automated test report reference")
                continue
            digest = report.get("artifact_digest")
            environment = report.get("environment")
            if (
                report.get("kind") != "release_evidence_bundle"
                or report.get("passed") is not True
                or report.get("synthetic_traffic") is not True
                or report.get("release_candidate_digest") != candidate_digest
                or not isinstance(digest, str)
                or not DIGEST.fullmatch(digest)
                or environment not in REQUIRED_ENVIRONMENTS
            ):
                blockers.append("invalid or mismatched release evidence bundle")
                continue
            proven_environments.add(str(environment))
        missing_reports = REQUIRED_ENVIRONMENTS - proven_environments
        if missing_reports:
            blockers.append("missing environment report bundles: " + ", ".join(sorted(missing_reports)))
    return Qualification(not blockers, tuple(blockers))
