#!/usr/bin/env python3
"""Validate and canonicalize the local-only route proof from stdin."""

from __future__ import annotations

import json
import re
import sys


EXPECTED_KEYS = {
    "schema",
    "ok",
    "transport",
    "gateway_id",
    "onion_service",
    "destination",
    "fixture",
    "response_sha256",
    "server_certificate_sha256",
}


def main() -> int:
    lines = [line for line in sys.stdin.read().splitlines() if line.startswith("{")]
    if not lines:
        raise SystemExit("route-proof JSON was not found")
    proof = json.loads(lines[-1])
    if set(proof) != EXPECTED_KEYS:
        raise SystemExit("route-proof fields do not match v1")
    if proof["schema"] != "onionroute.local-prototype.route-proof.v1" or proof["ok"] is not True:
        raise SystemExit("route did not pass")
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", proof["onion_service"]):
        raise SystemExit("route-proof does not contain a Tor v3 hostname")
    if proof["destination"] != "fixture.onionroute.test:18080":
        raise SystemExit("unexpected fixture destination")
    for field in ("response_sha256", "server_certificate_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", proof[field]):
            raise SystemExit(f"invalid {field}")
    print(json.dumps(proof, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

