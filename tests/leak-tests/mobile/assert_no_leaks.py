#!/usr/bin/env python3
"""Fail a captured physical-interface pcap on DNS, QUIC or unapproved egress."""

from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import shutil
import subprocess
import sys


def tshark_lines(pcap: pathlib.Path, display_filter: str, fields: list[str]) -> list[str]:
    command = [
        "tshark", "-r", str(pcap), "-Y", display_filter,
        "-T", "fields", "-E", "separator=\\t", "-E", "occurrence=f",
    ]
    for field in fields:
        command.extend(["-e", field])
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "tshark failed")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=pathlib.Path)
    parser.add_argument("policy", type=pathlib.Path)
    arguments = parser.parse_args()

    if shutil.which("tshark") is None:
        print("FAIL: tshark is required", file=sys.stderr)
        return 2
    if not arguments.pcap.is_file() or not arguments.policy.is_file():
        print("FAIL: missing pcap or policy", file=sys.stderr)
        return 2

    policy = json.loads(arguments.policy.read_text(encoding="utf-8"))
    allowed = [ipaddress.ip_network(value) for value in policy["allowed_physical_cidrs"]]
    failures: list[str] = []

    dns = tshark_lines(arguments.pcap, "dns || udp.port == 53 || tcp.port == 53", ["frame.number"])
    if dns:
        failures.append(f"physical DNS frames: {dns[:10]}")

    quic = tshark_lines(arguments.pcap, "quic || udp.port == 443", ["frame.number"])
    if quic:
        failures.append(f"physical QUIC/UDP443 frames: {quic[:10]}")

    destinations = tshark_lines(
        arguments.pcap,
        "ip || ipv6",
        ["frame.number", "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport"],
    )
    for line in destinations:
        columns = (line.split("\t") + [""] * 5)[:5]
        frame, ipv4, ipv6, tcp_port, udp_port = columns
        address_text = ipv4 or ipv6
        if not address_text:
            continue
        address = ipaddress.ip_address(address_text)
        if not any(address in network for network in allowed):
            failures.append(
                f"frame {frame}: unapproved physical destination {address_text} "
                f"tcp={tcp_port} udp={udp_port}"
            )
            if len(failures) >= 50:
                break

    raw_capture = arguments.pcap.read_bytes()
    for forbidden in policy.get("forbidden_utf8", []):
        encoded = forbidden.encode("utf-8")
        if encoded and encoded in raw_capture:
            failures.append(f"forbidden plaintext present: {forbidden!r}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("PASS: no DNS, QUIC, plaintext marker, or unapproved destination on physical capture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

