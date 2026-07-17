# Leak tests

OS/network packet-capture assertions are specified in `docs/integration-plan.md`.
Any unexpected DNS, IPv6, QUIC, direct destination, or fail-open packet is a test
failure; there is no development fallback exception.

`test_leak_invariants.py` даёт быстрый state oracle для DNS/IPv4/IPv6/WebRTC/
QUIC/DoH/DoT/app/LAN и transition windows. Он дополняет, но не заменяет pcap.
Mobile evidence runner fail-closed требует capture для каждого case.
