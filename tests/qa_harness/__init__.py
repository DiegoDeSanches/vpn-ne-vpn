"""Shared, dependency-free OnionRoute QA harness.

The package is test-only. It models fail-closed invariants and provides a
loopback transport stand; it is not a VPN, a Tor implementation, or evidence of
production anonymity.
"""

from .model import AnonymityMode, ConnectionState, TrafficKind, TunnelModel

__all__ = ["AnonymityMode", "ConnectionState", "TrafficKind", "TunnelModel"]
