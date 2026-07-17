"""Deterministic safety model used by lifecycle, leak, and chaos suites.

TEST ONLY: the model is an oracle for externally observable invariants. It does
not replace packet captures, platform firewall tests, or real Tor staging.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class AnonymityMode(str, Enum):
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"
    DIRECT_TOR = "direct_tor"


class ConnectionState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ROTATING = "rotating"
    RECONNECTING = "reconnecting"
    BLOCKED = "blocked"
    STOPPING = "stopping"


class TrafficKind(str, Enum):
    DNS = "dns"
    IPV4_TCP = "ipv4_tcp"
    IPV6 = "ipv6"
    WEBRTC = "webrtc"
    QUIC = "quic"
    DOH = "doh"
    DOT = "dot"
    APPLICATION_FALLBACK = "application_fallback"
    LOCAL_NETWORK = "local_network"


@dataclass(frozen=True)
class TrafficObservation:
    outcome: str
    physical_traffic: tuple[str, ...] = ()
    visible_layers: tuple[str, ...] = ()
    system_dns_calls: int = 0
    reason: str = ""

    @property
    def leaked(self) -> bool:
        return self.outcome == "direct" or self.system_dns_calls != 0 or any(
            item in {"destination", "dns", "ipv6", "quic", "local_lan"}
            for item in self.physical_traffic
        )


@dataclass(frozen=True)
class CatalogState:
    signed: bool = True
    expired: bool = False
    revoked: bool = False

    @property
    def usable(self) -> bool:
        return self.signed and not self.expired and not self.revoked


@dataclass
class TunnelModel:
    mode: AnonymityMode = AnonymityMode.STANDARD
    state: ConnectionState = ConnectionState.DISCONNECTED
    kill_switch: bool = False
    active_path: bool = False
    tor_alive: bool = False
    token_valid: bool = True
    catalog: CatalogState = field(default_factory=CatalogState)
    country: str = "ZZ"
    route_generation: int = 0
    dns_generation: int = 0
    direct_fallback_attempts: int = 0
    events: list[str] = field(default_factory=list)

    def first_launch(self) -> None:
        self.events.append("first_launch")
        self.begin_connect()

    def begin_connect(self) -> None:
        if self.state not in {ConnectionState.DISCONNECTED, ConnectionState.BLOCKED}:
            raise RuntimeError("connect is only valid from disconnected or blocked")
        self.kill_switch = True
        self.state = ConnectionState.CONNECTING
        self.active_path = False
        self.events.extend(("kill_switch_engaged", "connect_started"))

    def complete_connect(self) -> bool:
        if self.state not in {ConnectionState.CONNECTING, ConnectionState.RECONNECTING}:
            raise RuntimeError("no connection attempt is active")
        if not self.tor_alive:
            self.state = ConnectionState.BLOCKED
            self.events.append("connect_rejected_tor")
            return False
        if self.mode is not AnonymityMode.DIRECT_TOR and not self.catalog.usable:
            self.state = ConnectionState.BLOCKED
            self.events.append("connect_rejected_directory")
            return False
        if self.mode is not AnonymityMode.DIRECT_TOR and not self.token_valid:
            self.state = ConnectionState.BLOCKED
            self.events.append("connect_rejected_token")
            return False
        self.active_path = True
        self.state = ConnectionState.CONNECTED
        self.route_generation += 1
        self.events.append("protected_path_active")
        return True

    def connect(self) -> bool:
        self.begin_connect()
        self.tor_alive = True
        return self.complete_connect()

    def begin_disconnect(self) -> None:
        if self.state is ConnectionState.DISCONNECTED:
            return
        self.state = ConnectionState.STOPPING
        self.active_path = False
        self.kill_switch = True
        self.events.extend(("application_blocked", "shutdown_started"))

    def complete_disconnect(self, cleanup_verified: bool = True) -> None:
        if self.state is not ConnectionState.STOPPING:
            raise RuntimeError("shutdown is not active")
        self.tor_alive = False
        if cleanup_verified:
            self.state = ConnectionState.DISCONNECTED
            self.kill_switch = False
            self.events.extend(("cleanup_verified", "kill_switch_released"))
        else:
            self.state = ConnectionState.BLOCKED
            self.kill_switch = True
            self.events.append("cleanup_uncertain_blocked")

    def begin_rotation(self, hard: bool = False) -> None:
        if self.state is not ConnectionState.CONNECTED or not self.active_path:
            raise RuntimeError("rotation requires an active protected path")
        self.state = ConnectionState.ROTATING
        self.kill_switch = True
        self.events.append("hard_rotation_started" if hard else "soft_rotation_started")

    def complete_rotation(self, replacement_ready: bool, old_path_healthy: bool = True) -> bool:
        if self.state is not ConnectionState.ROTATING:
            raise RuntimeError("rotation is not active")
        if replacement_ready:
            self.route_generation += 1
            self.dns_generation += 1
            self.active_path = True
            self.state = ConnectionState.CONNECTED
            self.events.append("rotation_committed")
            return True
        if old_path_healthy:
            self.active_path = True
            self.state = ConnectionState.CONNECTED
            self.events.append("rotation_rolled_back")
            return False
        self.active_path = False
        self.state = ConnectionState.RECONNECTING
        self.events.append("rotation_failed_blocked")
        return False

    def change_country(self, country: str) -> bool:
        self.begin_rotation()
        self.country = country
        return self.complete_rotation(replacement_ready=True)

    def reset_identity(self) -> bool:
        self.begin_rotation(hard=True)
        changed = self.complete_rotation(replacement_ready=True)
        self.events.append("identity_reset")
        return changed

    def inject_failure(self, fault: str) -> None:
        self.events.append(f"fault:{fault}")
        if fault == "ui_crash":
            # The privileged daemon and its kill-switch generation survive.
            return
        if fault in {"disk_full", "memory_pressure"}:
            # Existing bounded flows may remain, but new allocation is denied.
            self.events.append("new_allocations_blocked")
            return
        if fault in {"database_outage", "kms_outage", "directory_signing_outage"}:
            # Existing data-plane sessions do not depend on control-plane health.
            self.events.append("control_plane_degraded")
            return
        if fault == "directory_expiry":
            self.catalog = CatalogState(signed=True, expired=True)
        elif fault == "directory_revocation":
            self.catalog = CatalogState(signed=True, revoked=True)
        elif fault == "token_expiry":
            self.token_valid = False
        elif fault in {"tor_crash", "process_kill_tor"}:
            self.tor_alive = False
        self.active_path = False
        self.kill_switch = True
        self.state = ConnectionState.RECONNECTING

    def attempt_reconnect(self) -> bool:
        self.state = ConnectionState.RECONNECTING
        result = self.complete_connect()
        if not result:
            self.direct_fallback_attempts += 0
        return result

    def observe(self, kind: TrafficKind) -> TrafficObservation:
        protected_state = self.state in {ConnectionState.CONNECTED, ConnectionState.ROTATING}
        if not protected_state or not self.active_path:
            return TrafficObservation(outcome="blocked", reason="no_verified_protected_path")

        if kind in {TrafficKind.IPV6, TrafficKind.WEBRTC, TrafficKind.QUIC}:
            return TrafficObservation(outcome="blocked", reason="unsupported_udp_or_ipv6")
        if kind in {TrafficKind.APPLICATION_FALLBACK, TrafficKind.LOCAL_NETWORK}:
            return TrafficObservation(outcome="blocked", reason="kill_switch_policy")

        visible = ("tor_exit",) if self.mode is AnonymityMode.DIRECT_TOR else ("private_exit",)
        return TrafficObservation(
            outcome="protected",
            physical_traffic=("tor_transport",),
            visible_layers=visible,
            system_dns_calls=0,
        )

    def assert_fail_closed(self, kinds: Iterable[TrafficKind] = tuple(TrafficKind)) -> None:
        for kind in kinds:
            observation = self.observe(kind)
            if observation.leaked:
                raise AssertionError(f"{kind.value} leaked in {self.state.value}")
        if not self.kill_switch and self.state is not ConnectionState.DISCONNECTED:
            raise AssertionError("kill switch is not engaged in a tunnel lifecycle state")
        if self.direct_fallback_attempts:
            raise AssertionError("direct fallback was attempted")
