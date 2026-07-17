"""Executable loopback route with a strict Mock Tor SOCKS boundary.

TEST ONLY: private hops are bounded TCP forwarders. Enhanced/Maximum transport
encryption is deliberately not simulated and must be proven by the real staging
suite. The stand validates topology, lifecycle wiring, backpressure, and absence
of a direct client socket to the controlled destination.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import time

from .model import AnonymityMode


Address = tuple[str, int]
MAX_CHUNK = 64 * 1024


@dataclass(frozen=True)
class FaultProfile:
    latency_ms: int = 0
    bandwidth_bytes_per_second: int = 0
    drop_connection: bool = False


@dataclass(frozen=True)
class ProbeEvidence:
    mode: str
    bootstrap_ms: float
    connect_ms: float
    time_to_first_byte_ms: float
    total_ms: float
    bytes_round_trip: int
    physical_traffic: tuple[str, ...]
    gateway_roles: tuple[str, ...]
    tor_target_class: str


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass


async def _pipe(
    source: asyncio.StreamReader,
    destination: asyncio.StreamWriter,
    fault: FaultProfile,
) -> None:
    while True:
        chunk = await source.read(MAX_CHUNK)
        if not chunk:
            try:
                destination.write_eof()
                await destination.drain()
            except (AttributeError, ConnectionError, OSError):
                pass
            return
        if fault.latency_ms:
            await asyncio.sleep(fault.latency_ms / 1000.0)
        if fault.bandwidth_bytes_per_second:
            await asyncio.sleep(len(chunk) / fault.bandwidth_bytes_per_second)
        destination.write(chunk)
        await destination.drain()


class _TcpServer:
    def __init__(self) -> None:
        self.server: asyncio.AbstractServer | None = None
        self.active_writers: set[asyncio.StreamWriter] = set()

    @property
    def address(self) -> Address:
        if self.server is None or not self.server.sockets:
            raise RuntimeError("server is not running")
        host, port = self.server.sockets[0].getsockname()[:2]
        return str(host), int(port)

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        writers = list(self.active_writers)
        self.active_writers.clear()
        await asyncio.gather(*(_close(writer) for writer in writers), return_exceptions=True)


class ControlledDestination(_TcpServer):
    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=MAX_CHUNK)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.active_writers.add(writer)
        try:
            while True:
                chunk = await reader.read(MAX_CHUNK)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        finally:
            self.active_writers.discard(writer)
            await _close(writer)


class TcpForwarder(_TcpServer):
    def __init__(self, role: str, upstream: Address, fault: FaultProfile | None = None) -> None:
        super().__init__()
        self.role = role
        self.upstream = upstream
        self.fault = fault or FaultProfile()
        self.connection_count = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=MAX_CHUNK)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connection_count += 1
        self.active_writers.add(writer)
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            if self.fault.drop_connection:
                return
            upstream_reader, upstream_writer = await asyncio.open_connection(*self.upstream, limit=MAX_CHUNK)
            self.active_writers.add(upstream_writer)
            await asyncio.gather(
                _pipe(reader, upstream_writer, self.fault),
                _pipe(upstream_reader, writer, self.fault),
            )
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            return
        finally:
            self.active_writers.discard(writer)
            await _close(writer)
            if upstream_writer is not None:
                self.active_writers.discard(upstream_writer)
                await _close(upstream_writer)


class MockTorSocks(_TcpServer):
    """Minimal authenticated SOCKS5 router with no clearnet fallback."""

    def __init__(self, routes: dict[str, tuple[Address, str]], allow_direct_tor: bool) -> None:
        super().__init__()
        self.routes = dict(routes)
        self.allow_direct_tor = allow_direct_tor
        self.target_classes: list[str] = []

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=MAX_CHUNK)

    async def _reject(self, writer: asyncio.StreamWriter, status: int = 2) -> None:
        writer.write(bytes((5, status, 0, 1, 0, 0, 0, 0, 0, 0)))
        await writer.drain()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.active_writers.add(writer)
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            version, method_count = await reader.readexactly(2)
            methods = await reader.readexactly(method_count)
            if version != 5 or 2 not in methods:
                writer.write(bytes((5, 255)))
                await writer.drain()
                return
            writer.write(bytes((5, 2)))
            await writer.drain()

            auth_version, user_length = await reader.readexactly(2)
            username = await reader.readexactly(user_length)
            password_length = (await reader.readexactly(1))[0]
            password = await reader.readexactly(password_length)
            if auth_version != 1 or not username or len(password) < 8:
                writer.write(bytes((1, 1)))
                await writer.drain()
                return
            writer.write(bytes((1, 0)))
            await writer.drain()

            version, command, reserved, address_type = await reader.readexactly(4)
            if (version, command, reserved, address_type) != (5, 1, 0, 3):
                await self._reject(writer, 8)
                return
            host_length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(host_length)).decode("ascii", "strict").lower()
            await reader.readexactly(2)  # The test topology supplies the mapped loopback port.
            route = self.routes.get(host)
            if route is None:
                await self._reject(writer, 4)
                return
            upstream, target_class = route
            if target_class == "public_tor_exit" and not self.allow_direct_tor:
                await self._reject(writer, 2)
                return
            if target_class == "onion_service" and not host.endswith(".onion"):
                await self._reject(writer, 2)
                return
            upstream_reader, upstream_writer = await asyncio.open_connection(*upstream, limit=MAX_CHUNK)
            self.active_writers.add(upstream_writer)
            self.target_classes.append(target_class)
            writer.write(bytes((5, 0, 0, 1, 0, 0, 0, 0, 0, 0)))
            await writer.drain()
            await asyncio.gather(
                _pipe(reader, upstream_writer, FaultProfile()),
                _pipe(upstream_reader, writer, FaultProfile()),
            )
        except (ConnectionError, OSError, UnicodeError, asyncio.IncompleteReadError):
            return
        finally:
            self.active_writers.discard(writer)
            await _close(writer)
            if upstream_writer is not None:
                self.active_writers.discard(upstream_writer)
                await _close(upstream_writer)


class MockRouteEnvironment:
    """Application -> Mock Tor -> 0/1/2/3 private hops -> fixture."""

    def __init__(
        self,
        mode: AnonymityMode,
        hop_faults: dict[str, FaultProfile] | None = None,
    ) -> None:
        self.mode = mode
        self.hop_faults = hop_faults or {}
        self.destination = ControlledDestination()
        self.forwarders: list[TcpForwarder] = []
        self.tor: MockTorSocks | None = None
        self.bootstrap_ms = 0.0

    async def __aenter__(self) -> "MockRouteEnvironment":
        started = time.perf_counter()
        await self.destination.start()
        upstream = self.destination.address
        roles_by_mode = {
            AnonymityMode.STANDARD: ("exit",),
            AnonymityMode.ENHANCED: ("entry", "exit"),
            AnonymityMode.MAXIMUM: ("entry", "relay", "exit"),
            AnonymityMode.DIRECT_TOR: (),
        }
        roles = roles_by_mode[self.mode]
        created_reversed: list[TcpForwarder] = []
        for role in reversed(roles):
            forwarder = TcpForwarder(role, upstream, self.hop_faults.get(role))
            await forwarder.start()
            created_reversed.append(forwarder)
            upstream = forwarder.address
        self.forwarders = list(reversed(created_reversed))

        if self.mode is AnonymityMode.DIRECT_TOR:
            routes = {"fixture.invalid": (self.destination.address, "public_tor_exit")}
        else:
            routes = {"qa-entry.onion": (upstream, "onion_service")}
        self.tor = MockTorSocks(routes, allow_direct_tor=self.mode is AnonymityMode.DIRECT_TOR)
        await self.tor.start()
        self.bootstrap_ms = (time.perf_counter() - started) * 1000.0
        return self

    async def __aexit__(self, *_: object) -> None:
        if self.tor is not None:
            await self.tor.stop()
        for forwarder in self.forwarders:
            await forwarder.stop()
        await self.destination.stop()

    async def kill(self, role: str) -> None:
        if role == "tor":
            if self.tor is not None:
                await self.tor.stop()
            return
        for forwarder in self.forwarders:
            if forwarder.role == role:
                await forwarder.stop()
                return
        raise ValueError(f"unknown process role: {role}")

    async def probe(self, payload: bytes = b"TEST ONLY ONIONROUTE ROUTE PROBE") -> ProbeEvidence:
        if not payload or len(payload) > 4 * 1024 * 1024:
            raise ValueError("probe payload must be between 1 byte and 4 MiB")
        if self.tor is None:
            raise RuntimeError("environment is not running")
        started = time.perf_counter()
        reader, writer = await asyncio.open_connection(*self.tor.address, limit=MAX_CHUNK)
        try:
            writer.write(bytes((5, 1, 2)))
            await writer.drain()
            if await reader.readexactly(2) != bytes((5, 2)):
                raise ConnectionError("Mock Tor did not require isolation authentication")
            username = b"or-test"
            password = b"TEST-ONLY-ISOLATION"
            writer.write(bytes((1, len(username))) + username + bytes((len(password),)) + password)
            await writer.drain()
            if await reader.readexactly(2) != bytes((1, 0)):
                raise ConnectionError("Mock Tor rejected isolation authentication")
            host = b"fixture.invalid" if self.mode is AnonymityMode.DIRECT_TOR else b"qa-entry.onion"
            writer.write(bytes((5, 1, 0, 3, len(host))) + host + bytes((1, 187)))
            await writer.drain()
            reply = await reader.readexactly(10)
            if reply[1] != 0:
                raise ConnectionError(f"Mock Tor connect failed with status {reply[1]}")
            connected = time.perf_counter()
            writer.write(payload)
            try:
                writer.write_eof()
            except (AttributeError, OSError):
                pass
            await writer.drain()
            first = await reader.read(1)
            if not first:
                raise ConnectionError("protected route returned no data")
            first_byte = time.perf_counter()
            response = first + await reader.read()
            finished = time.perf_counter()
            if response != payload:
                raise AssertionError("controlled destination response mismatch")
        finally:
            await _close(writer)

        roles = tuple(
            forwarder.role for forwarder in self.forwarders if forwarder.connection_count > 0
        )
        target_class = self.tor.target_classes[-1]
        return ProbeEvidence(
            mode=self.mode.value,
            bootstrap_ms=self.bootstrap_ms,
            connect_ms=(connected - started) * 1000.0,
            time_to_first_byte_ms=(first_byte - connected) * 1000.0,
            total_ms=(finished - started) * 1000.0,
            bytes_round_trip=len(response),
            physical_traffic=("tor_transport",),
            gateway_roles=roles,
            tor_target_class=target_class,
        )
