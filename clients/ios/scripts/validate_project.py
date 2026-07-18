#!/usr/bin/env python3
"""Validate the checked-in iOS project contract without Xcode or signing data."""

from __future__ import annotations

import pathlib
import plistlib
import re
import sys


IOS_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = IOS_ROOT.parents[1]


def require(condition: bool, message: str, failures: list[str]) -> None:
    if condition:
        print(f"PASS: {message}")
    else:
        print(f"FAIL: {message}", file=sys.stderr)
        failures.append(message)


def load_plist(relative: str, failures: list[str]) -> dict[str, object]:
    path = IOS_ROOT / relative
    try:
        with path.open("rb") as stream:
            value = plistlib.load(stream)
        require(isinstance(value, dict), f"{relative} is a dictionary plist", failures)
        return value if isinstance(value, dict) else {}
    except (OSError, plistlib.InvalidFileException) as error:
        require(False, f"{relative} parses: {error}", failures)
        return {}


def main() -> int:
    failures: list[str] = []
    project = (IOS_ROOT / "project.yml").read_text(encoding="utf-8")
    provider = (IOS_ROOT / "PacketTunnel/PacketTunnelProvider.swift").read_text(
        encoding="utf-8"
    )
    rust_core = (IOS_ROOT / "Shared/RustCore.swift").read_text(encoding="utf-8")
    tunnel_manager = (IOS_ROOT / "OnionRouteApp/TunnelManager.swift").read_text(
        encoding="utf-8"
    )
    header = (REPO_ROOT / "crates/mobile-ffi/include/onionroute_mobile.h").read_text(
        encoding="utf-8"
    )
    mobile_ffi = (REPO_ROOT / "crates/mobile-ffi/src/lib.rs").read_text(
        encoding="utf-8"
    )
    factory = (REPO_ROOT / "crates/client-core/src/factory.rs").read_text(
        encoding="utf-8"
    )
    embedded_tor = (REPO_ROOT / "crates/tor-backend/src/embedded.rs").read_text(
        encoding="utf-8"
    )

    app_info = load_plist("OnionRouteApp/Info.plist", failures)
    tunnel_info = load_plist("PacketTunnel/Info.plist", failures)
    app_entitlements = load_plist("OnionRouteApp/OnionRouteApp.entitlements", failures)
    tunnel_entitlements = load_plist("PacketTunnel/PacketTunnel.entitlements", failures)

    extension = tunnel_info.get("NSExtension", {})
    require(
        isinstance(extension, dict)
        and extension.get("NSExtensionPointIdentifier")
        == "com.apple.networkextension.packet-tunnel",
        "PacketTunnel declares the packet-tunnel extension point",
        failures,
    )
    require(
        app_info.get("CFBundleIdentifier") == "$(PRODUCT_BUNDLE_IDENTIFIER)",
        "containing app bundle identifier comes from the build setting",
        failures,
    )
    for label, info in (("app", app_info), ("extension", tunnel_info)):
        require(
            info.get("CFBundleExecutable") == "$(EXECUTABLE_NAME)"
            and info.get("CFBundlePackageType")
            == "$(PRODUCT_BUNDLE_PACKAGE_TYPE)",
            f"{label} declares installable executable bundle metadata",
            failures,
        )

    for label, entitlements in (
        ("app", app_entitlements),
        ("extension", tunnel_entitlements),
    ):
        require(
            "packet-tunnel-provider"
            in entitlements.get(
                "com.apple.developer.networking.networkextension", []
            ),
            f"{label} has the packet-tunnel-provider entitlement",
            failures,
        )
        require(
            "group.org.onionroute.mobile"
            in entitlements.get("com.apple.security.application-groups", []),
            f"{label} has the shared App Group",
            failures,
        )

    require(
        project.count("Frameworks/OnionRouteMobileFFI.xcframework") == 2,
        "both Swift targets link the generated mobile FFI XCFramework",
        failures,
    )
    require(
        "OTHER_LDFLAGS" not in project and "LIBRARY_SEARCH_PATHS" not in project,
        "project has no stale raw static-library linker configuration",
        failures,
    )
    require(
        "#define OR_ABI_MINOR 1u" in header
        and "or_client_poll_packet" in header
        and "OR_STATUS_BUFFER_TOO_SMALL" in header,
        "C header exposes the compatible ABI 1.1 packet-output contract",
        failures,
    )
    require(
        "or_client_poll_packet" in rust_core and "packetFlow.writePackets" in provider,
        "Rust packet output reaches NEPacketTunnelFlow",
        failures,
    )
    require(
        "packets.prefix" not in provider
        and "PacketBatchBudget.standard.endIndex" in provider,
        "input batches advance through every platform packet",
        failures,
    )
    require(
        "NEIPv4Route.default()" in provider
        and "NEIPv6Route.default()" in provider
        and "NEDNSSettings" in provider,
        "TUN claims default IPv4, IPv6 and protected DNS routes",
        failures,
    )
    require(
        "includeAllNetworks = true" in tunnel_manager
        and "isOnDemandEnabled = true" in tunnel_manager,
        "provider requests include-all routing and VPN On Demand",
        failures,
    )
    require(
        "protectedCoreReady" not in provider + rust_core
        and "or_client_set_core_ready" not in rust_core,
        "platform never fabricates a protected-core health proof",
        failures,
    )
    require(
        "install_client_runtime_factory" in mobile_ffi
        and "run_mobile_runtime" in mobile_ffi
        and "protected_path_healthy" in factory,
        "Connected is derived by the installed bounded Rust runtime factory",
        failures,
    )
    require(
        "onionroute_embedded_ctor_sys::run" in embedded_tor
        and "ControlClient::connect_and_authenticate" in embedded_tor
        and "SIGNAL SHUTDOWN" in embedded_tor,
        "iOS embedded C Tor uses the stable runner and authenticated control lifecycle",
        failures,
    )
    require(
        "private func drainEvents()" in provider
        and "guard acceptingPackets, let core" not in provider,
        "event polling remains active while the packet pump waits for Connected",
        failures,
    )
    direct_egress = re.compile(r"\b(URLSession|NWConnection|getaddrinfo|socket\s*\()")
    require(
        direct_egress.search(provider + tunnel_manager + rust_core) is None,
        "Swift adapter has no direct socket or system resolver fallback",
        failures,
    )

    if failures:
        print(f"FAIL: {len(failures)} iOS project contract check(s)", file=sys.stderr)
        return 1
    print("PASS: iOS project contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
