from __future__ import annotations

import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MATRIX = json.loads((pathlib.Path(__file__).parent / "matrix.json").read_text(encoding="utf-8"))


class CompatibilityMatrixTests(unittest.TestCase):
    def test_platform_floor_sources_exist_and_architectures_are_bounded(self) -> None:
        self.assertGreaterEqual(len(MATRIX["platforms"]), 8)
        for lane in MATRIX["platforms"]:
            self.assertTrue((ROOT / lane["source"]).is_file(), lane["source"])
            self.assertIn(lane["architecture"], {"x64", "x86_64", "arm64", "arm64-v8a"})
            self.assertIsInstance(lane["release_required"], bool)

    def test_declared_floors_match_build_configuration(self) -> None:
        windows = (ROOT / "clients/desktop/apps/windows/OnionRoute.App/OnionRoute.App.csproj").read_text(encoding="utf-8")
        macos = (ROOT / "clients/desktop/apps/macos/project.yml").read_text(encoding="utf-8")
        android = (ROOT / "clients/android/app/build.gradle.kts").read_text(encoding="utf-8")
        ios = (ROOT / "clients/ios/project.yml").read_text(encoding="utf-8")
        self.assertIn("10.0.19041.0", windows)
        self.assertIn('macOS: "13.0"', macos)
        self.assertIn("minSdk = 29", android)
        self.assertIn("targetSdk = 36", android)
        self.assertIn('iOS: "17.0"', ios)

    def test_each_release_platform_runs_every_network_and_upgrade_variant(self) -> None:
        self.assertEqual(
            set(MATRIX["network_variants"]),
            {"ipv4-only", "dual-stack", "ipv6-only-access", "nat64", "wifi", "ethernet", "cellular", "captive-portal"},
        )
        self.assertIn("reboot-with-tunnel-active", MATRIX["upgrade_paths"])
        self.assertIn("incompatible-major-reject", MATRIX["protocol_pairs"])

    def test_unapproved_linux_support_is_visible_and_owned(self) -> None:
        linux = next(item for item in MATRIX["conditional"] if item["family"] == "linux")
        self.assertIn("release-blocked", linux["status"])
        self.assertTrue(linux["owner"])


if __name__ == "__main__":
    unittest.main()
