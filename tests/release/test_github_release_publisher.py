from __future__ import annotations

import hashlib
import importlib.util
import io
import pathlib
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "publish_github_release.py"
SPEC = importlib.util.spec_from_file_location("publish_github_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
publisher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publisher
SPEC.loader.exec_module(publisher)


class GitHubReleasePublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.assets = pathlib.Path(self.temporary_directory.name)
        self.bundle = self.assets / "onionroute-0.1.0.tar.gz"
        self.bundle.write_bytes(b"signed release payload")
        (self.assets / f"{self.bundle.name}.sig").write_bytes(b"detached signature")
        (self.assets / "SHA256SUMS.sig").write_bytes(b"signed checksum manifest")
        self._write_checksums()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write_checksums(self) -> None:
        lines = []
        for path in sorted(self.assets.iterdir(), key=lambda candidate: candidate.name):
            if path.name in {"SHA256SUMS", "SHA256SUMS.sig"}:
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.name}")
        (self.assets / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_collects_complete_signed_asset_set(self) -> None:
        assets = publisher.collect_assets(self.assets, "v0.1.0")
        self.assertEqual(
            {asset.name for asset in assets},
            {"SHA256SUMS", "SHA256SUMS.sig", self.bundle.name, f"{self.bundle.name}.sig"},
        )

    def test_rejects_payload_without_detached_signature(self) -> None:
        (self.assets / f"{self.bundle.name}.sig").unlink()
        self._write_checksums()
        with self.assertRaisesRegex(publisher.ReleaseError, "detached signature"):
            publisher.collect_assets(self.assets, "v0.1.0")

    def test_rejects_secret_like_asset(self) -> None:
        (self.assets / "release.key").write_text("not-a-real-key", encoding="utf-8")
        with self.assertRaisesRegex(publisher.ReleaseError, "secret-like"):
            publisher.collect_assets(self.assets, "v0.1.0")

    def test_rejects_tampered_payload(self) -> None:
        self.bundle.write_bytes(b"modified after checksums")
        with self.assertRaisesRegex(publisher.ReleaseError, "digest mismatch"):
            publisher.collect_assets(self.assets, "v0.1.0")

    def test_stage_command_is_draft_and_requires_existing_remote_tag(self) -> None:
        assets = publisher.collect_assets(self.assets, "v0.1.0")
        notes = self.assets / "notes.md"
        notes.write_text("Release notes", encoding="utf-8")
        command = publisher.build_stage_command(
            "v0.1.0", assets, notes, "OnionRoute v0.1.0", "owner/repository", False
        )
        self.assertIn("--draft", command)
        self.assertIn("--verify-tag", command)
        self.assertNotIn("--clobber", command)

    def test_detects_downloaded_asset_tampering(self) -> None:
        assets = publisher.collect_assets(self.assets, "v0.1.0")
        with tempfile.TemporaryDirectory() as remote_directory:
            remote = pathlib.Path(remote_directory)
            for asset in assets:
                shutil.copy2(asset.path, remote / asset.name)
            publisher.assert_asset_sets_equal(assets, remote)
            (remote / self.bundle.name).write_bytes(b"remote mutation")
            with self.assertRaisesRegex(publisher.ReleaseError, "differ"):
                publisher.assert_asset_sets_equal(assets, remote)

    def test_stage_dry_run_uses_no_network_tools(self) -> None:
        with tempfile.TemporaryDirectory() as operator_directory:
            operator_path = pathlib.Path(operator_directory)
            notes = operator_path / "notes.md"
            notes.write_text("Release notes", encoding="utf-8")
            verification_key = operator_path / "release-signing.pub"
            verification_key.write_text("test-public-key", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                result = publisher.main(
                    [
                        "stage",
                        "--tag",
                        "v0.1.0",
                        "--assets",
                        str(self.assets),
                        "--notes-file",
                        str(notes),
                        "--verification-key",
                        str(verification_key),
                        "--repo",
                        "owner/repository",
                        "--dry-run",
                    ]
                )
        self.assertEqual(result, 0)
        self.assertIn("gh release create", output.getvalue())
        self.assertIn("--verify-tag", output.getvalue())

    def test_image_builder_emits_publishable_release_envelope(self) -> None:
        build_script = (ROOT / "infrastructure" / "images" / "build-image.sh").read_text(
            encoding="utf-8"
        )
        for required_fragment in (
            "release staging directory must be empty",
            "onionroute-$release_version.sbom.cdx.json",
            "onionroute-$release_version.provenance.json",
            'checksums="$artifacts/SHA256SUMS"',
            'output-signature "$checksums.sig"',
            "printf 'release_assets=%s",
        ):
            self.assertIn(required_fragment, build_script)


if __name__ == "__main__":
    unittest.main()
