from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "infrastructure" / "staging-ssh" / "onionroute-staging-deploy"
BOOTSTRAP = ROOT / "infrastructure" / "staging-ssh" / "bootstrap-server.sh"
BUNDLE = ROOT / "infrastructure" / "staging" / "build-bundle.sh"
BUNDLE_TEST = ROOT / "infrastructure" / "staging" / "test_bundle.sh"
CI = ROOT / ".github" / "workflows" / "backend-ci.yml"
DEPLOY = ROOT / ".github" / "workflows" / "staging-deploy.yml"
COMPOSE = ROOT / "infrastructure" / "staging" / "compose.yaml"


class StagingDeliveryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = CONTROLLER.read_text(encoding="utf-8")
        cls.bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        cls.bundle = BUNDLE.read_text(encoding="utf-8")
        cls.bundle_test = BUNDLE_TEST.read_text(encoding="utf-8")
        cls.ci = CI.read_text(encoding="utf-8")
        cls.deploy = DEPLOY.read_text(encoding="utf-8")
        cls.compose = COMPOSE.read_text(encoding="utf-8")

    def test_bundle_is_signed_and_verified_by_server_policy(self) -> None:
        self.assertIn("ssh-keygen -Y sign", self.bundle)
        self.assertIn("manifest.sha256.sig", self.bundle)
        self.assertIn("ssh-keygen -Y verify", self.controller)
        self.assertIn("bundle-allowed-signers", self.controller)
        self.assertIn("tampered bundle manifest", self.bundle_test)

    def test_short_ssh_reads_cannot_truncate_bundle(self) -> None:
        self.assertIn("iflag=fullblock", self.controller)

    def test_runtime_secret_is_group_readable_but_not_world_readable(self) -> None:
        self.assertIn("chown root:10001", self.bootstrap)
        self.assertIn("chmod 0640", self.bootstrap)
        self.assertNotIn(
            "chmod 0644",
            self.bootstrap,
        )

    def test_bootstrap_rotates_only_the_managed_forced_key_block(self) -> None:
        self.assertIn("# BEGIN onionroute-staging-deploy", self.bootstrap)
        self.assertIn("# END onionroute-staging-deploy", self.bootstrap)
        self.assertIn("authorized_keys.XXXXXXXX", self.bootstrap)
        self.assertNotIn('>> /root/.ssh/authorized_keys', self.bootstrap)

    def test_replay_is_checked_before_image_import_and_rollback_is_immutable(self) -> None:
        replay_check = self.controller.index("existing release metadata differs")
        image_import = self.controller.index('docker load --input')
        self.assertLess(replay_check, image_import)
        self.assertIn("release_image_id", self.controller)
        self.assertIn("docker image inspect \"$previous_image_id\"", self.controller)
        self.assertIn("pull_policy: never", self.compose)

    def test_bundle_has_compressed_and_expanded_limits(self) -> None:
        self.assertIn("max_bundle_bytes=536870912", self.controller)
        self.assertIn("max_expanded_bytes=2147483648", self.controller)
        self.assertIn("timeout 300 tar -tvzf", self.controller)

    def test_signed_run_id_prevents_replay_and_release_install_is_atomic(self) -> None:
        self.assertIn("run-id", self.bundle)
        self.assertIn("last-accepted-run-id", self.controller)
        self.assertIn("bundle run id does not match", self.controller)
        self.assertIn("already accepted or is older", self.controller)
        self.assertIn('mktemp -d "$releases_root/.${revision}.XXXXXXXX"', self.controller)
        self.assertIn('mv -- "$release_install_dir" "$release_dir"', self.controller)

    def test_onion_ingress_is_checked_through_tor(self) -> None:
        self.assertIn("status/bootstrap-phase", self.compose)
        self.assertIn("--socks5-hostname 127.0.0.1:29050", self.controller)

    def test_deploy_promotes_a_ci_digest_instead_of_rebuilding(self) -> None:
        self.assertIn("ghcr.io/${GITHUB_REPOSITORY,,}", self.ci)
        self.assertIn("onionroute/staging-image", self.ci)
        self.assertIn("OR_PROMOTED_IMAGE", self.deploy)
        self.assertNotIn("docker build", self.deploy)

    def test_checkout_credentials_are_not_persisted(self) -> None:
        checkout_count = self.ci.count("uses: actions/checkout@") + self.deploy.count(
            "uses: actions/checkout@"
        )
        hardened_count = self.ci.count("persist-credentials: false") + self.deploy.count(
            "persist-credentials: false"
        )
        self.assertEqual(hardened_count, checkout_count)

    def test_ssh_has_bounded_connect_and_exact_host_key_lookup(self) -> None:
        self.assertIn("ConnectTimeout=15", self.deploy)
        self.assertIn('known_host="[$SSH_HOST]:$SSH_PORT"', self.deploy)
        self.assertNotIn('ssh-keygen -F "[$SSH_HOST]:$SSH_PORT"', self.deploy)


if __name__ == "__main__":
    unittest.main()
