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
        cls.image_validation_job = cls.ci.split(
            "  staging_image_validation:", 1
        )[1].split("\n  publish_staging_image:", 1)[0]
        cls.image_publish_job = cls.ci.split(
            "  publish_staging_image:", 1
        )[1].split("\n  mark_staging_image_failure:", 1)[0]
        cls.image_failure_job = cls.ci.split(
            "  mark_staging_image_failure:", 1
        )[1]

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

    def test_image_publish_permissions_are_gateway_push_only(self) -> None:
        self.assertIn("rhysd/actionlint@sha256:", self.ci)
        self.assertNotIn("rhysd/actionlint:1.7.7", self.ci)
        self.assertIn("--network none", self.ci)
        self.assertNotIn("packages: write", self.image_validation_job)
        self.assertNotIn("statuses: write", self.image_validation_job)
        self.assertNotIn("secrets.GITHUB_TOKEN", self.image_validation_job)
        self.assertIn("packages: write", self.image_publish_job)
        self.assertIn("statuses: write", self.image_publish_job)
        self.assertIn("github.event_name == 'push'", self.image_publish_job)
        self.assertIn(
            "github.ref == 'refs/heads/gateway/multihop'",
            self.image_publish_job,
        )
        self.assertEqual(self.ci.count("packages: write"), 1)
        self.assertEqual(self.ci.count("statuses: write"), 2)
        self.assertNotIn("packages: write", self.image_failure_job)
        self.assertNotIn("actions/checkout", self.image_failure_job)
        self.assertIn(
            "needs.publish_staging_image.result != 'success'",
            self.image_failure_job,
        )
        self.assertIn("always()", self.image_failure_job)
        self.assertIn(
            '{state:"failure",context:"onionroute/staging-image"',
            self.image_failure_job,
        )

    def test_digest_status_is_bound_to_its_exact_successful_ci_run(self) -> None:
        self.assertIn(
            "/commits/${GITHUB_SHA}/statuses?per_page=100&page=1",
            self.deploy,
        )
        self.assertIn('ci_run_id="${ci_target_url#"$ci_run_prefix"}"', self.deploy)
        context_filter = self.deploy.index(
            '[.[] | select(.context == "onionroute/staging-image")]'
        )
        latest_status = self.deploy.index("| .[0]", context_filter)
        success_gate = self.deploy.index('| select(.state == "success")', latest_status)
        self.assertLess(context_filter, latest_status)
        self.assertLess(latest_status, success_gate)
        self.assertIn('^[1-9][0-9]{0,17}$', self.deploy)
        self.assertIn(
            '[[ "$ci_target_url" != "${ci_run_prefix}${ci_run_id}" ]]',
            self.deploy,
        )
        self.assertIn("/actions/runs/${ci_run_id}", self.deploy)
        self.assertIn(".html_url == $target_url", self.deploy)
        self.assertIn(".repository.full_name == $repository", self.deploy)
        self.assertIn(
            "/actions/workflows/backend-ci.yml",
            self.deploy,
        )
        self.assertIn(
            '(.path == ".github/workflows/backend-ci.yml")',
            self.deploy,
        )
        self.assertGreaterEqual(
            self.deploy.count("((.workflow_id | tostring) == $workflow_id)"),
            3,
        )
        self.assertNotIn(
            'startswith(".github/workflows/backend-ci.yml@")',
            self.deploy,
        )
        self.assertIn('.head_branch == "gateway/multihop"', self.deploy)
        self.assertIn('.event == "push"', self.deploy)
        self.assertIn('.status == "completed"', self.deploy)
        self.assertIn('.conclusion == "success"', self.deploy)
        self.assertNotIn("actions/workflows/backend-ci.yml/runs?", self.deploy)

    def test_promotion_artifact_binds_digest_and_run_attempt(self) -> None:
        publish = self.image_publish_job.index(
            "- name: Publish the CI-gated immutable image"
        )
        create = self.image_publish_job.index(
            "- name: Create the exact-run promotion record",
            publish,
        )
        upload = self.image_publish_job.index(
            "- name: Upload the exact-run promotion record",
            create,
        )
        success = self.image_publish_job.index(
            "- name: Mark immutable image publication successful",
            upload,
        )
        self.assertLess(publish, create)
        self.assertLess(create, upload)
        self.assertLess(upload, success)
        self.assertIn(
            "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            self.image_publish_job,
        )
        self.assertIn(
            "name: onionroute-staging-promotion-${{ github.run_id }}",
            self.image_publish_job,
        )
        self.assertIn("overwrite: true", self.image_publish_job)
        self.assertIn('--arg run_attempt "$GITHUB_RUN_ATTEMPT"', self.image_publish_job)
        self.assertIn(
            "/actions/runs/${ci_run_id}/artifacts?name=${promotion_name}&per_page=100",
            self.deploy,
        )
        self.assertIn("select(.total_count == 1)", self.deploy)
        self.assertIn(
            "((.workflow_run.id | tostring) == $run_id)",
            self.deploy,
        )
        self.assertIn(
            "/actions/artifacts/${artifact_id}/zip",
            self.deploy,
        )
        self.assertIn(
            '[[ "$downloaded_digest" != "$artifact_digest" ]]',
            self.deploy,
        )
        self.assertIn("--max-filesize 1048576", self.deploy)
        self.assertIn("--max-time 60", self.deploy)
        self.assertIn(
            'members[0].filename != "promotion.json"',
            self.deploy,
        )
        self.assertIn("data = source.read(4097)", self.deploy)
        self.assertIn("(.run_attempt == $run_attempt)", self.deploy)
        self.assertIn("(.image_digest == $image_digest)", self.deploy)
        self.assertIn(
            "/actions/runs/${ci_run_id}/attempts/${ci_run_attempt}",
            self.deploy,
        )
        self.assertIn(
            '((.id | tostring) == $status_id)',
            self.deploy,
        )
        self.assertIn(
            'promoted_image="$(jq -r \'.image\' "$promotion_json")"',
            self.deploy,
        )
        ssh_step = self.deploy.split(
            "      - name: Stream bundle to the forced deploy controller",
            1,
        )[1]
        current_run = ssh_step.index(
            "/actions/runs/${OR_PROMOTION_RUN_ID}"
        )
        current_status = ssh_step.index(
            "/commits/${GITHUB_SHA}/statuses?per_page=100&page=1",
            current_run,
        )
        ssh_delivery = ssh_step.index('"root@$SSH_HOST"', current_status)
        self.assertLess(current_run, current_status)
        self.assertLess(current_status, ssh_delivery)
        self.assertIn("OR_PROMOTION_RUN_ATTEMPT", ssh_step)
        self.assertIn("OR_PROMOTION_WORKFLOW_ID", ssh_step)
        self.assertIn("OR_PROMOTION_STATUS_ID", ssh_step)

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
