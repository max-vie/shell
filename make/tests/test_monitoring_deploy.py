"""Test MAKE's monitoring deployment boundaries without live access."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MAKE_ROOT = REPOSITORY_ROOT / "make"
MAKE_SCRIPTS_ROOT = MAKE_ROOT / "scripts"
WATCH_SCRIPTS_ROOT = REPOSITORY_ROOT / "watch/scripts"
TAR_SCRIPTS_ROOT = REPOSITORY_ROOT / "tar/scripts"
for scripts_root in (MAKE_SCRIPTS_ROOT, WATCH_SCRIPTS_ROOT, TAR_SCRIPTS_ROOT):
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load MAKE monitoring script: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


transport = load("k3s_transport", MAKE_SCRIPTS_ROOT / "k3s_transport.py")
images = load(
    "validate_monitoring_images",
    MAKE_SCRIPTS_ROOT / "validate_monitoring_images.py",
)
deploy = load("deploy_monitoring", MAKE_SCRIPTS_ROOT / "deploy_monitoring.py")


class TestMonitoringDeploy(unittest.TestCase):
    def test_source_has_no_secret_shortcuts(self) -> None:
        for path in (
            MAKE_SCRIPTS_ROOT / "deploy_monitoring.py",
            MAKE_SCRIPTS_ROOT / "validate_monitoring_images.py",
            MAKE_ROOT / "monitoring/values.yaml",
        ):
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotIn(":latest", source)
                self.assertNotIn("--limit", source)
                self.assertNotIn("openbao", source.lower())
                self.assertNotIn("password:", source.lower())

    def test_monitoring_values_keep_recovery_headroom(self) -> None:
        deploy.validate_stability_values(MAKE_ROOT / "monitoring/values.yaml")

    def test_monitoring_stability_values_are_component_specific(self) -> None:
        source = (MAKE_ROOT / "monitoring/values.yaml").read_text(encoding="utf-8")
        altered = source.replace("memory: 1280Mi", "memory: 1Gi")
        with tempfile.TemporaryDirectory() as temporary:
            values = Path(temporary) / "values.yaml"
            values.write_text(
                altered + "\nother:\n  memory: 1280Mi\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                deploy.MonitoringDeployError, "stability values changed"
            ):
                deploy.validate_stability_values(values)

    def test_monitoring_stability_keeps_default_alert_rules(self) -> None:
        source = (MAKE_ROOT / "monitoring/values.yaml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            values = Path(temporary) / "values.yaml"
            for override in (
                "defaultRules:\n  create: false\n",
                "defaultRules:\n  rules:\n    general: false\n",
                "defaultRules:\n  disabled:\n    Watchdog: true\n",
                "defaultRules: {rules: {general: false}}\n",
                "defaultRules:\n  disabled: {Watchdog: true}\n",
            ):
                with self.subTest(override=override):
                    values.write_text(override + source, encoding="utf-8")
                    with self.assertRaisesRegex(
                        deploy.MonitoringDeployError, "default alert rules"
                    ):
                        deploy.validate_stability_values(values)

    def test_check_only_stops_before_inventory_or_chart_access(self) -> None:
        with (
            mock.patch.object(deploy.transport, "resolve_connection") as resolve,
            mock.patch.object(deploy, "require_staged_chart") as staged,
        ):
            deploy.deploy([Path("/does/not/exist")], check_only=True)
        resolve.assert_not_called()
        staged.assert_not_called()

    def test_template_only_renders_before_inventory_access(self) -> None:
        with (
            mock.patch.object(deploy, "template_local") as template,
            mock.patch.object(deploy.transport, "resolve_connection") as resolve,
        ):
            deploy.deploy([Path("/does/not/exist")], template_only=True)
        template.assert_called_once()
        resolve.assert_not_called()

    def test_transport_requires_authoritative_gcp_route_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "inventory.json"
            inventory.write_text("{}", encoding="utf-8")
            inventory.chmod(stat.S_IRUSR | stat.S_IWUSR)
            known_hosts = Path(temporary) / "known_hosts"
            known_hosts.write_text("known", encoding="utf-8")
            known_hosts.chmod(stat.S_IRUSR | stat.S_IWUSR)
            route = (
                '-o ProxyCommand="gcloud compute start-iap-tunnel gcp-k3s-01 %p '
                '--listen-on-stdin --project=test-project --zone=europe-west4-a" '
                f"-o UserKnownHostsFile={known_hosts} -o StrictHostKeyChecking=yes"
            )
            host = {
                "ansible_host": "10.77.0.201",
                "ansible_user": "operator",
                "ansible_ssh_common_args": route,
                "gcp_project_id": "test-project",
                "gcp_zone": "europe-west4-a",
            }
            with mock.patch.object(transport, "run", return_value=json.dumps(host)):
                connection = transport.resolve_connection([inventory])
            self.assertEqual("operator@10.77.0.201", connection.target)

            altered = copy.deepcopy(host)
            altered["ansible_ssh_common_args"] = route.replace(
                "--project=test-project", "--project=other-project"
            )
            with mock.patch.object(transport, "run", return_value=json.dumps(altered)):
                with self.assertRaisesRegex(transport.TransportError, "fixed GCP IAP"):
                    transport.resolve_connection([inventory])

            altered = copy.deepcopy(host)
            altered["gcp_zone"] = "europe-west4-b"
            with mock.patch.object(transport, "run", return_value=json.dumps(altered)):
                with self.assertRaisesRegex(transport.TransportError, "wrong K3s zone"):
                    transport.resolve_connection([inventory])

    def test_transport_reports_subprocess_timeout(self) -> None:
        with mock.patch.object(
            transport.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["ssh"], 5),
        ):
            with self.assertRaisesRegex(transport.TransportError, "timed out after 5"):
                transport.run(["ssh"], label="test command", timeout_seconds=5)

    def test_helm_arguments_consume_every_tar_digest(self) -> None:
        supply_lock = deploy.supply.validate_public()
        arguments = deploy.helm_image_arguments(supply_lock)
        command = " ".join(arguments)
        for image, digest in supply_lock["runtime_image_digests"].items():
            with self.subTest(image=image):
                self.assertIn(
                    image.rsplit(":", 1)[1].removesuffix("-distroless"), command
                )
                self.assertIn(digest.removeprefix("sha256:"), command)
        self.assertIn(
            "prometheus-node-exporter.image.distroless=true",
            arguments,
        )
        self.assertIn("prometheus-node-exporter.image.tag=v1.12.1", arguments)
        self.assertIn(
            "prometheus-node-exporter.image.digest="
            "sha256:8c9bac11973b94b59be88d6e11fee4429aa743c8846cdc75d65b18db33f6a106",
            arguments,
        )
        self.assertIn(
            "grafana.image.repository=grafana",
            command,
        )
        self.assertIn(
            "grafana.image.tag=13.2.0",
            command,
        )

    def test_readiness_timeout_covers_all_selector_budgets(self) -> None:
        monitoring_contract = deploy.contract.validate_contract()
        with mock.patch.object(deploy, "remote") as remote:
            deploy.wait_ready(mock.sentinel.connection, monitoring_contract)
        self.assertEqual(360, remote.call_args.kwargs["timeout_seconds"])
        command = remote.call_args.args[1]
        self.assertIn("seq 1 60", command)
        self.assertIn("--timeout=180s", command)
        self.assertIn("release=shell-watch", command)
        self.assertIn("status.phase!=Succeeded,status.phase!=Failed", command)
        self.assertGreater(360, (60 * 2) + 180)

    def test_runtime_image_query_excludes_coexisting_log_releases(self) -> None:
        monitoring_contract = deploy.contract.validate_contract()
        with mock.patch.object(deploy, "remote") as remote:
            deploy.verify_runtime_images(
                mock.sentinel.connection,
                "/tmp/tmp.safe",
                monitoring_contract,
            )
        command = remote.call_args.args[1]
        self.assertIn("get pods -l release=shell-watch", command)

    def test_release_snapshot_and_restore_commands_are_fail_closed(self) -> None:
        with mock.patch.object(
            deploy,
            "remote",
            return_value='[{"name":"shell-watch","status":"deployed","revision":"3"}]',
        ):
            self.assertEqual(
                3,
                deploy.release_revision(
                    mock.sentinel.connection,
                    "monitoring",
                    "shell-watch",
                ),
            )
        with mock.patch.object(deploy, "remote") as remote:
            deploy.restore_release(
                mock.sentinel.connection,
                "monitoring",
                "shell-watch",
                3,
            )
            self.assertIn("rollback shell-watch 3", remote.call_args.args[1])
            deploy.restore_release(
                mock.sentinel.connection,
                "monitoring",
                "shell-watch",
                None,
            )
            self.assertIn("uninstall shell-watch", remote.call_args.args[1])

    def test_render_validation_requires_the_grafana_boundary(self) -> None:
        with self.assertRaisesRegex(
            deploy.MonitoringDeployError,
            "Deployment/shell-watch-grafana",
        ):
            deploy.validate_rendered_resources(
                "kind: Service\nmetadata:\n  name: shell-watch-grafana\n",
                deploy.contract.validate_contract(),
            )

    def test_rendered_and_running_images_must_match_tar(self) -> None:
        lock = deploy.supply.validate_public()
        expected, persistent = images.expected_images(lock)
        reloader = next(image for image in expected if "config-reloader" in image)
        rendered = "\n".join(
            [
                *(f"  image: {image}" for image in sorted(expected - {reloader})),
                f"  - --prometheus-config-reloader={reloader}",
            ]
        )
        pods = {
            "items": [
                {
                    "metadata": {"name": "monitoring", "namespace": "monitoring"},
                    "status": {"phase": "Running"},
                    "spec": {
                        "containers": [
                            {"name": f"container-{index}", "image": image}
                            for index, image in enumerate(sorted(persistent))
                        ]
                    },
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            rendered_path = Path(temporary) / "rendered.yaml"
            rendered_path.write_text(rendered, encoding="utf-8")
            lock_path = Path(temporary) / "supply.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            pods_path = Path(temporary) / "pods.json"
            pods_path.write_text(json.dumps(pods), encoding="utf-8")
            self.assertEqual(
                expected, images.validate_rendered(rendered_path, lock_path)
            )
            self.assertEqual(persistent, images.validate_running(pods_path, lock_path))

            rendered_path.write_text(
                rendered.replace(next(iter(expected)), "example.invalid/image:v1"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(images.MonitoringImageError, "does not match"):
                images.validate_rendered(rendered_path, lock_path)

    def test_rendered_validation_can_select_one_release_image_set(self) -> None:
        lock = deploy.supply.validate_public()
        selected = {
            "quay.io/prometheus/prometheus:v3.14.0-distroless",
            "quay.io/prometheus-operator/prometheus-operator:v0.93.1",
        }
        expected, _ = images.expected_images(lock, selected)
        with tempfile.TemporaryDirectory() as temporary:
            rendered = Path(temporary) / "rendered.yaml"
            rendered.write_text(
                "\n".join(f"image: {image}" for image in sorted(expected)),
                encoding="utf-8",
            )
            lock_path = Path(temporary) / "supply.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            self.assertEqual(
                expected,
                images.validate_rendered(rendered, lock_path, selected),
            )

    def test_tagged_and_digest_only_images_share_the_locked_identity(self) -> None:
        digest = "sha256:" + "a" * 64
        self.assertEqual(
            f"docker.io/grafana/loki@{digest}",
            images.canonical_image(f"docker.io/grafana/loki:3.7.6@{digest}"),
        )
        self.assertEqual(
            f"registry.example:5000/team/image@{digest}",
            images.canonical_image(f"registry.example:5000/team/image@{digest}"),
        )

    def test_guest_stage_is_cleaned_when_install_fails(self) -> None:
        monitoring_contract = deploy.contract.validate_contract()
        supply_lock = deploy.supply.validate_public()
        with (
            mock.patch.object(
                deploy,
                "validate_source",
                return_value=(monitoring_contract, supply_lock),
            ),
            mock.patch.object(
                deploy, "require_staged_chart", return_value=Path("/tmp/chart.tgz")
            ),
            mock.patch.object(
                deploy.transport,
                "resolve_connection",
                return_value=mock.sentinel.connection,
            ),
            mock.patch.object(deploy, "preflight"),
            mock.patch.object(deploy, "release_revision", return_value=None),
            mock.patch.object(
                deploy, "create_guest_stage", return_value="/tmp/tmp.safe"
            ),
            mock.patch.object(deploy, "stage_artifacts"),
            mock.patch.object(deploy, "render_release"),
            mock.patch.object(
                deploy, "install_release", side_effect=RuntimeError("boom")
            ),
            mock.patch.object(deploy, "cleanup_guest") as cleanup,
        ):
            with self.assertRaisesRegex(RuntimeError, "boom"):
                deploy.deploy(
                    [Path("inventory")], approval="environment-gcp/make/monitoring"
                )
        cleanup.assert_called_once_with(mock.sentinel.connection, "/tmp/tmp.safe")

    def test_post_install_failure_restores_the_prior_revision(self) -> None:
        monitoring_contract = deploy.contract.validate_contract()
        supply_lock = deploy.supply.validate_public()
        with (
            mock.patch.object(
                deploy,
                "validate_source",
                return_value=(monitoring_contract, supply_lock),
            ),
            mock.patch.object(
                deploy, "require_staged_chart", return_value=Path("/tmp/chart.tgz")
            ),
            mock.patch.object(
                deploy.transport,
                "resolve_connection",
                return_value=mock.sentinel.connection,
            ),
            mock.patch.object(deploy, "preflight"),
            mock.patch.object(deploy, "release_revision", return_value=3),
            mock.patch.object(
                deploy, "create_guest_stage", return_value="/tmp/tmp.safe"
            ),
            mock.patch.object(deploy, "stage_artifacts"),
            mock.patch.object(deploy, "render_release"),
            mock.patch.object(deploy, "install_release"),
            mock.patch.object(
                deploy,
                "wait_ready",
                side_effect=RuntimeError("readiness failed"),
            ),
            mock.patch.object(deploy, "restore_release") as restore,
            mock.patch.object(deploy, "cleanup_guest"),
        ):
            with self.assertRaisesRegex(RuntimeError, "readiness failed"):
                deploy.deploy([Path("inventory")], approval=deploy.MAKE_APPROVAL)
        restore.assert_called_once_with(
            mock.sentinel.connection,
            "monitoring",
            "shell-watch",
            3,
        )

    def test_ambiguous_install_failure_restores_an_observed_new_release(self) -> None:
        monitoring_contract = deploy.contract.validate_contract()
        supply_lock = deploy.supply.validate_public()
        with (
            mock.patch.object(
                deploy,
                "validate_source",
                return_value=(monitoring_contract, supply_lock),
            ),
            mock.patch.object(
                deploy, "require_staged_chart", return_value=Path("/tmp/chart.tgz")
            ),
            mock.patch.object(
                deploy.transport,
                "resolve_connection",
                return_value=mock.sentinel.connection,
            ),
            mock.patch.object(deploy, "preflight"),
            mock.patch.object(deploy, "release_revision", side_effect=[None, 1]),
            mock.patch.object(
                deploy, "create_guest_stage", return_value="/tmp/tmp.safe"
            ),
            mock.patch.object(deploy, "stage_artifacts"),
            mock.patch.object(deploy, "render_release"),
            mock.patch.object(
                deploy,
                "install_release",
                side_effect=RuntimeError("SSH completion was ambiguous"),
            ),
            mock.patch.object(deploy, "restore_release") as restore,
            mock.patch.object(deploy, "cleanup_guest"),
        ):
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                deploy.deploy([Path("inventory")], approval=deploy.MAKE_APPROVAL)
        restore.assert_called_once_with(
            mock.sentinel.connection,
            "monitoring",
            "shell-watch",
            None,
        )

    def test_cleanup_failure_preserves_the_deployment_error(self) -> None:
        with mock.patch.object(
            deploy,
            "cleanup_guest",
            side_effect=RuntimeError("cleanup failed"),
        ):
            try:
                raise RuntimeError("deployment failed")
            except RuntimeError as error:
                with self.assertRaisesRegex(RuntimeError, "deployment failed") as raised:
                    try:
                        raise error
                    finally:
                        deploy.cleanup_preserving_error(
                            mock.sentinel.connection,
                            "/tmp/tmp.safe",
                        )
        self.assertTrue(
            any("cleanup failed" in note for note in raised.exception.__notes__)
        )

    def test_main_reports_compensation_and_cleanup_details(self) -> None:
        error = deploy.MonitoringDeployError("primary deployment failure")
        error.add_note("failed to restore shell-watch: rollback failed")
        error.add_note("temporary artifact cleanup also failed: cleanup failed")
        stderr = io.StringIO()
        with (
            mock.patch.object(deploy, "deploy", side_effect=error),
            mock.patch.object(sys, "argv", ["deploy_monitoring.py", "--check-only"]),
            redirect_stderr(stderr),
        ):
            self.assertEqual(2, deploy.main())
        output = stderr.getvalue()
        self.assertIn("primary deployment failure", output)
        self.assertIn("rollback failed", output)
        self.assertIn("cleanup failed", output)


if __name__ == "__main__":
    unittest.main()
