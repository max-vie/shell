"""Test MAKE's Loki and Alloy deployment boundary without live access."""

from __future__ import annotations

import io
import importlib.util
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MAKE_SCRIPTS_ROOT = REPOSITORY_ROOT / "make/scripts"
WATCH_SCRIPTS_ROOT = REPOSITORY_ROOT / "watch/scripts"
TAR_SCRIPTS_ROOT = REPOSITORY_ROOT / "tar/scripts"
for scripts_root in (MAKE_SCRIPTS_ROOT, WATCH_SCRIPTS_ROOT, TAR_SCRIPTS_ROOT):
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load MAKE logs script: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deploy = load("deploy_logs", MAKE_SCRIPTS_ROOT / "deploy_logs.py")


class TestLogsDeploy(unittest.TestCase):
    def test_source_has_no_unpinned_or_grafana_secret_shortcuts(self) -> None:
        for path in (
            MAKE_SCRIPTS_ROOT / "deploy_logs.py",
            MAKE_ROOT / "monitoring/logs-values.yaml",
            MAKE_ROOT / "monitoring/alloy-values.yaml",
        ):
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertNotIn(":latest", source)
                self.assertNotIn("--limit", source)
                self.assertNotIn("adminPassword", source)
                self.assertNotIn("grafana-loki-datasource", source)
        loki_values = (MAKE_ROOT / "monitoring/logs-values.yaml").read_text(
            encoding="utf-8"
        )
        alloy_values = (MAKE_ROOT / "monitoring/alloy-values.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("  sidecar: false", loki_values)
        self.assertIn("  metrics:\n    enabled: false", loki_values)
        self.assertIn("automountServiceAccountToken: false", loki_values)
        self.assertIn("rbac:\n  namespaced: true", loki_values)
        self.assertIn("sidecar:\n  rules:\n    enabled: false", loki_values)
        self.assertIn("crds:\n  create: false", alloy_values)
        self.assertIn("networkPolicy:\n  enabled: true", alloy_values)
        self.assertIn("service:\n  enabled: false", alloy_values)
        self.assertIn("shell-watch-loki-allow-alloy-gateway", loki_values)
        self.assertIn("app.kubernetes.io/name: grafana", loki_values)
        self.assertIn("app.kubernetes.io/instance: shell-watch", loki_values)
        self.assertIn("shell-watch-loki-allow-gateway", loki_values)
        self.assertIn("own_namespace = true", alloy_values)
        self.assertIn("namespaces: [monitoring]", alloy_values)
        self.assertIn("resources: [pods]", alloy_values)
        self.assertIn("mountPath: /var/lib/alloy", alloy_values)
        self.assertIn("emptyDir: {}", alloy_values)
        self.assertNotIn("resources: [configmaps, secrets]", alloy_values)

    def test_helm_arguments_consume_every_log_digest(self) -> None:
        logs_supply = deploy.supply.validate_public()
        arguments = deploy.helm_image_arguments(
            logs_supply, deploy.CHART_IMAGES["loki"]
        )
        command = " ".join(arguments)
        for image in deploy.CHART_IMAGES["loki"]:
            digest = logs_supply["runtime_image_digests"][image]
            with self.subTest(image=image):
                self.assertIn(image.rsplit(":", 1)[1], command)
                self.assertIn(digest, command)
        self.assertNotIn("alloy:v1.18.1", command)
        alloy_arguments = deploy.helm_image_arguments(
            logs_supply, deploy.CHART_IMAGES["alloy"]
        )
        alloy_command = " ".join(alloy_arguments)
        self.assertIn("image.tag=v1.18.1", alloy_command)
        self.assertIn("configReloader.image.tag=v0.91.0", alloy_command)

    def test_check_only_stops_before_inventory_or_artifact_access(self) -> None:
        with (
            mock.patch.object(deploy.transport, "resolve_connection") as resolve,
        ):
            deploy.deploy([Path("/does/not/exist")], check_only=True)
        resolve.assert_not_called()

    def test_template_only_renders_before_inventory_access(self) -> None:
        with (
            mock.patch.object(deploy, "template_local") as template,
            mock.patch.object(deploy.transport, "resolve_connection") as resolve,
        ):
            deploy.deploy([Path("/does/not/exist")], template_only=True)
        template.assert_called_once()
        resolve.assert_not_called()

    def test_staged_chart_checksum_is_checked_before_connection(self) -> None:
        logs_supply = deploy.supply.validate_public()
        with tempfile.TemporaryDirectory() as temporary:
            chart = Path(temporary) / "loki.tgz"
            chart.write_bytes(b"wrong chart")
            with mock.patch.object(
                deploy.transport,
                "require_regular_file",
                return_value=chart,
            ):
                with self.assertRaisesRegex(
                    deploy.LogsDeployError, "loki checksum changed"
                ):
                    deploy.require_staged_chart(logs_supply, "loki")

    def test_release_snapshot_and_restore_commands_are_fail_closed(self) -> None:
        with mock.patch.object(
            deploy,
            "remote",
            return_value='[{"name":"shell-watch-loki","status":"deployed","revision":"3"}]',
        ):
            self.assertEqual(
                3,
                deploy.release_revision(
                    mock.sentinel.connection,
                    "monitoring",
                    "shell-watch-loki",
                ),
            )
        with mock.patch.object(deploy, "remote") as remote:
            deploy.restore_release(
                mock.sentinel.connection,
                "monitoring",
                "shell-watch-loki",
                3,
            )
            self.assertIn("rollback shell-watch-loki 3", remote.call_args.args[1])
            deploy.restore_release(
                mock.sentinel.connection,
                "monitoring",
                "shell-watch-alloy",
                None,
            )
            self.assertIn("uninstall shell-watch-alloy", remote.call_args.args[1])

    def test_guest_stage_is_cleaned_when_a_log_release_fails(self) -> None:
        logs_contract = deploy.contract.validate_contract()
        logs_supply = deploy.supply.validate_public()
        with (
            mock.patch.object(
                deploy,
                "validate_source",
                return_value=(logs_contract, logs_supply),
            ),
            mock.patch.object(
                deploy,
                "require_staged_chart",
                return_value=Path("/tmp/staged-chart.tgz"),
            ),
            mock.patch.object(
                deploy.transport,
                "resolve_connection",
                return_value=mock.sentinel.connection,
            ),
            mock.patch.object(deploy, "preflight"),
            mock.patch.object(deploy, "release_revision", return_value=None),
            mock.patch.object(deploy, "remote"),
            mock.patch.object(
                deploy,
                "create_guest_stage",
                return_value="/tmp/tmp.safe",
            ),
            mock.patch.object(deploy, "stage_artifacts"),
            mock.patch.object(deploy, "render_release"),
            mock.patch.object(
                deploy,
                "install_release",
                side_effect=RuntimeError("boom"),
            ),
            mock.patch.object(deploy, "cleanup_guest") as cleanup,
        ):
            with self.assertRaisesRegex(RuntimeError, "boom"):
                deploy.deploy(
                    [Path("inventory")],
                    approval=deploy.MAKE_APPROVAL,
                )
        cleanup.assert_called_once_with(mock.sentinel.connection, "/tmp/tmp.safe")

    def test_second_release_failure_removes_new_loki_release(self) -> None:
        logs_contract = deploy.contract.validate_contract()
        logs_supply = deploy.supply.validate_public()
        with (
            mock.patch.object(
                deploy,
                "validate_source",
                return_value=(logs_contract, logs_supply),
            ),
            mock.patch.object(deploy, "require_staged_chart"),
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
                deploy,
                "install_release",
                side_effect=[None, RuntimeError("alloy failed")],
            ),
            mock.patch.object(deploy, "restore_release") as restore,
            mock.patch.object(deploy, "cleanup_guest"),
        ):
            with self.assertRaisesRegex(RuntimeError, "alloy failed"):
                deploy.deploy([Path("inventory")], approval=deploy.MAKE_APPROVAL)
        restore.assert_called_once_with(
            mock.sentinel.connection,
            "monitoring",
            "shell-watch-loki",
            None,
        )

    def test_post_install_failure_rolls_back_both_prior_revisions(self) -> None:
        logs_contract = deploy.contract.validate_contract()
        logs_supply = deploy.supply.validate_public()
        with (
            mock.patch.object(
                deploy,
                "validate_source",
                return_value=(logs_contract, logs_supply),
            ),
            mock.patch.object(deploy, "require_staged_chart"),
            mock.patch.object(
                deploy.transport,
                "resolve_connection",
                return_value=mock.sentinel.connection,
            ),
            mock.patch.object(deploy, "preflight"),
            mock.patch.object(deploy, "release_revision", side_effect=[3, 4]),
            mock.patch.object(
                deploy, "create_guest_stage", return_value="/tmp/tmp.safe"
            ),
            mock.patch.object(deploy, "stage_artifacts"),
            mock.patch.object(deploy, "render_release"),
            mock.patch.object(deploy, "install_release"),
            mock.patch.object(deploy, "wait_ready"),
            mock.patch.object(
                deploy,
                "verify_runtime_images",
                side_effect=RuntimeError("verification failed"),
            ),
            mock.patch.object(deploy, "restore_release") as restore,
            mock.patch.object(deploy, "cleanup_guest"),
        ):
            with self.assertRaisesRegex(RuntimeError, "verification failed"):
                deploy.deploy([Path("inventory")], approval=deploy.MAKE_APPROVAL)
        self.assertEqual(
            [
                mock.call(
                    mock.sentinel.connection,
                    "monitoring",
                    "shell-watch-alloy",
                    4,
                ),
                mock.call(
                    mock.sentinel.connection,
                    "monitoring",
                    "shell-watch-loki",
                    3,
                ),
            ],
            restore.call_args_list,
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
                with self.assertRaisesRegex(
                    RuntimeError, "deployment failed"
                ) as raised:
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
        error = deploy.LogsDeployError("primary deployment failure")
        error.add_note("failed to restore shell-watch-loki: rollback failed")
        error.add_note("temporary artifact cleanup also failed: cleanup failed")
        stderr = io.StringIO()
        with (
            mock.patch.object(deploy, "deploy", side_effect=error),
            mock.patch.object(sys, "argv", ["deploy_logs.py", "--check-only"]),
            redirect_stderr(stderr),
        ):
            self.assertEqual(2, deploy.main())
        output = stderr.getvalue()
        self.assertIn("primary deployment failure", output)
        self.assertIn("rollback failed", output)
        self.assertIn("cleanup failed", output)

    def test_make_targets_are_fixed_and_approval_gated(self) -> None:
        source = (MAKE_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("logs-check", source)
        self.assertIn("logs-preview", source)
        self.assertIn("logs-apply", source)
        self.assertIn("environment-gcp/make/logs", source)
        self.assertIn("deploy_logs.py", source)


MAKE_ROOT = REPOSITORY_ROOT / "make"


if __name__ == "__main__":
    unittest.main()
