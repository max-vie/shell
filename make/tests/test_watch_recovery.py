"""Test the MAKE-owned Grafana recovery controller offline."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MAKE_SCRIPTS = REPOSITORY_ROOT / "make/scripts"
WATCH_SCRIPTS = REPOSITORY_ROOT / "watch/scripts"
for path in (MAKE_SCRIPTS, WATCH_SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


recovery = load("make_watch_recovery", MAKE_SCRIPTS / "watch_recovery.py")


class TestRecoveryCommands(unittest.TestCase):
    OPERATION = "grafana-20260829-120000-abcdef123456-1234abcd"

    def contract(self) -> dict[str, Any]:
        return recovery._contract()

    def monitoring(self) -> dict[str, dict[str, Any]]:
        return {
            "grafana": {
                "pod": "shell-watch-grafana-abc",
                "ready": True,
                "restart_count": 0,
                "oom_killed": False,
                "memory_limit_bytes": 1024 * 1024 * 1024,
            },
            "prometheus": {
                "pod": "prometheus-shell-watch-0",
                "ready": True,
                "restart_count": 0,
                "oom_killed": False,
                "memory_limit_bytes": 1280 * 1024 * 1024,
            },
        }

    def baseline(self) -> dict[str, object]:
        return {
            "replicas": 1,
            "available_replicas": 1,
            "endpoints": 1,
            "ready_nodes": 3,
            "monitoring": self.monitoring(),
            "alert": {"loaded": True, "firing": False, "active": False},
        }

    def terminal(self, contract: dict[str, Any]) -> dict[str, object]:
        return {
            "replicas": 1,
            "available_replicas": 1,
            "endpoints": 1,
            "nodes": [
                {"name": name, "ready": True, "memory_pressure": False}
                for name in contract["cluster"]["nodes"]
            ],
            "monitoring": self.monitoring(),
            "annotation_absent": True,
        }

    def stability(self) -> dict[str, object]:
        return {
            "started_at": "2026-08-29T11:49:00Z",
            "completed_at": "2026-08-29T11:59:00Z",
            "samples": 20,
            "interval_seconds": 30,
            "result": "pass",
        }

    def test_patch_tests_one_replica_and_sets_current_annotation(self) -> None:
        command = recovery.patch_command(
            {
                "metadata": {"annotations": {}, "resourceVersion": "7"},
                "spec": {"replicas": 1},
            },
            self.OPERATION,
            self.contract()["target"],
        )
        self.assertIn("--type=json", command)
        self.assertIn('"op":"test"', command)
        self.assertIn('"value":1', command)
        self.assertIn("resourceVersion", command)
        self.assertIn("shell.internal~1recovery-drill", command)
        self.assertNotIn("shellprod.dev", command)

    def test_restore_targets_only_the_declared_deployment(self) -> None:
        command = recovery.restore_command(
            {
                "metadata": {
                    "annotations": {"shell.internal/recovery-drill": self.OPERATION},
                    "resourceVersion": "8",
                },
                "spec": {"replicas": 0},
            },
            self.contract()["target"],
            self.OPERATION,
        )
        self.assertIn("patch deployment shell-watch-grafana", command)
        self.assertIn("--type=json", command)
        self.assertIn('"path":"/spec/replicas"', command)
        self.assertIn('"value":1', command)

    def test_operation_ids_include_a_per_run_nonce(self) -> None:
        first = recovery.operation_id("a" * 40, "1234abcd")
        second = recovery.operation_id("a" * 40, "5678abcd")
        self.assertNotEqual(first, second)
        self.assertTrue(first.endswith("-aaaaaaaaaaaa-1234abcd"))

    def test_evidence_output_rejects_nested_paths(self) -> None:
        nested = recovery.DEFAULT_OUTPUT_ROOT / "nested" / "evidence.json"
        with self.assertRaisesRegex(recovery.RecoveryDrillError, "direct child"):
            recovery.evidence_path(nested, self.OPERATION)

    def test_wrong_approval_is_rejected_before_connection_resolution(self) -> None:
        with mock.patch.object(recovery, "resolve_connection") as resolve:
            with self.assertRaisesRegex(recovery.RecoveryDrillError, "approval"):
                recovery.rule_apply("wrong", [Path("inventory")])
        resolve.assert_not_called()

    def test_dirty_source_is_rejected(self) -> None:
        with mock.patch.object(recovery, "_git", side_effect=[" M make/Makefile"]):
            with self.assertRaisesRegex(recovery.RecoveryDrillError, "clean worktree"):
                recovery.require_clean_source()

    def test_injection_requires_one_replica_and_uses_one_remote_patch(self) -> None:
        fake = mock.Mock()
        fake.target = self.contract()["target"]
        fake.connection = mock.sentinel.connection
        fake.deployment.side_effect = [
            {
                "metadata": {"annotations": {}, "resourceVersion": "7"},
                "spec": {"replicas": 1},
            },
            {
                "metadata": {
                    "annotations": {"shell.internal/recovery-drill": self.OPERATION},
                    "resourceVersion": "8",
                },
                "spec": {"replicas": 0},
            },
        ]
        with mock.patch.object(recovery.transport, "ssh") as ssh:
            recovery.inject_fault(fake, self.OPERATION)
        ssh.assert_called_once()
        self.assertIn("--type=json", ssh.call_args.kwargs["command"])

    def test_restore_rejects_a_different_operation_annotation(self) -> None:
        fake = mock.Mock()
        fake.target = self.contract()["target"]
        fake.connection = mock.sentinel.connection
        fake.deployment.return_value = {
            "metadata": {
                "annotations": {"shell.internal/recovery-drill": "other"},
                "resourceVersion": "8",
            },
            "spec": {"replicas": 0},
        }
        with mock.patch.object(recovery.transport, "ssh") as ssh:
            with self.assertRaisesRegex(recovery.RecoveryDrillError, "does not match"):
                recovery.restore_fault(fake, self.OPERATION)
        ssh.assert_not_called()

    def test_restore_is_atomic_and_checks_its_readback(self) -> None:
        fake = mock.Mock()
        fake.target = self.contract()["target"]
        fake.connection = mock.sentinel.connection
        fake.deployment.side_effect = [
            {
                "metadata": {
                    "annotations": {"shell.internal/recovery-drill": self.OPERATION},
                    "resourceVersion": "8",
                },
                "spec": {"replicas": 0},
            },
            {
                "metadata": {"annotations": {}, "resourceVersion": "9"},
                "spec": {"replicas": 1},
            },
        ]
        with mock.patch.object(recovery.transport, "ssh") as ssh:
            recovery.restore_fault(fake, self.OPERATION)
        command = ssh.call_args.kwargs["command"]
        self.assertIn("resourceVersion", command)
        self.assertIn("shell.internal~1recovery-drill", command)

    def test_rule_apply_requires_loaded_inactive_alert(self) -> None:
        fake = mock.Mock()
        fake.alert_state.return_value = {
            "loaded": True,
            "firing": False,
            "active": False,
        }
        with (
            mock.patch.object(recovery, "require_clean_source", return_value="a" * 40),
            mock.patch.object(
                recovery, "resolve_connection", return_value=mock.sentinel.connection
            ),
            mock.patch.object(recovery, "apply_rule") as apply,
            mock.patch.object(recovery.observer, "RecoveryObserver", return_value=fake),
        ):
            recovery.rule_apply(recovery.APPROVAL, [Path("inventory")])
        apply.assert_called_once_with(mock.sentinel.connection, dry_run=False)

    def test_failed_required_soak_prevents_fault_injection(self) -> None:
        with (
            mock.patch.object(recovery, "require_clean_source", return_value="a" * 40),
            mock.patch.object(
                recovery,
                "run_stability_soak",
                side_effect=recovery.RecoveryDrillError("unstable"),
            ),
            mock.patch.object(recovery, "start_restore_guard") as start_guard,
            mock.patch.object(recovery, "inject_fault") as inject,
        ):
            with self.assertRaisesRegex(recovery.RecoveryDrillError, "unstable"):
                recovery.run_drill(recovery.APPROVAL, [Path("inventory")], None)
        start_guard.assert_not_called()
        inject.assert_not_called()

    def test_stability_soak_rejects_deployed_memory_limit_drift(self) -> None:
        fake = mock.Mock()
        drifted = self.monitoring()
        drifted["grafana"]["memory_limit_bytes"] = 512 * 1024 * 1024
        fake.monitoring_snapshot.return_value = drifted
        with (
            mock.patch.object(
                recovery,
                "resolve_connection",
                return_value=mock.sentinel.connection,
            ),
            mock.patch.object(recovery, "run_existing_verifiers"),
            mock.patch.object(recovery.observer, "RecoveryObserver", return_value=fake),
            mock.patch.object(
                recovery.observer, "preflight", return_value=self.baseline()
            ),
        ):
            with self.assertRaisesRegex(
                recovery.RecoveryDrillError, "deployed monitoring memory limits"
            ):
                recovery.run_stability_soak(
                    [Path("inventory")], samples=1, interval=1
                )

    def test_source_drift_after_soak_prevents_fault_injection(self) -> None:
        fake = mock.Mock()
        with (
            mock.patch.object(
                recovery,
                "require_clean_source",
                side_effect=["a" * 40, "b" * 40],
            ),
            mock.patch.object(
                recovery, "run_stability_soak", return_value=self.stability()
            ),
            mock.patch.object(
                recovery,
                "resolve_connection",
                return_value=mock.sentinel.connection,
            ),
            mock.patch.object(recovery, "run_existing_verifiers"),
            mock.patch.object(recovery.observer, "RecoveryObserver", return_value=fake),
            mock.patch.object(
                recovery.observer, "preflight", return_value=self.baseline()
            ),
            mock.patch.object(recovery, "start_restore_guard") as start_guard,
            mock.patch.object(recovery, "inject_fault") as inject,
        ):
            with self.assertRaisesRegex(recovery.RecoveryDrillError, "source changed"):
                recovery.run_drill(recovery.APPROVAL, [Path("inventory")], None)
        start_guard.assert_not_called()
        inject.assert_not_called()

    def test_restore_guard_retries_atomically_without_a_predictable_log(self) -> None:
        fake = mock.Mock()
        fake.target = self.contract()["target"]
        fake.contract = self.contract()
        fake.connection = mock.sentinel.connection
        with mock.patch.object(recovery.transport, "ssh", return_value="42") as ssh:
            self.assertEqual(42, recovery.start_restore_guard(fake, self.OPERATION))
        command = ssh.call_args.kwargs["command"]
        self.assertIn("setsid", command)
        self.assertIn("while :", command)
        self.assertIn("--type=json", command)
        self.assertIn("rollout status", command)
        self.assertIn(">/dev/null", command)
        self.assertNotIn("/tmp/", command)

    def test_restore_guard_cancellation_requires_the_matching_process(self) -> None:
        fake = mock.Mock()
        fake.connection = mock.sentinel.connection
        with mock.patch.object(
            recovery.transport, "ssh", return_value="cancelled"
        ) as ssh:
            self.assertTrue(recovery.stop_restore_guard(fake, 42, self.OPERATION))
        command = ssh.call_args.kwargs["command"]
        self.assertIn(self.OPERATION, command)
        self.assertIn("kill -TERM -- -42", command)

    def test_alert_helpers_fail_closed_when_the_rule_is_not_loaded(self) -> None:
        fake = mock.Mock()
        fake.alert_state.side_effect = [
            {"loaded": False, "firing": True, "active": True},
            {"loaded": False, "firing": False, "active": False},
        ]
        self.assertFalse(recovery.alert_firing(fake))
        self.assertFalse(recovery.alert_clear(fake))

    def test_successful_drill_writes_pass_evidence_and_cleans_guard(self) -> None:
        contract = self.contract()
        fake = mock.Mock()
        fake.connection = mock.sentinel.connection
        fake.target = contract["target"]
        fake.contract = contract
        fake.loki_entries.return_value = [
            {"timestamp": "1", "line": "grafana recovered"}
        ]
        fake.terminal_snapshot.return_value = self.terminal(contract)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            with (
                mock.patch.object(
                    recovery, "require_clean_source", return_value="a" * 40
                ),
                mock.patch.object(
                    recovery,
                    "resolve_connection",
                    return_value=mock.sentinel.connection,
                ),
                mock.patch.object(
                    recovery, "run_stability_soak", return_value=self.stability()
                ),
                mock.patch.object(recovery, "run_existing_verifiers"),
                mock.patch.object(
                    recovery.observer, "RecoveryObserver", return_value=fake
                ),
                mock.patch.object(
                    recovery.observer, "preflight", return_value=self.baseline()
                ),
                mock.patch.object(recovery, "start_restore_guard", return_value=42),
                mock.patch.object(recovery, "inject_fault"),
                mock.patch.object(recovery, "restore_fault"),
                mock.patch.object(
                    recovery, "stop_restore_guard", return_value=True
                ) as stop,
                mock.patch.object(recovery, "evidence_path", return_value=output),
                mock.patch.object(recovery, "wait_until"),
                mock.patch.object(
                    recovery.observer,
                    "utc_now",
                    side_effect=[
                        "2026-08-29T12:00:00Z",
                        "2026-08-29T12:00:05Z",
                        "2026-08-29T12:01:10Z",
                        "2026-08-29T12:01:15Z",
                        "2026-08-29T12:01:30Z",
                        "2026-08-29T12:02:00Z",
                        "2026-08-29T12:02:00Z",
                        "2026-08-29T12:02:01Z",
                    ],
                ),
            ):
                recovery.run_drill(recovery.APPROVAL, [Path("inventory")], output)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("pass", evidence["result"])
            stop.assert_called_once()

    def test_alert_timeout_restores_and_writes_failed_evidence(self) -> None:
        contract = self.contract()
        operation = self.OPERATION
        fake = mock.Mock()
        fake.connection = mock.sentinel.connection
        fake.target = contract["target"]
        fake.contract = contract
        fake.loki_entries.return_value = [
            {"timestamp": "1", "line": "grafana recovered"}
        ]
        fake.terminal_snapshot.return_value = self.terminal(contract)

        def inject(observer: object, operation_id: str) -> None:
            nonlocal operation
            operation = operation_id
            fake.deployment.return_value = {
                "metadata": {
                    "annotations": {"shell.internal/recovery-drill": operation_id}
                },
                "spec": {"replicas": 0},
            }

        def wait(
            description: str, predicate: object, timeout: int, interval: int
        ) -> None:
            if "fire" in description:
                raise recovery.RecoveryDrillError("alert timeout")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "failed-evidence.json"
            with (
                mock.patch.object(
                    recovery, "require_clean_source", return_value="a" * 40
                ),
                mock.patch.object(
                    recovery,
                    "resolve_connection",
                    return_value=mock.sentinel.connection,
                ),
                mock.patch.object(
                    recovery, "run_stability_soak", return_value=self.stability()
                ),
                mock.patch.object(recovery, "run_existing_verifiers"),
                mock.patch.object(
                    recovery.observer, "RecoveryObserver", return_value=fake
                ),
                mock.patch.object(
                    recovery.observer, "preflight", return_value=self.baseline()
                ),
                mock.patch.object(recovery, "start_restore_guard", return_value=42),
                mock.patch.object(recovery, "inject_fault", side_effect=inject),
                mock.patch.object(recovery, "restore_fault") as restore,
                mock.patch.object(recovery, "stop_restore_guard", return_value=True),
                mock.patch.object(recovery, "evidence_path", return_value=output),
                mock.patch.object(recovery, "wait_until", side_effect=wait),
                mock.patch.object(
                    recovery.observer,
                    "utc_now",
                    side_effect=[
                        "2026-08-29T12:00:00Z",
                        "2026-08-29T12:00:05Z",
                        "2026-08-29T12:01:15Z",
                        "2026-08-29T12:01:30Z",
                        "2026-08-29T12:02:00Z",
                        "2026-08-29T12:02:00Z",
                        "2026-08-29T12:02:01Z",
                    ],
                ),
            ):
                with self.assertRaisesRegex(
                    recovery.RecoveryDrillError, "alert timeout"
                ):
                    recovery.run_drill(recovery.APPROVAL, [Path("inventory")], output)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("fail", evidence["result"])
            restore.assert_called_once_with(fake, operation)


if __name__ == "__main__":
    unittest.main()
