"""Test the WATCH Grafana recovery contract and observer offline."""

from __future__ import annotations

import copy
import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WATCH_SCRIPTS = REPOSITORY_ROOT / "watch/scripts"
MAKE_SCRIPTS = REPOSITORY_ROOT / "make/scripts"
for path in (WATCH_SCRIPTS, MAKE_SCRIPTS):
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


recovery = load("watch_recovery_contract", WATCH_SCRIPTS / "validate_recovery.py")
observer = load("watch_recovery_observer", WATCH_SCRIPTS / "recovery_observer.py")


class TestRecoveryContract(unittest.TestCase):
    def test_contract_and_rule_match_current_grafana(self) -> None:
        contract = recovery.validate_contract()
        recovery.validate_rule()
        self.assertEqual("grafana-recovery-drill", contract["contract_id"])
        self.assertEqual("shell-watch-grafana", contract["target"]["name"])
        self.assertEqual(
            "shell.internal/recovery-drill", contract["target"]["annotation"]
        )
        self.assertEqual(20, contract["stability"]["samples"])

    def test_contract_drift_is_rejected(self) -> None:
        source = json.loads(recovery.CONTRACT_PATH.read_text(encoding="utf-8"))
        source["target"]["healthy_replicas"] = 2
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(
                recovery.RecoveryValidationError, "target boundary"
            ):
                recovery.validate_contract(path)

    def test_rule_does_not_retain_donor_scope(self) -> None:
        source = recovery.RULE_PATH.read_text(encoding="utf-8")
        self.assertIn("alert: ShellWatchGrafanaUnavailable", source)
        self.assertNotIn("alert: Watchdog", source)
        self.assertNotIn("shellprod.dev", source)
        self.assertNotIn("LokiRecovery", source)

    def test_operation_id_is_bounded(self) -> None:
        recovery.validate_operation_id("grafana-20260829-120000-abcdef123456-1234abcd")
        with self.assertRaisesRegex(recovery.RecoveryValidationError, "operation ID"):
            recovery.validate_operation_id("grafana-bad")


class TestRecoveryEvidence(unittest.TestCase):
    def evidence(self) -> dict[str, object]:
        contract = recovery.validate_contract()
        monitoring = {
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
                "restart_count": 1,
                "oom_killed": False,
                "memory_limit_bytes": 1280 * 1024 * 1024,
            },
        }
        nodes = [
            {"name": name, "ready": True, "memory_pressure": False}
            for name in contract["cluster"]["nodes"]
        ]
        return {
            "schema_version": "1.1",
            "contract_id": "grafana-recovery-drill",
            "contract_version": "1.0.0",
            "environment": "environment-gcp",
            "operation_id": "grafana-20260829-120000-abcdef123456-1234abcd",
            "implementation_revision": "a" * 40,
            "target": contract["target"],
            "started_at": "2026-08-29T12:00:00Z",
            "fault_observed_at": "2026-08-29T12:00:05Z",
            "alert_fired_at": "2026-08-29T12:01:10Z",
            "restore_started_at": "2026-08-29T12:01:15Z",
            "recovered_at": "2026-08-29T12:01:30Z",
            "alert_resolved_at": "2026-08-29T12:02:00Z",
            "completed_at": "2026-08-29T12:02:01Z",
            "outage_duration_seconds": 85.0,
            "alert_duration_seconds": 50.0,
            "stability": {
                "started_at": "2026-08-29T11:49:00Z",
                "completed_at": "2026-08-29T11:59:00Z",
                "samples": 20,
                "interval_seconds": 30,
                "result": "pass",
            },
            "baseline": {
                "replicas": 1,
                "available_replicas": 1,
                "endpoints": 1,
                "ready_nodes": 3,
                "monitoring": monitoring,
                "alert": {"loaded": True, "firing": False, "active": False},
            },
            "observations": {
                "during": {"endpoints": 0, "alert_fired": True},
                "after": {
                    "replicas": 1,
                    "available_replicas": 1,
                    "endpoints": 1,
                    "nodes": nodes,
                    "monitoring": monitoring,
                    "annotation_absent": True,
                },
            },
            "logs": {
                "query": '{namespace="monitoring",pod=~"shell-watch-grafana.*"}',
                "entry_count": 1,
                "sample_sha256": "b" * 64,
            },
            "cleanup": {
                "annotation_absent": True,
                "guard_cancelled": True,
                "restore_attempted": True,
            },
            "result": "pass",
            "failure": None,
        }

    def test_evidence_is_create_only_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            recovery.write_evidence(path, self.evidence())
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            with self.assertRaisesRegex(
                recovery.RecoveryValidationError, "already exists"
            ):
                recovery.write_evidence(path, self.evidence())

    def test_raw_logs_and_unknown_fields_are_rejected(self) -> None:
        document = self.evidence()
        altered = copy.deepcopy(document)
        altered["logs"] = {"query": "x", "entry_count": 1, "line": "raw log"}
        with self.assertRaisesRegex(
            recovery.RecoveryValidationError, "unexpected fields"
        ):
            recovery.validate_evidence(altered)
        altered = copy.deepcopy(document)
        altered["unexpected"] = True
        with self.assertRaisesRegex(recovery.RecoveryValidationError, "shape changed"):
            recovery.validate_evidence(altered)

    def test_failed_evidence_can_record_partial_timestamps(self) -> None:
        document = self.evidence()
        document["fault_observed_at"] = None
        document["alert_fired_at"] = None
        document["recovered_at"] = None
        document["alert_resolved_at"] = None
        document["result"] = "fail"
        document["failure"] = "alert did not fire"
        document["outage_duration_seconds"] = 0.0
        document["alert_duration_seconds"] = 0.0
        document["observations"] = {
            "during": {"endpoints": None, "alert_fired": False},
            "after": {},
        }
        document["cleanup"] = {
            "annotation_absent": True,
            "guard_cancelled": True,
            "restore_attempted": True,
        }
        recovery.validate_evidence(document)

    def test_passing_evidence_requires_health_and_consistent_durations(self) -> None:
        empty = self.evidence()
        empty["baseline"] = {}
        with self.assertRaisesRegex(
            recovery.RecoveryValidationError, "baseline shape changed"
        ):
            recovery.validate_evidence(empty)

        inconsistent = self.evidence()
        inconsistent["outage_duration_seconds"] = 1.0
        with self.assertRaisesRegex(
            recovery.RecoveryValidationError, "differs from timestamps"
        ):
            recovery.validate_evidence(inconsistent)

    def test_alert_hold_is_bound_to_the_loaded_rule_not_endpoint_timing(self) -> None:
        document = self.evidence()
        document["alert_fired_at"] = "2026-08-29T12:00:15Z"
        document["restore_started_at"] = "2026-08-29T12:00:20Z"
        document["recovered_at"] = "2026-08-29T12:00:30Z"
        document["alert_resolved_at"] = "2026-08-29T12:01:00Z"
        document["completed_at"] = "2026-08-29T12:01:01Z"
        document["outage_duration_seconds"] = 25.0
        document["alert_duration_seconds"] = 45.0
        recovery.validate_evidence(document)

    def test_failed_evidence_rejects_sensitive_failure_detail(self) -> None:
        document = self.evidence()
        document["result"] = "fail"
        document["failure"] = "private key could not be read"
        with self.assertRaisesRegex(
            recovery.RecoveryValidationError, "forbidden detail"
        ):
            recovery.validate_evidence(document)


class TestRecoveryObserver(unittest.TestCase):
    def contract(self) -> dict[str, Any]:
        return recovery.validate_contract()

    def test_memory_units_are_converted(self) -> None:
        self.assertEqual(1024**2, observer._memory_bytes("1Mi"))
        self.assertEqual(2 * 1000**3, observer._memory_bytes("2G"))
        with self.assertRaisesRegex(observer.RecoveryObservationError, "memory value"):
            observer._memory_bytes("bad")

    def test_preflight_rejects_an_active_recovery_alert(self) -> None:
        fake = mock.Mock()
        fake.target = self.contract()["target"]
        fake.deployment.return_value = {
            "metadata": {"annotations": {}},
            "spec": {"replicas": 1},
            "status": {"availableReplicas": 1},
        }
        fake.endpoints.return_value = 1
        fake.nodes.return_value = [
            {"name": name, "ready": True, "memory_pressure": False}
            for name in self.contract()["cluster"]["nodes"]
        ]
        fake.monitoring_snapshot.return_value = {
            "grafana": {"ready": True, "oom_killed": False, "restart_count": 0},
            "prometheus": {"ready": True, "oom_killed": False, "restart_count": 0},
        }
        fake.alert_state.return_value = {"loaded": True, "firing": True, "active": True}
        with self.assertRaisesRegex(
            observer.RecoveryObservationError, "already active"
        ):
            observer.preflight(fake)

    def test_endpoint_readback_counts_ready_addresses(self) -> None:
        instance = observer.RecoveryObserver(mock.sentinel.connection, self.contract())
        with mock.patch.object(
            observer.transport,
            "ssh",
            return_value=json.dumps(
                {"subsets": [{"addresses": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]}]}
            ),
        ):
            self.assertEqual(2, instance.endpoints())

    def test_monitoring_snapshot_uses_each_service_pod_selector(self) -> None:
        instance = observer.RecoveryObserver(mock.sentinel.connection, self.contract())
        services = [
            {"spec": {"selector": {"app": "grafana", "instance": "shell-watch"}}},
            {"spec": {"selector": {"app": "prometheus", "server": "main"}}},
        ]

        def pod(name: str) -> str:
            role = "grafana" if "grafana" in name else "prometheus"
            memory = "1Gi" if role == "grafana" else "1280Mi"
            return json.dumps(
                {
                    "items": [
                        {
                            "metadata": {"name": name},
                            "spec": {
                                "containers": [
                                    {
                                        "name": role,
                                        "resources": {"limits": {"memory": memory}},
                                    }
                                ]
                            },
                            "status": {
                                "containerStatuses": [
                                    {
                                        "ready": True,
                                        "restartCount": 0,
                                        "state": {"running": {}},
                                        "lastState": {},
                                    }
                                ]
                            },
                        }
                    ]
                }
            )

        with (
            mock.patch.object(
                observer.verify_monitoring,
                "resolve_resource",
                side_effect=services,
            ),
            mock.patch.object(
                observer.transport,
                "ssh",
                side_effect=[pod("shell-watch-grafana-abc"), pod("prometheus-main-0")],
            ) as ssh,
        ):
            snapshot = instance.monitoring_snapshot()
        self.assertEqual("prometheus-main-0", snapshot["prometheus"]["pod"])
        self.assertEqual(
            1280 * 1024**2, snapshot["prometheus"]["memory_limit_bytes"]
        )
        self.assertIn(
            "app=grafana,instance=shell-watch", ssh.call_args_list[0].kwargs["command"]
        )
        self.assertIn(
            "app=prometheus,server=main", ssh.call_args_list[1].kwargs["command"]
        )
        self.assertNotIn("release=shell-watch", ssh.call_args_list[1].kwargs["command"])

    def test_role_pods_rejects_operator_decoys(self) -> None:
        instance = observer.RecoveryObserver(mock.sentinel.connection, self.contract())
        response = json.dumps(
            {
                "items": [
                    {"metadata": {"name": "prometheus-main-0"}},
                    {"metadata": {"name": "prometheus-operator-decoy"}},
                ]
            }
        )
        with (
            mock.patch.object(
                observer.verify_monitoring,
                "resolve_resource",
                return_value={"spec": {"selector": {"app": "prometheus"}}},
            ),
            mock.patch.object(observer.transport, "ssh", return_value=response),
        ):
            with self.assertRaisesRegex(
                observer.RecoveryObservationError, "selection is ambiguous"
            ):
                instance.role_pods("prometheus")

    def test_memory_usage_binds_each_value_to_its_selected_pod(self) -> None:
        instance = observer.RecoveryObserver(mock.sentinel.connection, self.contract())
        services = [
            {"spec": {"selector": {"app": "grafana"}}},
            {"spec": {"selector": {"app": "prometheus", "server": "main"}}},
        ]
        with (
            mock.patch.object(
                observer.verify_monitoring,
                "resolve_resource",
                side_effect=services,
            ),
            mock.patch.object(
                observer.transport,
                "ssh",
                side_effect=[
                    "shell-watch-grafana-abc 25m 512Mi\n",
                    "prometheus-main-0 100m 1Gi\n",
                ],
            ),
        ):
            usage = instance.memory_usage()
        self.assertEqual("shell-watch-grafana-abc", usage["grafana"]["pod"])
        self.assertEqual(1024**3, usage["prometheus"]["bytes"])

    def test_alert_state_requires_loaded_rule_and_reads_both_alert_systems(
        self,
    ) -> None:
        instance = observer.RecoveryObserver(mock.sentinel.connection, self.contract())
        responses = [
            json.dumps(
                {
                    "status": "success",
                    "data": {
                        "groups": [
                            {
                                "rules": [
                                    {
                                        "name": "ShellWatchGrafanaUnavailable",
                                        "health": "ok",
                                        "duration": 60,
                                        "query": (
                                            "kube_deployment_status_replicas_available"
                                            '{namespace="monitoring",deployment="shell-watch-grafana"} < 1'
                                        ),
                                        "labels": {
                                            "owner": "watch",
                                            "drill": "grafana-unavailability",
                                            "severity": "warning",
                                        },
                                    }
                                ]
                            }
                        ]
                    },
                }
            ),
            json.dumps({"status": "success", "data": {"result": []}}),
            "[]",
        ]
        with mock.patch.object(
            observer.verify_monitoring, "query_service", side_effect=responses
        ) as query:
            self.assertEqual(
                {"loaded": True, "firing": False, "active": False},
                instance.alert_state(),
            )
        self.assertEqual(3, query.call_count)

    def test_alert_state_rejects_an_unhealthy_same_named_rule(self) -> None:
        instance = observer.RecoveryObserver(mock.sentinel.connection, self.contract())
        responses = [
            json.dumps(
                {
                    "status": "success",
                    "data": {
                        "groups": [
                            {
                                "rules": [
                                    {
                                        "name": "ShellWatchGrafanaUnavailable",
                                        "health": "err",
                                        "duration": 60,
                                        "query": self.contract()["alert"]["query"],
                                        "labels": self.contract()["alert"]["labels"],
                                    }
                                ]
                            }
                        ]
                    },
                }
            ),
            json.dumps({"status": "success", "data": {"result": []}}),
            "[]",
        ]
        with mock.patch.object(
            observer.verify_monitoring, "query_service", side_effect=responses
        ):
            self.assertFalse(instance.alert_state()["loaded"])

    def test_alert_state_rejects_a_malformed_alertmanager_response(self) -> None:
        instance = observer.RecoveryObserver(mock.sentinel.connection, self.contract())
        responses = [
            json.dumps(
                {
                    "status": "success",
                    "data": {
                        "groups": [
                            {
                                "rules": [
                                    {
                                        "name": "ShellWatchGrafanaUnavailable",
                                        "health": "ok",
                                        "duration": 60,
                                        "query": self.contract()["alert"]["query"],
                                        "labels": self.contract()["alert"]["labels"],
                                    }
                                ]
                            }
                        ]
                    },
                }
            ),
            json.dumps({"status": "success", "data": {"result": []}}),
            json.dumps({"unexpected": "object"}),
        ]
        with mock.patch.object(
            observer.verify_monitoring, "query_service", side_effect=responses
        ):
            with self.assertRaisesRegex(
                observer.RecoveryObservationError, "Alertmanager.*invalid"
            ):
                instance.alert_state()


if __name__ == "__main__":
    unittest.main()
