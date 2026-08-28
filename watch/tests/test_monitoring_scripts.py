"""Test WATCH's read-only monitoring verifier without contacting a cluster."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WATCH_ROOT = REPOSITORY_ROOT / "watch"
MAKE_SCRIPTS_ROOT = REPOSITORY_ROOT / "make/scripts"
WATCH_SCRIPTS_ROOT = WATCH_ROOT / "scripts"
for scripts_root in (MAKE_SCRIPTS_ROOT, WATCH_SCRIPTS_ROOT):
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load WATCH script: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verify = load("watch_verify_monitoring", WATCH_SCRIPTS_ROOT / "verify_monitoring.py")


class TestMonitoringScripts(unittest.TestCase):
    def test_watch_has_no_kubernetes_mutation_entrypoint(self) -> None:
        makefile = (WATCH_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertNotIn("apply:", makefile)
        self.assertNotIn("deploy_monitoring", makefile)
        self.assertIn("check-logs:", makefile)
        self.assertIn("verify-logs:", makefile)
        self.assertFalse((WATCH_SCRIPTS_ROOT / "deploy_monitoring.py").exists())
        self.assertFalse((WATCH_ROOT / "monitoring/values.yaml").exists())

    def test_service_name_is_derived_from_the_contract_selector(self) -> None:
        service = {
            "items": [
                {
                    "metadata": {"name": "generated-prometheus"},
                    "spec": {"ports": [{"port": 9090}]},
                }
            ]
        }
        with mock.patch.object(
            verify.transport, "ssh", return_value=json.dumps(service)
        ) as ssh:
            name = verify.resolve_service(
                mock.sentinel.connection,
                "monitoring",
                "app=prometheus,release=shell-watch",
                9090,
            )
        self.assertEqual("generated-prometheus", name)
        self.assertIn(
            "app=prometheus,release=shell-watch", ssh.call_args.kwargs["command"]
        )

    def test_service_selector_must_resolve_exactly_once(self) -> None:
        with mock.patch.object(
            verify.transport,
            "ssh",
            return_value=json.dumps({"items": [{}, {}]}),
        ):
            with self.assertRaisesRegex(verify.WatchVerifyError, "resolve one service"):
                verify.resolve_service(
                    mock.sentinel.connection,
                    "monitoring",
                    "release=shell-watch",
                    9090,
                )

    def test_configmap_selector_must_resolve_exactly_once(self) -> None:
        response = {
            "items": [
                {
                    "metadata": {"name": "grafana-datasources"},
                    "data": {"datasources.yaml": "type: prometheus"},
                }
            ]
        }
        with mock.patch.object(
            verify.transport,
            "ssh",
            return_value=json.dumps(response),
        ) as ssh:
            resource = verify.resolve_resource(
                mock.sentinel.connection,
                "monitoring",
                "configmap",
                "app.kubernetes.io/name=grafana,app.kubernetes.io/instance=shell-watch",
            )
        self.assertEqual("grafana-datasources", resource["metadata"]["name"])
        self.assertIn(
            "get configmap -l app.kubernetes.io/name=grafana,app.kubernetes.io/instance=shell-watch",
            ssh.call_args.kwargs["command"],
        )

    def test_query_uses_ephemeral_port_and_temporary_log(self) -> None:
        with (
            mock.patch.object(verify, "resolve_service", return_value="prometheus-svc"),
            mock.patch.object(verify.transport, "ssh", return_value="proof") as ssh,
        ):
            output = verify.query_service(
                mock.sentinel.connection,
                "monitoring",
                "release=shell-watch",
                9090,
                "/api/v1/targets",
            )
        self.assertEqual("proof", output)
        command = ssh.call_args.kwargs["command"]
        self.assertIn("mktemp -d", command)
        self.assertIn("s.bind", command)
        self.assertIn("curl --fail", command)
        self.assertNotIn("19090", command)
        self.assertNotIn("/tmp/shell-watch-port-forward.log", command)
        self.assertEqual(45, ssh.call_args.kwargs["timeout_seconds"])

    def test_grafana_health_uses_the_contract_path(self) -> None:
        with mock.patch.object(
            verify,
            "query_service",
            return_value=json.dumps({"database": "ok", "version": "13.2.0"}),
        ) as query:
            verify.verify_grafana_health(
                mock.sentinel.connection,
                "monitoring",
                "app.kubernetes.io/name=grafana",
                80,
                "/api/health",
            )
        self.assertEqual(
            (
                mock.sentinel.connection,
                "monitoring",
                "app.kubernetes.io/name=grafana",
                80,
                "/api/health",
            ),
            query.call_args.args[:5],
        )

    def test_grafana_provisioned_datasource_and_query_are_checked(self) -> None:
        datasource = {
            "uid": "prometheus",
            "type": "prometheus",
            "url": "http://prometheus.monitoring:9090/",
            "access": "proxy",
            "readOnly": True,
        }
        proof = {"status": "success", "data": {"result": [{"value": [1, "1"]}]}}
        with mock.patch.object(
            verify,
            "query_service",
            side_effect=[json.dumps(datasource), json.dumps(proof)],
        ) as query:
            verify.verify_grafana_datasource(
                mock.sentinel.connection,
                "monitoring",
                "app.kubernetes.io/name=grafana",
                80,
                "prometheus",
                "prometheus",
                "http://prometheus.monitoring:9090/",
            )
            verify.verify_grafana_datasource_query(
                mock.sentinel.connection,
                "monitoring",
                "app.kubernetes.io/name=grafana",
                80,
                "prometheus",
                "/api/v1/query?query=vector%281%29",
            )
        self.assertIn(
            "/api/datasources/uid/prometheus",
            query.call_args_list[0].args[4],
        )
        self.assertIn(
            "/api/datasources/proxy/uid/prometheus/api/v1/query",
            query.call_args_list[1].args[4],
        )

    def test_grafana_datasource_query_must_succeed(self) -> None:
        with mock.patch.object(
            verify,
            "query_service",
            return_value=json.dumps({"status": "error", "data": {}}),
        ):
            with self.assertRaisesRegex(verify.WatchVerifyError, "query failed"):
                verify.verify_grafana_datasource_query(
                    mock.sentinel.connection,
                    "monitoring",
                    "app.kubernetes.io/name=grafana",
                    80,
                    "loki",
                    "/loki/api/v1/query_range?query=%7Bjob%3D%22alloy%22%7D",
                )

    def test_grafana_loki_datasource_query_accepts_a_bounded_success(self) -> None:
        with mock.patch.object(
            verify,
            "query_service",
            return_value=json.dumps(
                {"status": "success", "data": {"result": []}}
            ),
        ) as query:
            verify.verify_grafana_datasource_query(
                mock.sentinel.connection,
                "monitoring",
                "app.kubernetes.io/name=grafana",
                80,
                "loki",
                "/loki/api/v1/query_range?query=%7Bjob%3D%22alloy%22%7D&limit=1",
            )
        self.assertIn(
            "/api/datasources/proxy/uid/loki/loki/api/v1/query_range",
            query.call_args.args[4],
        )

    def test_grafana_datasource_rejects_wrong_loaded_url(self) -> None:
        datasource = {
            "uid": "prometheus",
            "type": "prometheus",
            "url": "http://wrong.invalid",
            "access": "proxy",
            "readOnly": True,
        }
        with mock.patch.object(
            verify,
            "query_service",
            return_value=json.dumps(datasource),
        ):
            with self.assertRaisesRegex(verify.WatchVerifyError, "URL changed"):
                verify.verify_grafana_datasource(
                    mock.sentinel.connection,
                    "monitoring",
                    "app.kubernetes.io/name=grafana",
                    80,
                    "prometheus",
                    "prometheus",
                    "http://prometheus.monitoring:9090/",
                )

    def test_grafana_dashboard_is_read_from_the_api(self) -> None:
        response = {
            "metadata": {"name": "shell-watch-overview"},
            "spec": {
                "uid": "shell-watch-overview",
                "title": "SHELL Watch Overview",
                "panels": [
                    {"datasource": {"uid": "prometheus"}},
                    {"datasource": {"uid": "loki"}},
                ],
            }
        }
        with mock.patch.object(
            verify,
            "query_service",
            return_value=json.dumps(response),
        ) as query:
            verify.verify_grafana_dashboard(
                mock.sentinel.connection,
                "monitoring",
                "app.kubernetes.io/name=grafana",
                80,
                "shell-watch-overview",
                "SHELL Watch Overview",
                {"prometheus", "loki"},
            )
        self.assertEqual(
            "/apis/dashboard.grafana.app/v1/namespaces/default/dashboards/"
            "shell-watch-overview",
            query.call_args.args[4],
        )

    def test_grafana_dashboard_must_be_provisioned(self) -> None:
        with mock.patch.object(
            verify,
            "query_service",
            return_value=json.dumps(
                {"metadata": {"name": "shell-watch-overview"}}
            ),
        ):
            with self.assertRaisesRegex(verify.WatchVerifyError, "not provisioned"):
                verify.verify_grafana_dashboard(
                    mock.sentinel.connection,
                    "monitoring",
                    "app.kubernetes.io/name=grafana",
                    80,
                    "shell-watch-overview",
                    "SHELL Watch Overview",
                    {"prometheus", "loki"},
                )

    def test_verify_contains_metrics_and_grafana_proof_targets(self) -> None:
        source = (WATCH_SCRIPTS_ROOT / "verify_monitoring.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("node-exporter", source)
        self.assertIn("Watchdog", source)
        self.assertIn("Grafana", source)
        self.assertIn("verify_grafana_health", source)
        self.assertIn("dashboard", source.lower())
        self.assertNotIn("recovery", source.lower())
        self.assertNotIn("register_forgejo_repository", source)

    def test_verify_runs_both_datasource_proofs_and_the_dashboard(self) -> None:
        with (
            mock.patch.object(
                verify.transport,
                "resolve_connection",
                return_value=mock.sentinel.connection,
            ),
            mock.patch.object(verify, "verify_scrape_target"),
            mock.patch.object(verify, "verify_watchdog"),
            mock.patch.object(verify, "verify_grafana_health"),
            mock.patch.object(verify, "verify_grafana_datasource") as datasource,
            mock.patch.object(
                verify, "verify_grafana_datasource_query"
            ) as datasource_query,
            mock.patch.object(verify, "verify_grafana_dashboard") as dashboard,
        ):
            verify.verify([Path("inventory")])
        self.assertEqual(2, datasource.call_count)
        self.assertEqual(2, datasource_query.call_count)
        dashboard.assert_called_once()


if __name__ == "__main__":
    unittest.main()
