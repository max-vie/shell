"""Test WATCH's read-only monitoring verifier without contacting a cluster."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WATCH_ROOT = REPOSITORY_ROOT / "watch"
MAKE_SCRIPTS_ROOT = REPOSITORY_ROOT / "make/scripts"
WATCH_SCRIPTS_ROOT = WATCH_ROOT / "scripts"
for scripts_root in (MAKE_SCRIPTS_ROOT, WATCH_SCRIPTS_ROOT):
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))


def load(name: str, path: Path):
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
                "print('ok')",
            )
        self.assertEqual("proof", output)
        command = ssh.call_args.kwargs["command"]
        self.assertIn("mktemp -d", command)
        self.assertIn("s.bind", command)
        self.assertNotIn("19090", command)
        self.assertNotIn("/tmp/shell-watch-port-forward.log", command)
        self.assertEqual(45, ssh.call_args.kwargs["timeout_seconds"])

    def test_verify_contains_only_the_metrics_proof_targets(self) -> None:
        source = (WATCH_SCRIPTS_ROOT / "verify_monitoring.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("node-exporter", source)
        self.assertIn("Watchdog", source)
        self.assertNotIn("loki", source.lower())
        self.assertNotIn("recovery", source.lower())
        self.assertNotIn("register_forgejo_repository", source)


if __name__ == "__main__":
    unittest.main()
