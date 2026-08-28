"""Test WATCH's read-only Loki verification boundary."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
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


SCRIPT = WATCH_SCRIPTS_ROOT / "verify_logs.py"
SPEC = importlib.util.spec_from_file_location("verify_logs", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load WATCH logs verifier: {SCRIPT}")
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class TestLogsVerifier(unittest.TestCase):
    def test_alloy_readiness_requires_one_ready_daemonset(self) -> None:
        response = {
            "items": [
                {
                    "metadata": {"generation": 2},
                    "status": {
                        "observedGeneration": 2,
                        "desiredNumberScheduled": 3,
                        "currentNumberScheduled": 3,
                        "updatedNumberScheduled": 3,
                        "numberReady": 3,
                        "numberAvailable": 3,
                    },
                }
            ]
        }
        with mock.patch.object(
            verifier.transport,
            "ssh",
            return_value=json.dumps(response),
        ) as ssh:
            verifier.verify_alloy_ready(
                mock.sentinel.connection,
                "monitoring",
                "app.kubernetes.io/instance=shell-watch-alloy",
                3,
            )
        self.assertIn("get daemonset", ssh.call_args.kwargs["command"])

    def test_alloy_readiness_rejects_a_stale_rollout(self) -> None:
        response = {
            "items": [
                {
                    "metadata": {"generation": 2},
                    "status": {
                        "observedGeneration": 1,
                        "desiredNumberScheduled": 3,
                        "currentNumberScheduled": 3,
                        "updatedNumberScheduled": 2,
                        "numberReady": 3,
                        "numberAvailable": 3,
                    },
                }
            ]
        }
        with mock.patch.object(
            verifier.transport,
            "ssh",
            return_value=json.dumps(response),
        ):
            with self.assertRaisesRegex(verifier.WatchLogsVerifyError, "not ready"):
                verifier.verify_alloy_ready(
                    mock.sentinel.connection,
                    "monitoring",
                    "app.kubernetes.io/instance=shell-watch-alloy",
                    3,
                )

    def test_alloy_readiness_rejects_partial_node_coverage(self) -> None:
        response = {
            "items": [
                {
                    "metadata": {"generation": 2},
                    "status": {
                        "observedGeneration": 2,
                        "desiredNumberScheduled": 1,
                        "currentNumberScheduled": 1,
                        "updatedNumberScheduled": 1,
                        "numberReady": 1,
                        "numberAvailable": 1,
                    },
                }
            ]
        }
        with mock.patch.object(
            verifier.transport,
            "ssh",
            return_value=json.dumps(response),
        ):
            with self.assertRaisesRegex(verifier.WatchLogsVerifyError, "not ready"):
                verifier.verify_alloy_ready(
                    mock.sentinel.connection,
                    "monitoring",
                    "app.kubernetes.io/instance=shell-watch-alloy",
                    3,
                )

    def test_alloy_readiness_rejects_malformed_counters(self) -> None:
        response = {
            "items": [
                {
                    "metadata": {"generation": 2},
                    "status": {
                        "observedGeneration": 2,
                        "desiredNumberScheduled": "3",
                        "currentNumberScheduled": 3,
                        "updatedNumberScheduled": 3,
                        "numberReady": 3,
                        "numberAvailable": 3,
                    },
                }
            ]
        }
        with mock.patch.object(
            verifier.transport,
            "ssh",
            return_value=json.dumps(response),
        ):
            with self.assertRaisesRegex(verifier.WatchLogsVerifyError, "not ready"):
                verifier.verify_alloy_ready(
                    mock.sentinel.connection,
                    "monitoring",
                    "app.kubernetes.io/instance=shell-watch-alloy",
                    3,
                )

    def test_logs_query_uses_the_fixed_contract_boundary(self) -> None:
        connection = mock.sentinel.connection
        with mock.patch.object(
            verifier,
            "query_service",
            return_value="FRESH_LOG_ENTRIES=3",
        ) as query:
            verifier.verify_ingested_logs(
                connection,
                "monitoring",
                "app.kubernetes.io/component=gateway",
                80,
            )
        query.assert_called_once()
        args = query.call_args.args
        self.assertEqual("monitoring", args[1])
        self.assertEqual("app.kubernetes.io/component=gateway", args[2])
        self.assertEqual(80, args[3])
        self.assertIn("pod%3D~%22shell-watch-alloy-.%2B%22", args[4])
        self.assertIn("since=300s", args[4])

        fresh_payload = json.dumps(
            {
                "data": {
                    "result": [{"values": [[str(time.time_ns()), "current Alloy log"]]}]
                }
            }
        )
        filtered = subprocess.run(
            [sys.executable, "-c", args[5]],
            input=fresh_payload,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, filtered.returncode, filtered.stderr)

    def test_zero_log_entries_fail_closed(self) -> None:
        with mock.patch.object(
            verifier,
            "query_service",
            return_value="FRESH_LOG_ENTRIES=0",
        ):
            with self.assertRaisesRegex(
                verifier.WatchLogsVerifyError, "no fresh Alloy log entries"
            ):
                verifier.verify_ingested_logs(
                    mock.sentinel.connection,
                    "monitoring",
                    "release=shell-watch-loki",
                    80,
                )

    def test_logs_verifier_has_no_grafana_or_recovery_scope(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("grafana", source.lower())
        self.assertNotIn("datasource", source.lower())
        self.assertNotIn("recovery", source.lower())
        self.assertNotIn(":latest", source)
        self.assertNotIn("--limit", source)

    def test_watch_makefile_exposes_only_read_only_logs_verification(self) -> None:
        source = (WATCH_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("check-logs", source)
        self.assertIn("verify-logs", source)
        self.assertNotIn("logs-apply", source)


if __name__ == "__main__":
    unittest.main()
