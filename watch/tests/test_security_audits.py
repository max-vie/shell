"""Test the source-only WATCH kube-bench and k6 boundaries."""

from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WATCH_SCRIPTS = ROOT / "watch/scripts"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kube_bench = load("watch_kube_bench", WATCH_SCRIPTS / "kube_bench.py")
k6 = load("watch_k6_load", WATCH_SCRIPTS / "k6_load.py")


class SecurityAuditTests(unittest.TestCase):
    def test_kube_bench_contract_and_resources(self) -> None:
        document = kube_bench.contract()
        resources = kube_bench.resources("20260903120000")
        daemonset = next(item for item in resources if item["kind"] == "DaemonSet")
        pod = daemonset["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertEqual(document["benchmark"], "k3s-cis-1.9")
        self.assertTrue(pod["hostPID"])
        self.assertFalse(pod.get("hostNetwork", False))
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertEqual(len(pod["volumes"]), 9)
        self.assertTrue(all(volume["hostPath"]["type"] == "Directory" for volume in pod["volumes"] if "hostPath" in volume))

    def test_kube_bench_parser_counts_nested_results(self) -> None:
        payload = json.dumps({"Controls": [{"tests": [{"results": [{"status": "PASS"}, {"status": "WARN"}, {"status": "FAIL"}]}]}]})
        self.assertEqual(
            kube_bench.parse_report(payload),
            {"PASS": 1, "FAIL": 1, "WARN": 1, "INFO": 0, "NOT_APPLICABLE": 0, "MANUAL": 0},
        )

    def test_k6_contract_and_job_are_bounded(self) -> None:
        document = k6.contract()
        job = next(item for item in k6.resources("20260903120000") if item["kind"] == "Job")
        pod = job["spec"]["template"]["spec"]
        container = pod["containers"][0]
        self.assertEqual(document["expected_requests"], 600)
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertFalse(pod.get("hostNetwork", False))
        self.assertFalse(pod.get("hostPID", False))
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertNotIn("imagePullSecrets", pod)

    def _summary(self, requests: int = 600) -> dict[str, object]:
        return {
            "metrics": {
                "http_reqs": {"values": {"count": requests}},
                "dropped_iterations": {"values": {"count": 0}},
                "http_req_failed": {"values": {"rate": 0}},
                "checks": {"values": {"rate": 1}},
                "http_req_duration": {"values": {"p(95)": 12.5}},
            }
        }

    def test_k6_summary_gate(self) -> None:
        values = k6.validate_summary(self._summary())
        self.assertEqual(values["requests"], 600)
        with self.assertRaisesRegex(k6.K6Error, "request count"):
            k6.validate_summary(self._summary(599))

    def test_evidence_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            k6_path = Path(directory) / "k6.json"
            bench_path = Path(directory) / "bench.json"
            k6.write_evidence(k6_path, {"result": "pass"})
            kube_bench.write_evidence(bench_path, {"result": "pass"})
            self.assertEqual(stat.S_IMODE(k6_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(bench_path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(k6.K6Error, "overwrite"):
                k6.write_evidence(k6_path, {"result": "pass"})
            with self.assertRaisesRegex(kube_bench.KubeBenchError, "overwrite"):
                kube_bench.write_evidence(bench_path, {"result": "pass"})


if __name__ == "__main__":
    unittest.main()
