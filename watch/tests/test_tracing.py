"""Test the source-only WATCH tracing boundary."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_ROOT = ROOT / "watch/scripts"
sys.path.insert(0, str(SCRIPT_ROOT))
sys.path.insert(0, str(ROOT / "make/scripts"))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load WATCH tracing script: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract = load("validate_tracing_contract", SCRIPT_ROOT / "validate_tracing_contract.py")
verify = load("verify_tracing", SCRIPT_ROOT / "verify_tracing.py")


class TracingSourceTests(unittest.TestCase):
    def test_source_contract_validates(self) -> None:
        document = contract.validate_contract()
        self.assertEqual(document["tempo"]["retention"], "24h")
        self.assertEqual(document["collector"]["metrics_port"], 8889)

    def test_contract_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tracing.json"
            path.write_text(
                '{"schema_version":"1.0","schema_version":"2"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                contract.TracingContractError, "duplicate JSON key"
            ):
                contract.read_json(path, "tracing contract")

    def test_workload_readiness_requires_generation_and_replicas(self) -> None:
        resource = {
            "metadata": {"generation": 2},
            "status": {
                "observedGeneration": 2,
                "readyReplicas": 1,
                "currentReplicas": 1,
                "updatedReplicas": 1,
            },
        }
        verify.verify_ready_workload(resource, "StatefulSet", 1, "tempo")
        resource["status"]["readyReplicas"] = 0
        with self.assertRaisesRegex(verify.TracingVerifyError, "not ready"):
            verify.verify_ready_workload(resource, "StatefulSet", 1, "tempo")

    def test_services_reject_external_routes(self) -> None:
        resource = {
            "spec": {
                "type": "ClusterIP",
                "ports": [{"port": 3200}, {"port": 4317}, {"port": 4318}],
            }
        }
        verify.verify_service(resource, "tempo", {3200, 4317, 4318}, "ClusterIP")
        resource["spec"]["loadBalancerIP"] = "10.0.0.1"
        with self.assertRaisesRegex(verify.TracingVerifyError, "external route"):
            verify.verify_service(resource, "tempo", {3200}, "ClusterIP")

    def test_verifier_is_read_only(self) -> None:
        source = (SCRIPT_ROOT / "verify_tracing.py").read_text(encoding="utf-8")
        for forbidden in (" apply ", " delete ", " patch ", " create "):
            self.assertNotIn(forbidden, source)
        self.assertIn("port-forward", source)
        self.assertNotIn("instrumented_application_trace", source)


if __name__ == "__main__":
    unittest.main()
