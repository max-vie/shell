"""Test the TAR-to-INIT Cilium network supply handoff."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name}: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


validator = load(
    "validate_init_k3s_network_supply",
    ROOT / "tar/scripts/validate_init_k3s_network_supply.py",
)
stager = load(
    "stage_init_k3s_network_supply",
    ROOT / "tar/scripts/stage_init_k3s_network_supply.py",
)


class TestInitK3sNetworkSupply(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.helm_source = Path(self.temporary.name) / "helm"
        self.helm_content = b"synthetic Helm binary\n"
        self.helm_source.write_bytes(self.helm_content)
        self.chart_source = Path(self.temporary.name) / "cilium.tgz"
        self.chart_content = b"synthetic Cilium chart\n"
        self.chart_source.write_bytes(self.chart_content)
        self.expected_helm = {
            **validator.EXPECTED_HELM_BINARY,
            "sha256": hashlib.sha256(self.helm_content).hexdigest(),
            "size": len(self.helm_content),
        }
        self.expected_chart = {
            **validator.EXPECTED_CILIUM_CHART,
            "sha256": hashlib.sha256(self.chart_content).hexdigest(),
            "size": len(self.chart_content),
        }
        self.patchers = [
            mock.patch.object(validator, "EXPECTED_HELM_BINARY", self.expected_helm),
            mock.patch.object(validator, "EXPECTED_CILIUM_CHART", self.expected_chart),
        ]
        for patcher in self.patchers:
            patcher.start()
        self.lock_path = self.root / "tar/manifests/init-k3s-network-supply.json"
        self.write_lock()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def lock_value(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "contract_version": "1.0.0",
            "contract_id": "init-k3s-network-supply",
            "policy_owner": "tar",
            "execution_owner": "init",
            "proof_status": "source-reference-only",
            "staging": {
                "mode": "local-verified-artifacts",
                "network_acquisition_owner": "tar",
                "consumer_network_acquisition": False,
                "artifact_directory": "init-k3s-network",
                "chart_cache_layout": "charts/{name}-{version}.tgz",
            },
            "helm_binary": copy.deepcopy(self.expected_helm),
            "cilium_chart": copy.deepcopy(self.expected_chart),
            "cilium_images": copy.deepcopy(validator.EXPECTED_CILIUM_IMAGES),
            "cilium_configuration": copy.deepcopy(
                validator.EXPECTED_CILIUM_CONFIGURATION
            ),
        }

    def write_lock(self, value: dict[str, Any] | None = None) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.write_text(
            json.dumps(self.lock_value() if value is None else value),
            encoding="utf-8",
        )

    def stage(self) -> tuple[Path, Path, Path]:
        return stager.stage(
            self.helm_source,
            self.chart_source,
            repository_root=self.root,
            lock_path=self.lock_path,
        )

    def test_contract_validates_the_exact_network_inputs(self) -> None:
        lock = validator.validate_public(self.lock_path)
        self.assertEqual(lock["cilium_chart"]["name"], "cilium")
        self.assertEqual(set(lock["cilium_images"]), {"agent", "envoy", "operator"})
        self.assertEqual(lock["cilium_configuration"]["operator_replicas"], 1)

    def test_stage_publishes_private_inputs_and_handoff(self) -> None:
        helm, chart, handoff_path = self.stage()
        self.assertEqual(helm.read_bytes(), self.helm_content)
        self.assertEqual(chart.read_bytes(), self.chart_content)
        for path in (helm, chart, handoff_path):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(helm.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(chart.parent.stat().st_mode), 0o700)
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        self.assertEqual(
            handoff,
            {
                "shell_k3s_helm_version": self.expected_helm["version"],
                "shell_k3s_helm_path": str(helm),
                "shell_k3s_helm_sha256": self.expected_helm["sha256"],
                "shell_k3s_cilium_chart_path": str(chart),
                "shell_k3s_cilium_chart_sha256": self.expected_chart["sha256"],
                "shell_k3s_cilium_chart_version": self.expected_chart["version"],
                "shell_k3s_cilium_images": validator.EXPECTED_CILIUM_IMAGES,
                "shell_k3s_cilium_configuration": validator.EXPECTED_CILIUM_CONFIGURATION,
            },
        )

    def test_stage_is_idempotent_for_matching_private_state(self) -> None:
        helm, chart, handoff = self.stage()
        baseline = tuple(path.stat().st_ino for path in (helm, chart, handoff))
        repeated = self.stage()
        self.assertEqual(
            tuple(path.stat().st_ino for path in repeated),
            baseline,
        )

    def test_validate_staged_checks_both_artifacts(self) -> None:
        self.stage()
        validator.validate_staged(
            self.root / ".local/tar/init-k3s-network", self.lock_path
        )

    def test_stage_rejects_a_symlinked_source_before_state(self) -> None:
        source_link = Path(self.temporary.name) / "helm-link"
        source_link.symlink_to(self.helm_source)
        with self.assertRaisesRegex(stager.trusted_stage.SupplyError, "regular file"):
            stager.stage(
                source_link,
                self.chart_source,
                repository_root=self.root,
                lock_path=self.lock_path,
            )
        self.assertFalse((self.root / ".local").exists())

    def test_stage_rejects_a_bad_chart_size_before_state(self) -> None:
        self.chart_source.write_bytes(self.chart_content + b"extra")
        with self.assertRaisesRegex(stager.NetworkStageError, "size does not match"):
            self.stage()
        self.assertFalse((self.root / ".local").exists())

    def test_lock_rejects_unknown_fields_and_changed_configuration(self) -> None:
        unknown = self.lock_value()
        unknown["future"] = True
        self.write_lock(unknown)
        with self.assertRaisesRegex(validator.NetworkSupplyError, "shape changed"):
            validator.validate_public(self.lock_path)

        changed = self.lock_value()
        changed["cilium_configuration"]["operator_replicas"] = 2
        self.write_lock(changed)
        with self.assertRaisesRegex(
            validator.NetworkSupplyError, "configuration changed"
        ):
            validator.validate_public(self.lock_path)


if __name__ == "__main__":
    unittest.main()
