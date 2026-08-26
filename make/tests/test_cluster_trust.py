"""Test the source-only MAKE cluster-trust contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SOURCE_ROOT / "make/scripts/validate_cluster_trust.py"
SPEC = importlib.util.spec_from_file_location("validate_cluster_trust", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load cluster-trust validator: {SCRIPT}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TestClusterTrust(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        for relative in (
            "make/contracts/cluster-trust-requirements.json",
            "sudo/access/kubernetes-ecosystem-profile.json",
            "sudo/secrets/kubernetes-ecosystem-input-contract.json",
            "sudo/pki/shell-offline-root.crt.pem",
            "tar/manifests/kubernetes-ecosystem-supply.json",
            "init/scripts/run_k3s_runtime.py",
            "make/cert-manager/cluster-issuer.json",
            "make/cert-manager/values.yaml",
            "make/certificates/forgejo-tls.json",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE_ROOT / relative, target)
        self.contract_path = self.root / "make/contracts/cluster-trust-requirements.json"
        self.contract = json.loads(self.contract_path.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_current_contract_validates(self) -> None:
        contract = validator.validate_contract(
            self.contract_path, repository_root=self.root
        )
        self.assertEqual(contract["cluster_scope"], ["gcp", "proxmox"])

    def test_rejects_unknown_fields_and_manifest_drift(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["unexpected"] = True
        self.contract_path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(validator.ClusterTrustError, "shape changed"):
            validator.validate_contract(self.contract_path, repository_root=self.root)

        self.contract_path.write_text(json.dumps(self.contract), encoding="utf-8")
        manifest = self.root / "make/certificates/forgejo-tls.json"
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["spec"]["dnsNames"] = ["other.shell.internal"]
        manifest.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(validator.ClusterTrustError, "consumer certificate"):
            validator.validate_contract(self.contract_path, repository_root=self.root)

    def test_rejects_duplicate_contract_keys(self) -> None:
        self.contract_path.write_text(
            '{"schema_version":"1.0","schema_version":"2"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(validator.ClusterTrustError, "duplicate JSON key"):
            validator.validate_contract(self.contract_path, repository_root=self.root)

    def test_rejects_missing_source_contract(self) -> None:
        source = self.root / "tar/manifests/kubernetes-ecosystem-supply.json"
        source.unlink()
        with self.assertRaisesRegex(validator.ClusterTrustError, "missing regular"):
            validator.validate_contract(self.contract_path, repository_root=self.root)


if __name__ == "__main__":
    unittest.main()
