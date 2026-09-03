"""Test the source-only Cosign and Kyverno admission contract."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "make/scripts/validate_cosign_admission.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("validate_cosign_admission", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Cosign admission validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class CosignAdmissionTests(unittest.TestCase):
    def test_source_contract_validates(self) -> None:
        contract = module.validate()
        self.assertEqual(contract["policy"]["failure_policy"], "Fail")
        self.assertTrue(contract["policy"]["verify_digest"])

    def test_source_does_not_contain_private_trust_material(self) -> None:
        for path in (
            ROOT / "make/gitops/values/kyverno.yaml",
            ROOT / "make/gitops/platform/kyverno/policies.yaml",
            ROOT / "make/gitops/platform/kyverno/trust-rbac.yaml",
        ):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("BEGIN ENCRYPTED", source)
            self.assertNotIn("private_key", source)
            self.assertNotIn("password", source.lower())

    def test_policy_is_label_scoped(self) -> None:
        source = (ROOT / "make/gitops/platform/kyverno/policies.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("shell.platform/policy: enforced", source)
        self.assertIn("registry.shell.internal/shell/*", source)
        self.assertIn("failurePolicy: Fail", source)


if __name__ == "__main__":
    unittest.main()
