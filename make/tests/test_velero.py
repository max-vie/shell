"""Test the source-only Velero and GCS workload contract."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "make/scripts/validate_velero.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("validate_velero", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Velero validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class VeleroSourceTests(unittest.TestCase):
    def test_source_contract_and_manifests_validate(self) -> None:
        contract = module.validate()
        self.assertEqual(contract["backup"]["provider"], "gcp")
        self.assertEqual(contract["snapshot"]["driver"], "driver.longhorn.io")

    def test_source_has_no_legacy_object_store_or_mutable_images(self) -> None:
        paths = [ROOT / "make/gitops/values/velero.yaml"] + list(
            (ROOT / "make/gitops/platform/velero").rglob("*.yaml")
        )
        for path in paths:
            source = path.read_text(encoding="utf-8").lower()
            self.assertNotIn("rustfs", source)
            self.assertNotIn(":latest", source)
        values = (ROOT / "make/gitops/values/velero.yaml").read_text(encoding="utf-8")
        self.assertIn("provider: gcp", values)
        self.assertIn("uploaderType: kopia", values)


if __name__ == "__main__":
    unittest.main()
