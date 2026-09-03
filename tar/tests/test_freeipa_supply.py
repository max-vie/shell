"""Test the source-only TAR FreeIPA package contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tar/scripts/validate_freeipa_supply.py"
SPEC = importlib.util.spec_from_file_location("validate_freeipa_supply", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load FreeIPA supply validator")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TestFreeIPASupply(unittest.TestCase):
    def setUp(self) -> None:
        self.source = json.loads(
            (ROOT / "tar/manifests/freeipa-supply.json").read_text(encoding="utf-8")
        )

    def write(self, value: dict[str, object]) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", delete=False
        )
        with temporary:
            json.dump(value, temporary)
        return Path(temporary.name)

    def test_current_source_contract_validates(self) -> None:
        lock = validator.validate_public()
        self.assertEqual(lock["contract_id"], "freeipa-supply")
        self.assertEqual(lock["packages"], validator.EXPECTED_PACKAGES)

    def test_rejects_unknown_fields_and_package_drift(self) -> None:
        changed = copy.deepcopy(self.source)
        changed["future"] = True
        path = self.write(changed)
        self.addCleanup(path.unlink, missing_ok=True)
        with self.assertRaisesRegex(validator.FreeIPASupplyError, "shape changed"):
            validator.validate_public(path)

        changed = copy.deepcopy(self.source)
        changed["packages"] = ["ipa-server"]
        path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(validator.FreeIPASupplyError, "package set"):
            validator.validate_public(path)

    def test_rejects_acquisition_policy_drift(self) -> None:
        changed = copy.deepcopy(self.source)
        changed["acquisition"]["network_acquisition_owner"] = "tar"
        path = self.write(changed)
        self.addCleanup(path.unlink, missing_ok=True)
        with self.assertRaisesRegex(validator.FreeIPASupplyError, "acquisition policy"):
            validator.validate_public(path)


if __name__ == "__main__":
    unittest.main()
