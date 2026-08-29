"""Test the source-only Grafana recovery policy."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate_recovery.py"
SPEC = importlib.util.spec_from_file_location("validate_recovery", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TestRecoveryContract(unittest.TestCase):
    def test_current_contract_and_rule_validate(self) -> None:
        document = validator.validate_contract()
        validator.validate_rule()
        self.assertEqual("grafana-recovery-drill", document["contract_id"])
        self.assertEqual("make", document["execution_owner"])
        self.assertEqual(20, document["stability"]["samples"])

    def test_contract_rejects_target_drift(self) -> None:
        source = json.loads(validator.CONTRACT_PATH.read_text(encoding="utf-8"))
        source["target"]["name"] = "other"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(validator.RecoveryValidationError, "target"):
                validator.validate_contract(path)

    def test_contract_rejects_duplicate_keys(self) -> None:
        source = validator.CONTRACT_PATH.read_text(encoding="utf-8")
        altered = source.replace('"name": "gcp",', '"name": "gcp", "name": "other",')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(altered, encoding="utf-8")
            with self.assertRaisesRegex(validator.RecoveryValidationError, "duplicate"):
                validator.validate_contract(path)

    def test_rule_rejects_donor_or_watchdog_scope(self) -> None:
        source = validator.RULE_PATH.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rule.yaml"
            path.write_text(source + "\n        - alert: Watchdog\n", encoding="utf-8")
            with self.assertRaisesRegex(validator.RecoveryValidationError, "Watchdog"):
                validator.validate_rule(path)

    def test_rule_rejects_a_changed_query(self) -> None:
        source = validator.RULE_PATH.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rule.yaml"
            path.write_text(source.replace("< 1", "< 2"), encoding="utf-8")
            with self.assertRaisesRegex(validator.RecoveryValidationError, "query"):
                validator.validate_rule(path)


if __name__ == "__main__":
    unittest.main()
