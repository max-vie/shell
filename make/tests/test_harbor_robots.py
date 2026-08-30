"""Test Harbor robot contract boundaries without private handoffs."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_harbor_robots", ROOT / "make/scripts/validate_harbor_robots.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Harbor robot validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class HarborRobotTests(unittest.TestCase):
    def test_robot_contract_validates_without_values(self) -> None:
        document = module.validate()
        self.assertEqual(document["endpoint"]["address"], "10.77.0.221")
        self.assertNotIn("password", str(document).lower())

    def test_duplicate_and_unknown_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text(
                '{"contract_id":"one","contract_id":"two"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(module.HarborRobotError, "duplicate JSON key"):
                module.validate(duplicate)

            changed = module.validate()
            changed["future"] = True
            unknown = Path(directory) / "unknown.json"
            unknown.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(module.HarborRobotError, "shape changed"):
                module.validate(unknown)


if __name__ == "__main__":
    unittest.main()
