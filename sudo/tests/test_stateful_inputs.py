"""Test SUDO stateful contracts without reading private inputs."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_stateful_inputs", ROOT / "sudo/scripts/validate_stateful_inputs.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load SUDO stateful validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class StatefulInputTests(unittest.TestCase):
    def test_public_contracts_validate(self) -> None:
        self.assertEqual(
            module.validate_release_feed()["inputs"]["release_feed"]["required_keys"],
            ["read_token", "write_token"],
        )
        self.assertEqual(module.validate_openbao()["initialization"]["threshold"], 3)

    def test_plaintext_private_values_are_not_in_contract(self) -> None:
        for path in (module.RELEASE_FEED, module.OPENBAO):
            source = path.read_text(encoding="utf-8")
            if path == module.OPENBAO:
                self.assertNotIn("admin_password", source)
            self.assertNotIn("BEGIN PRIVATE", source)
            self.assertNotIn('read_token": "', source)

    def test_duplicate_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(
                '{"schema_version":"1.0","schema_version":"2"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                module.StatefulInputError, "duplicate JSON key"
            ):
                module.read_json(path, "test contract")

    def test_changed_openbao_threshold_is_rejected(self) -> None:
        changed = copy.deepcopy(json.loads(module.OPENBAO.read_text(encoding="utf-8")))
        changed["initialization"]["threshold"] = 4
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(
                module.StatefulInputError, "initialization policy"
            ):
                module.validate_openbao(path)

    def test_malformed_types_fail_closed(self) -> None:
        release = json.loads(module.RELEASE_FEED.read_text(encoding="utf-8"))
        release["description"] = {"unexpected": True}
        release["inputs"] = None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(release), encoding="utf-8")
            with self.assertRaises(module.StatefulInputError):
                module.validate_release_feed(path)

    def test_release_feed_phase_drift_is_rejected(self) -> None:
        release = json.loads(module.RELEASE_FEED.read_text(encoding="utf-8"))
        release["inputs"]["release_feed"]["phase"] = "after-bootstrap"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(release), encoding="utf-8")
            with self.assertRaisesRegex(module.StatefulInputError, "release_feed input"):
                module.validate_release_feed(path)


if __name__ == "__main__":
    unittest.main()
