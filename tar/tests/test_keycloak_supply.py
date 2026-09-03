"""Test the source-only TAR Keycloak image supply contract."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_keycloak_supply", ROOT / "tar/scripts/validate_keycloak_supply.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Keycloak supply validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class KeycloakSupplyTests(unittest.TestCase):
    def test_public_pins_validate_without_staging(self) -> None:
        lock = module.validate_public()
        self.assertEqual(set(lock["images"]), {"keycloak", "postgresql"})
        self.assertTrue(all("@sha256:" in image["runtime"] for image in lock["images"].values()))

    def test_changed_or_extra_pins_are_rejected(self) -> None:
        source = json.loads(
            (ROOT / "tar/manifests/keycloak-supply.json").read_text(encoding="utf-8")
        )
        for changed in (
            {**source, "images": {**source["images"], "other": {}}},
            {**source, "images": {**source["images"], "keycloak": {**source["images"]["keycloak"], "digest": "sha256:" + "0" * 64}}},
        ):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "keycloak.json"
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises(module.KeycloakSupplyError):
                    module.validate_public(path)

    def test_duplicate_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keycloak.json"
            path.write_text('{"contract_id":"one","contract_id":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(module.KeycloakSupplyError, "duplicate JSON key"):
                module.read_json(path)


if __name__ == "__main__":
    unittest.main()
