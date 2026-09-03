"""Test Keycloak input generation without private values or SOPS."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "sudo/scripts/generate_keycloak_inputs.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("generate_keycloak_inputs", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Keycloak input generator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class KeycloakInputGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.private_root = self.root / ".local/sudo/keycloak"
        self.private_root.mkdir(parents=True, mode=0o700)
        for parent in (self.root / ".local", self.root / ".local/sudo", self.private_root):
            parent.chmod(0o700)
        self.age_key = self.private_root / "age-key.txt"
        self.age_key.write_text("AGE-SECRET-KEY-test\n", encoding="utf-8")
        self.age_key.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def contracts() -> dict[str, dict[str, object]]:
        return {"keycloak": {"identity": {"bind_principal": "keycloak-bind"}}}

    @staticmethod
    def run_command(command: list[str], **_: object) -> str:
        if command[0] == "age-keygen":
            return "age1testrecipient\n"
        return json.dumps({"encrypted": "values", "sops": {"age": []}})

    def test_generation_is_create_only_and_encrypted(self) -> None:
        output = self.private_root / "keycloak.sops.json"
        with mock.patch.object(module.contracts, "validate_contracts", return_value=self.contracts()):
            created = module.generate(
                approval=module.APPROVAL,
                repository_root=self.root,
                age_key=self.age_key,
                output=output,
                run_command=self.run_command,
            )
        self.assertEqual(created, output)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertIn('"sops"', output.read_text(encoding="utf-8"))
        with mock.patch.object(module.contracts, "validate_contracts", return_value=self.contracts()):
            with self.assertRaisesRegex(module.KeycloakInputError, "pass --rotate"):
                module.generate(
                    approval=module.APPROVAL,
                    repository_root=self.root,
                    age_key=self.age_key,
                    output=output,
                    run_command=self.run_command,
                )

    def test_wrong_approval_is_rejected(self) -> None:
        with self.assertRaisesRegex(module.KeycloakInputError, "approval must be"):
            module.generate(approval="wrong")


if __name__ == "__main__":
    unittest.main()
