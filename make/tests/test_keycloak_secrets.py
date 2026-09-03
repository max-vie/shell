"""Test Keycloak secret manifests without private values or cluster access."""

from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "make/scripts/apply_keycloak_secrets.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("apply_keycloak_secrets", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Keycloak secret controller")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class KeycloakSecretTests(unittest.TestCase):
    @staticmethod
    def document() -> dict[str, str]:
        return {
            "database_username": "keycloak",
            "database_password": "d" * 48,
            "bootstrap_admin_username": "sso-bootstrap",
            "bootstrap_admin_password": "b" * 48,
            "ldap_bind_password": "l" * 48,
        }

    def test_secret_documents_have_only_declared_resources(self) -> None:
        resources = module.documents(self.document(), "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n")
        self.assertEqual(
            [(item["kind"], item["metadata"]["name"]) for item in resources],
            [
                ("Namespace", "shell-identity"),
                ("ConfigMap", "shell-freeipa-ca"),
                ("Secret", "keycloak-database"),
                ("Secret", "keycloak-bootstrap"),
                ("Secret", "keycloak-runtime"),
            ],
        )
        self.assertEqual(resources[-1]["stringData"], {"ldap_bind_password": "l" * 48})

    def test_invalid_private_input_is_rejected(self) -> None:
        with mock.patch.object(
            module.sops_helpers, "decrypt_json", return_value={"unused": "value"}
        ):
            with self.assertRaisesRegex(
                module.KeycloakSecretError, "input keys changed"
            ):
                module.protected_input({"unused": "value"}, Path("unused"))

    def test_wrong_apply_approval_stops_before_decryption(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(module.validate_keycloak, "validate"),
            mock.patch.object(module, "protected_input") as decrypt,
            redirect_stderr(stderr),
        ):
            result = module.main(["apply", "--approval", "wrong"])
        self.assertEqual(result, 2)
        decrypt.assert_not_called()
        self.assertIn("approval must be", stderr.getvalue())

    def test_check_is_public_and_does_not_decrypt(self) -> None:
        with mock.patch.object(module, "protected_input") as decrypt:
            self.assertEqual(module.main(["check"]), 0)
        decrypt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
