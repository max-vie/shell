"""Test Argo CD repository Secret construction without private credentials."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "make/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "register_argocd_repository", ROOT / "make/scripts/register_argocd_repository.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Argo repository controller")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ArgoRepositoryTests(unittest.TestCase):
    def test_public_source_contracts_validate(self) -> None:
        module.validate_source()

    def test_live_registration_is_blocked_before_inventory(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(module, "apply") as apply, redirect_stderr(stderr):
            result = module.main(
                [
                    "--approval",
                    module.APPROVAL,
                    "--inventory",
                    "private-inventory.yml",
                ]
            )
        self.assertEqual(result, 2)
        self.assertIn("registration is blocked", stderr.getvalue())
        apply.assert_not_called()

    def test_repository_secret_is_read_only_git_secret(self) -> None:
        document = json.loads(
            module.manifest(
                {
                    "url": module.REPOSITORY_URL,
                    "username": "bot",
                    "api_token": "private",
                }
            )
        )
        self.assertEqual(document["metadata"]["namespace"], "argocd")
        self.assertEqual(
            document["metadata"]["labels"]["argocd.argoproj.io/secret-type"],
            "repository",
        )
        self.assertEqual(
            document["stringData"]["insecureSkipServerVerification"], "false"
        )

    def test_harbor_chart_repository_is_oci_enabled(self) -> None:
        document = json.loads(
            module.harbor_manifest(
                {
                    "puller": {
                        "username": "robot$puller",
                        "password": "private",
                    }
                }
            )
        )
        self.assertEqual(document["stringData"]["type"], "helm")
        self.assertEqual(document["stringData"]["enableOCI"], "true")
        self.assertEqual(document["metadata"]["namespace"], "argocd")


if __name__ == "__main__":
    unittest.main()
