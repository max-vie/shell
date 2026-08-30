"""Test OpenBao bootstrap payloads without calling a server."""

from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "make/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "bootstrap_openbao", ROOT / "make/scripts/bootstrap_openbao.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load OpenBao bootstrap")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class OpenBaoBootstrapTests(unittest.TestCase):
    def test_live_bootstrap_is_blocked_before_private_inputs(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(module, "bootstrap") as bootstrap,
            mock.patch.object(module, "OpenBaoClient") as client,
            redirect_stderr(stderr),
        ):
            result = module.main(
                [
                    "--approval",
                    module.APPROVAL,
                    "--url",
                    "https://openbao.invalid",
                    "--ca-file",
                    str(ROOT / "sudo/pki/shell-offline-root.crt.pem"),
                    "--kubernetes-host",
                    "https://kubernetes.invalid",
                    "--reviewer-jwt-file",
                    "reviewer.jwt",
                    "--kubernetes-ca-file",
                    "k3s-ca.crt",
                ]
            )
        self.assertEqual(result, 2)
        self.assertIn("bootstrap is blocked", stderr.getvalue())
        bootstrap.assert_not_called()
        client.assert_not_called()

    def test_role_is_bound_to_release_feed(self) -> None:
        self.assertEqual(
            module.role()["bound_service_account_namespaces"], ["release-feed"]
        )
        self.assertEqual(module.role()["policies"], ["release-feed"])
        self.assertEqual(module.role()["audience"], "openbao")

    def test_policy_is_read_only(self) -> None:
        policy = module.policy()
        self.assertIn('capabilities = ["read"]', policy)
        self.assertNotIn("create", policy)
        self.assertNotIn("update", policy)

    def test_client_rejects_http(self) -> None:
        with self.assertRaisesRegex(module.OpenBaoBootstrapError, "HTTPS"):
            module.OpenBaoClient(
                "http://openbao", ROOT / "sudo/pki/shell-offline-root.crt.pem"
            )


if __name__ == "__main__":
    unittest.main()
