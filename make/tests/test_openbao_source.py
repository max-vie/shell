"""Test the source-only OpenBao GitOps boundary."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_openbao", ROOT / "make/scripts/validate_openbao.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load OpenBao validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class OpenBaoSourceTests(unittest.TestCase):
    def test_live_bootstrap_contract_remains_blocked(self) -> None:
        module.validate()
    def test_source_is_tls_raft_and_clusterip(self) -> None:
        values = module.validate()
        self.assertTrue(values["server"]["ha"]["raft"]["enabled"])
        self.assertEqual(values["server"]["ha"]["replicas"], 3)
        self.assertEqual(values["server"]["service"]["type"], "ClusterIP")

    def test_source_has_no_oidc_or_keycloak(self) -> None:
        source = (
            (ROOT / "make/gitops/values/openbao.yaml")
            .read_text(encoding="utf-8")
            .lower()
        )
        self.assertNotIn("keycloak", source)
        self.assertNotIn("oidc", source)


if __name__ == "__main__":
    unittest.main()
