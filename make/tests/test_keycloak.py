"""Test the source-only Keycloak workload contract."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "make/scripts"))
import validate_keycloak as module  # noqa: E402


class KeycloakSourceTests(unittest.TestCase):
    def test_source_contract_and_manifests_validate(self) -> None:
        contract = module.validate()
        self.assertEqual(contract["workload"]["service"]["type"], "ClusterIP")
        self.assertFalse(contract["workload"]["external_endpoint"])

    def test_realm_is_read_only_freeipa_federation_without_downstream_clients(self) -> None:
        source = (ROOT / "make/gitops/platform/keycloak/realm.yaml").read_text(
            encoding="utf-8"
        )
        document = next(
            item
            for item in module.read_yaml(ROOT / "make/gitops/platform/keycloak/realm.yaml")
            if item.get("kind") == "ConfigMap"
        )
        realm = json.loads(document["data"]["shell-realm.json"])
        provider = realm["components"]["org.keycloak.storage.UserStorageProvider"][0]
        self.assertEqual(provider["config"]["editMode"], ["READ_ONLY"])
        self.assertIn("freeipa-groups", source)
        self.assertNotIn("clients", realm)

    def test_source_does_not_expose_an_external_service(self) -> None:
        for path in (ROOT / "make/gitops/platform/keycloak").glob("*.yaml"):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("LoadBalancer", source)
            self.assertNotIn("NodePort", source)
            self.assertNotIn("\nkind: Ingress", source)
            self.assertNotIn(":latest", source)


if __name__ == "__main__":
    unittest.main()
