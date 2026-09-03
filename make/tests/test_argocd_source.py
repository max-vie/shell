"""Test the source-only Argo CD bootstrap boundary."""

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
    "validate_argocd", ROOT / "make/scripts/validate_argocd.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Argo validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

DEPLOY_SPEC = importlib.util.spec_from_file_location(
    "deploy_argocd", ROOT / "make/scripts/deploy_argocd.py"
)
if DEPLOY_SPEC is None or DEPLOY_SPEC.loader is None:
    raise RuntimeError("cannot load Argo deploy controller")
deploy_module = importlib.util.module_from_spec(DEPLOY_SPEC)
DEPLOY_SPEC.loader.exec_module(deploy_module)


class ArgoSourceTests(unittest.TestCase):
    def test_live_apply_is_blocked_before_inventory(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(deploy_module.transport, "resolve_connection") as resolve,
            redirect_stderr(stderr),
        ):
            result = deploy_module.main(
                ["apply", "--inventory", "private-inventory.yml"]
            )
        self.assertEqual(result, 2)
        self.assertIn("apply is blocked", stderr.getvalue())
        resolve.assert_not_called()

    def test_source_is_clusterip_and_allowlisted(self) -> None:
        module.validate()
        source = (ROOT / "make/gitops/bootstrap/argocd/values.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("type: ClusterIP", source)
        self.assertNotIn("LoadBalancer", source)

    def test_release_feed_has_one_make_owner(self) -> None:
        source = (
            ROOT / "make/gitops/bootstrap/argocd/root-application.yaml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("release-feed", source)

    def test_keycloak_namespace_is_an_allowed_downstream_destination(self) -> None:
        project = module.yaml.safe_load(
            (ROOT / "make/gitops/bootstrap/argocd/project.yaml").read_text(
                encoding="utf-8"
            )
        )
        namespaces = {
            item["namespace"] for item in project["spec"]["destinations"]
        }
        self.assertIn("shell-identity", namespaces)
        self.assertIn("kyverno", namespaces)
        self.assertIn("shell-trust", namespaces)
        self.assertIn("monitoring", namespaces)


if __name__ == "__main__":
    unittest.main()
