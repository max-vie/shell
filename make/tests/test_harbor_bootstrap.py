"""Test Harbor source and secret construction without private values."""

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
    "register_harbor_robots", ROOT / "make/scripts/register_harbor_robots.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Harbor robot controller")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

DEPLOY_SPEC = importlib.util.spec_from_file_location(
    "deploy_harbor", ROOT / "make/scripts/deploy_harbor.py"
)
if DEPLOY_SPEC is None or DEPLOY_SPEC.loader is None:
    raise RuntimeError("cannot load Harbor deploy controller")
deploy_module = importlib.util.module_from_spec(DEPLOY_SPEC)
DEPLOY_SPEC.loader.exec_module(deploy_module)


class HarborBootstrapTests(unittest.TestCase):
    def test_live_apply_is_blocked_before_inventory(self) -> None:
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

    def test_harbor_deploy_is_blocked_before_inventory(self) -> None:
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

    def test_pull_secret_is_docker_config_and_scoped(self) -> None:
        document = json.loads(module.secret("pull", "robot", "secret"))
        self.assertEqual(document["type"], "kubernetes.io/dockerconfigjson")
        self.assertEqual(document["metadata"]["namespace"], "release-feed")
        self.assertIn(module.REGISTRY, document["stringData"][".dockerconfigjson"])

    def test_platform_pull_secret_can_be_rendered_per_namespace(self) -> None:
        document = json.loads(module.secret("pull", "robot", "secret", "argocd"))
        self.assertEqual(document["metadata"]["namespace"], "argocd")

    def test_harbor_source_is_full_profile(self) -> None:
        source = (ROOT / "tar/manifests/harbor-values.json").read_text(encoding="utf-8")
        self.assertIn('"IP": "10.77.0.221"', source)
        self.assertIn('"enabled": true', source)


if __name__ == "__main__":
    unittest.main()
