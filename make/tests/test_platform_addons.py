"""Test the MAKE platform add-on boundary without a cluster."""

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
    "deploy_platform_addons", ROOT / "make/scripts/deploy_platform_addons.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load platform add-on deployer")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PlatformAddonsTests(unittest.TestCase):
    def test_source_contract_and_values(self) -> None:
        lock = module.validate_source()
        self.assertEqual(
            lock["service_routing"]["services"]["harbor"]["node_port"], 30443
        )
        self.assertEqual(
            module.values(lock, "metallb")["speaker"]["frr"]["enabled"], False
        )
        self.assertEqual(
            module.values(lock, "longhorn")["defaultSettings"]["defaultDataPath"],
            "/var/lib/longhorn",
        )

    def test_apply_requires_approval_before_inventory(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(module.transport, "resolve_connection") as resolve,
            redirect_stderr(stderr),
        ):
            result = module.main(["apply", "--inventory", "private-inventory.yml"])
        self.assertEqual(result, 2)
        self.assertIn("approval", stderr.getvalue())
        resolve.assert_not_called()

    def test_rendered_output_requires_locked_digests(self) -> None:
        lock = module.validate_source()
        with self.assertRaisesRegex(module.PlatformAddonsError, "missing"):
            module.validate_rendered("image: quay.io/example:latest\n", lock, "metallb")

    def test_service_consumers_do_not_use_metal_lb_addresses(self) -> None:
        service = (ROOT / "make/apps/release-feed/k8s/base/service.yaml").read_text(
            encoding="utf-8"
        )
        harbor = (ROOT / "tar/manifests/harbor-values.json").read_text(
            encoding="utf-8"
        )
        self.assertIn("type: NodePort", service)
        self.assertNotIn("loadBalancerIP:", service)
        self.assertIn('"type": "nodePort"', harbor)
        self.assertNotIn('"IP": "10.77.0.221"', harbor)


if __name__ == "__main__":
    unittest.main()
