"""Test platform chart publication guards without delivery or Harbor access."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tar/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "publish_platform_charts", ROOT / "tar/scripts/publish_platform_charts.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load platform chart publisher")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PublishPlatformChartsTests(unittest.TestCase):
    def test_wrong_approval_stops_before_private_inputs(self) -> None:
        with mock.patch.object(module, "run") as run:
            with self.assertRaisesRegex(module.ChartPublicationError, "APPROVAL"):
                module.publish("wrong", [])
            run.assert_not_called()

    def test_chart_set_is_limited_to_bootstrap_dependencies(self) -> None:
        self.assertEqual(module.CHARTS, ("argo-cd-10.1.4.tgz", "openbao-0.28.6.tgz"))

    def test_publication_is_blocked_before_private_inputs(self) -> None:
        with self.assertRaisesRegex(module.ChartPublicationError, "blocked"):
            module.publish(module.APPROVAL, [])


if __name__ == "__main__":
    unittest.main()
