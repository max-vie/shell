"""Test platform image publication guards without Harbor access."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tar/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "publish_platform_images", ROOT / "tar/scripts/publish_platform_images.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load platform image publisher")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PublishPlatformImagesTests(unittest.TestCase):
    def test_publication_is_blocked_before_private_inputs(self) -> None:
        with self.assertRaisesRegex(module.ImagePublicationError, "blocked"):
            module.publish(module.APPROVAL, [])
    def test_wrong_approval_stops_before_private_inputs(self) -> None:
        with self.assertRaisesRegex(module.ImagePublicationError, "APPROVAL"):
            module.publish("wrong", [])

    def test_source_and_destination_are_immutable(self) -> None:
        self.assertIn("@sha256:", module.SOURCE)
        self.assertEqual(
            module.EXPECTED,
            "sha256:"
            + "5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0",
        )


if __name__ == "__main__":
    unittest.main()
