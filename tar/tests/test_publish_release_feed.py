"""Test release-feed publication guards without building or publishing."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tar/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "publish_release_feed", ROOT / "tar/scripts/publish_release_feed.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release-feed publisher")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PublishReleaseFeedTests(unittest.TestCase):
    def test_wrong_approval_fails_before_private_or_build_inputs(self) -> None:
        with mock.patch.object(module, "run") as run:
            with self.assertRaisesRegex(module.PublicationError, "APPROVAL"):
                module.publish("wrong", [])
            run.assert_not_called()

    def test_digest_shape_is_strict(self) -> None:
        self.assertIsNotNone(module.DIGEST.fullmatch("sha256:" + "a" * 64))
        self.assertIsNone(module.DIGEST.fullmatch("latest"))

    def test_publication_is_blocked_before_build_or_private_inputs(self) -> None:
        with self.assertRaisesRegex(module.PublicationError, "blocked"):
            module.publish(module.APPROVAL, [])


if __name__ == "__main__":
    unittest.main()
