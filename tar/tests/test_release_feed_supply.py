"""Test release-feed artifact guards without building or publishing."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_release_feed", ROOT / "tar/scripts/validate_release_feed.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release-feed validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ReleaseFeedSupplyTests(unittest.TestCase):
    def test_contract_stays_unpromoted(self) -> None:
        lock = module.validate()
        self.assertIsNone(lock["image_digest"])
        self.assertEqual(lock["source_state"], "unpromoted")

    def test_promoted_digest_is_rejected_before_final_run(self) -> None:
        lock = copy.deepcopy(
            json.loads(
                (ROOT / "tar/manifests/release-feed-supply.json").read_text(
                    encoding="utf-8"
                )
            )
        )
        lock["image_digest"] = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release-feed.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(
                module.ReleaseFeedSupplyError, "digest must remain unpromoted"
            ):
                module.validate(path)


if __name__ == "__main__":
    unittest.main()
