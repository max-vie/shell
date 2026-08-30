"""Test release-feed deployment guards without a cluster or image."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "make/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "deploy_release_feed", ROOT / "make/scripts/deploy_release_feed.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release-feed deployer")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ReleaseFeedDeployTests(unittest.TestCase):
    def test_live_apply_is_blocked_before_inventory(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(module.transport, "resolve_connection") as resolve,
            redirect_stderr(stderr),
        ):
            result = module.main(["apply", "--inventory", "private-inventory.yml"])
        self.assertEqual(result, 2)
        self.assertIn("apply is blocked", stderr.getvalue())
        resolve.assert_not_called()

    def test_source_check_allows_only_the_unpromoted_placeholder(self) -> None:
        module.validate_source()
        source = (ROOT / "make/apps/release-feed/k8s/base/statefulset.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn(module.IMAGE_PLACEHOLDER, source)

    def test_rendered_manifests_replace_only_the_image_digest(self) -> None:
        digest = "sha256:" + "b" * 64
        temporary, directory = module.rendered_manifests(digest)
        try:
            statefulset = (directory / "statefulset.yaml").read_text(encoding="utf-8")
            self.assertIn(digest, statefulset)
            self.assertNotIn(module.IMAGE_PLACEHOLDER, statefulset)
            self.assertNotIn("value: unpromoted", statefulset)
            self.assertEqual(
                (directory / "statefulset.yaml").stat().st_mode & 0o777, 0o600
            )
        finally:
            temporary.cleanup()

    def test_invalid_digest_is_rejected(self) -> None:
        with self.assertRaisesRegex(module.ReleaseFeedDeployError, "invalid"):
            module.rendered_manifests("latest")

    def test_contract_rejects_duplicate_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text(
                '{"contract_id":"one","contract_id":"two"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(module.ReleaseFeedDeployError, "duplicate"):
                module.read_json(duplicate)

            contract = module.read_json(module.CONTRACT)
            contract["future"] = True
            changed = Path(directory) / "changed.json"
            changed.write_text(json.dumps(contract), encoding="utf-8")
            with mock.patch.object(module, "CONTRACT", changed):
                with self.assertRaisesRegex(
                    module.ReleaseFeedDeployError, "shape changed"
                ):
                    module.validate_source()


if __name__ == "__main__":
    unittest.main()
