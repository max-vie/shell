"""Test the source-only Skopeo transfer boundary."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tar/scripts/publish_kubernetes_images.py"
SPEC = importlib.util.spec_from_file_location("publish_kubernetes_images", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Skopeo transfer script")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class SkopeoTransferTests(unittest.TestCase):
    def test_locked_request_uses_the_expected_harbor_destination(self) -> None:
        lock = module.supply.validate_public()
        source = "docker.io/grafana/k6:2.1.0"
        destination = module.expected_destination(source)
        source_ref, digest = module.validate_request(source, destination, lock)
        self.assertEqual(
            source_ref,
            "docker.io/grafana/k6:2.1.0@"
            "sha256:65c920dc067d5e2e00befbf982af6ad6ad0117034e8b1c65817c7975c52d4669",
        )
        self.assertEqual(digest, lock["images"][source]["digest"])

    def test_destination_and_unlocked_sources_are_rejected(self) -> None:
        with self.assertRaisesRegex(module.ImageTransferError, "not in the TAR lock"):
            module.validate_request(
                "docker.io/grafana/k6:latest",
                "registry.shell.internal/shell/system/k6:latest-amd64",
            )
        with self.assertRaisesRegex(module.ImageTransferError, "destination"):
            module.validate_request(
                "docker.io/grafana/k6:2.1.0",
                "registry.shell.internal/shell/system/other:2.1.0-amd64",
            )

    def test_remote_command_preserves_digest_and_checks_existing_content(self) -> None:
        command = module.remote_command(
            "docker.io/grafana/k6:2.1.0@sha256:" + "a" * 64,
            "registry.shell.internal/shell/system/k6:2.1.0-amd64",
            "sha256:" + "a" * 64,
        )
        self.assertIn("skopeo copy", command)
        self.assertIn("--preserve-digests", command)
        self.assertIn("--authfile", command)
        self.assertIn("DEST_DIGEST", command)
        self.assertNotIn("--password", command)
        self.assertNotIn("--username", command)

    def test_preview_does_not_read_private_inputs(self) -> None:
        self.assertEqual(module.main(["preview"]), 0)


if __name__ == "__main__":
    unittest.main()
