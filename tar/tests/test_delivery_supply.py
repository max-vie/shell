"""Test the public TAR delivery image supply contract."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SOURCE_ROOT / "tar/scripts/validate_delivery_supply.py"
SPEC = importlib.util.spec_from_file_location("validate_delivery_supply", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load delivery supply validator: {SCRIPT}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TestDeliverySupply(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.lock_path = Path(self.temporary.name) / "delivery-supply.json"
        self.lock = json.loads(
            (SOURCE_ROOT / "tar/manifests/delivery-supply.json").read_text(
                encoding="utf-8"
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, value: dict[str, Any]) -> None:
        self.lock_path.write_text(json.dumps(value), encoding="utf-8")

    def test_current_lock_matches_reviewed_pins(self) -> None:
        lock = validator.validate_lock(SOURCE_ROOT / "tar/manifests/delivery-supply.json")
        self.assertEqual(lock["images"], validator.EXPECTED_IMAGES)
        self.assertEqual(
            lock["provenance"]["registry_verification"]["status"], "verified"
        )
        self.assertEqual(lock["images"]["node"]["tag"], "24-bookworm")
        self.assertEqual(lock["required_images"], list(validator.EXPECTED_IMAGES))

    def test_rejects_shape_platform_digest_and_required_image_drift(self) -> None:
        cases: list[tuple[str, dict[str, Any], str]] = []

        unknown = copy.deepcopy(self.lock)
        unknown["future"] = True
        cases.append(("unknown field", unknown, "shape changed"))

        platform = copy.deepcopy(self.lock)
        platform["runtime_image_platform"] = "linux/arm64"
        cases.append(("platform", platform, "platform changed"))

        digest = copy.deepcopy(self.lock)
        digest["images"]["forgejo"]["digest"] = "sha256:not-a-digest"
        cases.append(("digest", digest, "digest is invalid"))

        repository = copy.deepcopy(self.lock)
        repository["images"]["forgejo"]["repository"] = "https://example.invalid"
        cases.append(("repository", repository, "repository is invalid"))

        tag = copy.deepcopy(self.lock)
        tag["images"]["forgejo"]["tag"] = ""
        cases.append(("tag", tag, "tag is invalid"))

        valid_digest_drift = copy.deepcopy(self.lock)
        valid_digest_drift["images"]["forgejo"]["digest"] = "sha256:" + "0" * 64
        cases.append(("pin", valid_digest_drift, "image pins changed"))

        required = copy.deepcopy(self.lock)
        required["required_images"] = ["forgejo"]
        cases.append(("required image", required, "required image set changed"))

        for label, value, message in cases:
            with self.subTest(case=label):
                self.write(value)
                with self.assertRaisesRegex(validator.DeliverySupplyError, message):
                    validator.validate_lock(self.lock_path)

    def test_rejects_malformed_duplicate_and_symlinked_locks(self) -> None:
        with self.assertRaisesRegex(validator.DeliverySupplyError, "missing regular"):
            validator.validate_lock(self.lock_path)

        self.lock_path.write_bytes(b"{")
        with self.assertRaisesRegex(validator.DeliverySupplyError, "invalid JSON"):
            validator.validate_lock(self.lock_path)

        self.lock_path.write_text(
            '{"schema_version":"1.0","schema_version":"1.0"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(validator.DeliverySupplyError, "duplicate JSON"):
            validator.validate_lock(self.lock_path)

        target = Path(self.temporary.name) / "target.json"
        target.write_text(json.dumps(self.lock), encoding="utf-8")
        self.lock_path.unlink()
        self.lock_path.symlink_to(target)
        with self.assertRaisesRegex(validator.DeliverySupplyError, "missing regular"):
            validator.validate_lock(self.lock_path)

    def test_validation_reads_only_public_lock(self) -> None:
        lock = validator.validate_lock(SOURCE_ROOT / "tar/manifests/delivery-supply.json")
        self.assertEqual(lock["proof_status"], "source-reference-only")
        self.assertFalse((Path(self.temporary.name) / ".local").exists())

    def test_main_reports_controlled_errors(self) -> None:
        self.lock_path.write_bytes(b"{")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = validator.main(self.lock_path)
        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("delivery supply validation failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
