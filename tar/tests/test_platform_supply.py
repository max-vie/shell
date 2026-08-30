"""Test the source-only platform and Harbor supply locks."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_platform_supply", ROOT / "tar/scripts/validate_platform_supply.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load platform supply validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PlatformSupplyTests(unittest.TestCase):
    def test_platform_and_service_locks_validate(self) -> None:
        platform_lock = module.validate_platform()
        service_lock = module.validate_services()
        harbor = module.validate_harbor()
        self.assertEqual(platform_lock["execution_owner"], "make")
        self.assertEqual(
            platform_lock["service_addresses"]["harbor"], "10.77.0.221"
        )
        self.assertEqual(service_lock["charts"]["openbao"]["version"], "0.28.6")
        self.assertTrue(harbor["profiles"]["full"]["trivy"])

    def test_harbor_does_not_reuse_proxmox_host_address(self) -> None:
        lock_path = ROOT / "tar/manifests/harbor-supply.json"
        changed = copy.deepcopy(json.loads(lock_path.read_text(encoding="utf-8")))
        changed["endpoint"]["address"] = "10.77.0.220"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "harbor.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(module.PlatformSupplyError, "Harbor endpoint"):
                module.validate_harbor(path)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(
                '{"schema_version":"1.0","schema_version":"2"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                module.PlatformSupplyError, "duplicate JSON key"
            ):
                module.read_json(path, "test lock")

    def test_harbor_image_lock_matches_every_values_reference(self) -> None:
        lock = module.validate_harbor()
        values = module.read_json(module.HARBOR_VALUES, "Harbor values")
        references = {
            f"{repository}:{tag.partition('@')[0]}"
            for repository, tag in module.image_references(values)
        }
        self.assertEqual(set(lock["runtime_image_digests"]), references)

    def test_harbor_rejects_one_changed_digest(self) -> None:
        values = json.loads(module.HARBOR_VALUES.read_text(encoding="utf-8"))
        values["nginx"]["image"]["tag"] = "v2.15.2@sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "values.json"
            path.write_text(json.dumps(values), encoding="utf-8")
            with mock.patch.object(module, "HARBOR_VALUES", path):
                with self.assertRaisesRegex(module.PlatformSupplyError, "digest changed"):
                    module.validate_harbor()


if __name__ == "__main__":
    unittest.main()
