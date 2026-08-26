"""Test the cert-manager TAR supply lock and staging boundary."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load("validate_kubernetes_supply", SOURCE_ROOT / "tar/scripts/validate_kubernetes_supply.py")
stager = load("stage_kubernetes_supply", SOURCE_ROOT / "tar/scripts/stage_kubernetes_supply.py")


class TestKubernetesSupply(unittest.TestCase):
    def test_public_lock_validates(self) -> None:
        lock = validator.validate_public()
        self.assertEqual(set(lock["charts"]), {"cert-manager"})
        self.assertEqual(len(lock["images"]), 4)

    def test_unknown_or_changed_public_pins_are_rejected(self) -> None:
        lock_path = SOURCE_ROOT / "tar/manifests/kubernetes-ecosystem-supply.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        changed = copy.deepcopy(lock)
        changed["charts"]["cert-manager"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(validator.SupplyError, "chart pin changed"):
                validator.validate_public(path)

    def test_duplicate_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text('{"schema_version":"1.0","schema_version":"2"}', encoding="utf-8")
            with self.assertRaisesRegex(validator.SupplyError, "duplicate JSON key"):
                validator.read_json(path, "test lock")

    def test_stage_publishes_verified_bytes_atomically(self) -> None:
        content = b"cert-manager-chart"
        chart = validator.EXPECTED_CHART
        changed = copy.deepcopy(chart)
        changed["sha256"] = hashlib.sha256(content).hexdigest()
        lock_path = SOURCE_ROOT / "tar/manifests/kubernetes-ecosystem-supply.json"

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                self.close()

            def geturl(self) -> str:
                return chart["source"]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            modified = json.loads(lock_path.read_text(encoding="utf-8"))
            modified["charts"]["cert-manager"] = changed
            with patch.object(stager, "validate_public", return_value=modified):
                path = stager.stage(root, opener=lambda *_args, **_kwargs: Response(content))
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_stage_rejects_wrong_existing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            chart_path = root / "charts/cert-manager-v1.21.0.tgz"
            chart_path.parent.mkdir()
            chart_path.write_bytes(b"wrong")
            chart_path.chmod(0o600)
            with self.assertRaisesRegex(stager.StageError, "differs"):
                stager.stage(root, opener=Mock())

    def test_stage_rejects_symlinked_artifact_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            local = root / "local"
            local.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(stager.StageError, "symlink"):
                stager.stage(local, opener=Mock())


if __name__ == "__main__":
    unittest.main()
