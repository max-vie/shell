"""Test the Kubernetes and admission TAR supply boundary."""

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


validator = load(
    "validate_kubernetes_supply", SOURCE_ROOT / "tar/scripts/validate_kubernetes_supply.py"
)
stager = load(
    "stage_kubernetes_supply", SOURCE_ROOT / "tar/scripts/stage_kubernetes_supply.py"
)


class TestKubernetesSupply(unittest.TestCase):
    def test_public_lock_validates(self) -> None:
        lock = validator.validate_public()
        self.assertEqual(
            set(lock["charts"]),
            {"cert-manager", "kyverno", "velero", "tempo", "opentelemetry-collector"},
        )
        self.assertEqual(len(lock["images"]), 18)
        self.assertEqual(lock["tools"]["cosign"]["version"], "2.6.4")
        self.assertEqual(lock["tools"]["skopeo"]["version"], "1.22.2")

    def test_unknown_or_changed_public_pins_are_rejected(self) -> None:
        lock_path = SOURCE_ROOT / "tar/manifests/kubernetes-ecosystem-supply.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        changed = copy.deepcopy(lock)
        changed["charts"]["cert-manager"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(validator.SupplyError, "chart pins changed"):
                validator.validate_public(path)

    def test_duplicate_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text('{"schema_version":"1.0","schema_version":"2"}', encoding="utf-8")
            with self.assertRaisesRegex(validator.SupplyError, "duplicate JSON key"):
                validator.read_json(path, "test lock")

    def test_stage_publishes_all_verified_bytes_atomically(self) -> None:
        lock_path = SOURCE_ROOT / "tar/manifests/kubernetes-ecosystem-supply.json"
        modified = json.loads(lock_path.read_text(encoding="utf-8"))
        contents = {
            "cert-manager": b"cert-manager-chart",
            "kyverno": b"kyverno-chart",
            "velero": b"velero-chart",
            "tempo": b"tempo-chart",
            "opentelemetry-collector": b"otel-chart",
            "cosign": b"cosign-tool",
        }
        for name, content in contents.items():
            target = (
                modified["charts"][name]
                if name in modified["charts"]
                else modified["tools"][name]
            )
            checksum_key = "sha256" if name in modified["charts"] else "source_sha256"
            target["size"] = len(content)
            target[checksum_key] = hashlib.sha256(content).hexdigest()
            if name in modified["charts"]:
                target["max_bytes"] = 1024

        class Response(io.BytesIO):
            def __init__(self, content: bytes, source: str):
                super().__init__(content)
                self.source = source

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                self.close()

            def geturl(self) -> str:
                return self.source

        def opener(request: object, **_: object) -> Response:
            source = getattr(request, "full_url")
            if source.endswith("cosign-linux-amd64"):
                name = "cosign"
            elif "kyverno-3.8.2" in source:
                name = "kyverno"
            elif "velero-12.1.0" in source:
                name = "velero"
            elif "tempo-1.24.4" in source:
                name = "tempo"
            elif "opentelemetry-collector-0.165.0" in source:
                name = "opentelemetry-collector"
            else:
                name = "cert-manager"
            return Response(contents[name], source)

        with patch.object(stager, "validate_public", return_value=modified):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = stager.stage(root, opener=opener)
                self.assertEqual(len(paths), 6)
                self.assertEqual(
                    (root / "charts/cert-manager-v1.21.0.tgz").read_bytes(),
                    contents["cert-manager"],
                )
                self.assertEqual(
                    (root / "charts/kyverno-3.8.2.tgz").read_bytes(),
                    contents["kyverno"],
                )
                self.assertEqual(
                    (root / "charts/velero-12.1.0.tgz").read_bytes(),
                    contents["velero"],
                )
                self.assertEqual(
                    (root / "charts/tempo-1.24.4.tgz").read_bytes(),
                    contents["tempo"],
                )
                self.assertEqual(
                    (root / "charts/opentelemetry-collector-0.165.0.tgz").read_bytes(),
                    contents["opentelemetry-collector"],
                )
                cosign = root / "tools/cosign"
                self.assertEqual(cosign.read_bytes(), contents["cosign"])
                self.assertEqual(stat.S_IMODE(cosign.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_stage_rejects_wrong_existing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            chart_path = root / "charts/cert-manager-v1.21.0.tgz"
            chart_path.parent.mkdir()
            chart_path.write_bytes(b"wrong")
            chart_path.chmod(0o600)
            with self.assertRaisesRegex(stager.StageError, "size changed"):
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
