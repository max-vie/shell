"""Test TAR's WATCH metrics and Grafana supply lock."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate_watch.py"
SPEC = importlib.util.spec_from_file_location("validate_watch", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load WATCH supply validator: {SCRIPT}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TestWatchSupply(unittest.TestCase):
    def test_current_supply_validates(self) -> None:
        lock = validator.validate_public()
        self.assertEqual("watch-supply", lock["contract_id"])
        self.assertEqual("2.0.0", lock["contract_version"])
        self.assertEqual("source-reference-only", lock["proof_status"])
        self.assertEqual("make", lock["execution_owner"])
        self.assertEqual("88.5.2", lock["charts"]["kube-prometheus-stack"]["version"])
        self.assertEqual(
            "sha256:3fd54ae1214669f8355f065ec9f6445d5279a3d77095ab048ca045685272429b",
            lock["runtime_image_digests"]["docker.io/grafana/grafana:13.2.0"],
        )

    def test_supply_has_unique_digest_pinned_images(self) -> None:
        lock = validator.validate_public()
        images = lock["required_runtime_images"]
        self.assertEqual(len(images), len(set(images)))
        self.assertEqual(set(images), set(lock["runtime_image_digests"]))
        for image, digest in lock["runtime_image_digests"].items():
            self.assertNotIn(":latest", image)
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            set(images) - {"ghcr.io/jkroepke/kube-webhook-certgen:1.8.5"},
            set(lock["persistent_runtime_images"]),
        )

    def test_supply_rejects_chart_checksum_drift(self) -> None:
        source = json.loads(
            (ROOT / "manifests/watch-supply.json").read_text(encoding="utf-8")
        )
        altered = copy.deepcopy(source)
        altered["charts"]["kube-prometheus-stack"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "watch-supply.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(validator.WatchSupplyError, "checksum changed"):
                validator.validate_public(path)

    def test_supply_rejects_runtime_digest_drift(self) -> None:
        source = json.loads(
            (ROOT / "manifests/watch-supply.json").read_text(encoding="utf-8")
        )
        altered = copy.deepcopy(source)
        altered["runtime_image_digests"][
            "quay.io/prometheus/prometheus:v3.14.0-distroless"
        ] = "sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "watch-supply.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(validator.WatchSupplyError, "digest changed"):
                validator.validate_public(path)

    def test_supply_rejects_chart_source_drift(self) -> None:
        source = json.loads(
            (ROOT / "manifests/watch-supply.json").read_text(encoding="utf-8")
        )
        altered = copy.deepcopy(source)
        altered["charts"]["kube-prometheus-stack"]["source"] = (
            "https://example.invalid/chart.tgz"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "watch-supply.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(validator.WatchSupplyError, "source changed"):
                validator.validate_public(path)


if __name__ == "__main__":
    unittest.main()
