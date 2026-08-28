"""Test TAR's WATCH logs supply lock."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import stat
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import Self
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate_watch_logs.py"
SPEC = importlib.util.spec_from_file_location("validate_watch_logs", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load WATCH logs supply validator: {SCRIPT}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

STAGER_SCRIPT = ROOT / "scripts/stage_watch_logs.py"
STAGER_SPEC = importlib.util.spec_from_file_location("stage_watch_logs", STAGER_SCRIPT)
if STAGER_SPEC is None or STAGER_SPEC.loader is None:
    raise RuntimeError(f"cannot load WATCH logs stager: {STAGER_SCRIPT}")
stager = importlib.util.module_from_spec(STAGER_SPEC)
STAGER_SPEC.loader.exec_module(stager)


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def geturl(self) -> str:
        return self.url


class TestWatchLogsSupply(unittest.TestCase):
    def test_current_supply_validates(self) -> None:
        lock = validator.validate_public()
        self.assertEqual("watch-logs-supply", lock["contract_id"])
        self.assertEqual("make", lock["execution_owner"])
        self.assertEqual(
            {"loki", "alloy"},
            set(lock["charts"]),
        )

    def test_supply_has_digest_pinned_runtime_images(self) -> None:
        lock = validator.validate_public()
        self.assertEqual(
            lock["required_runtime_images"],
            lock["persistent_runtime_images"],
        )
        for image, digest in lock["runtime_image_digests"].items():
            self.assertNotIn(":latest", image)
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")

    def test_supply_rejects_chart_source_and_digest_drift(self) -> None:
        source = json.loads(
            (ROOT / "manifests/watch-logs-supply.json").read_text(encoding="utf-8")
        )
        altered = copy.deepcopy(source)
        altered["charts"]["alloy"]["source"] = "https://example.invalid/logs.tgz"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "watch-logs-supply.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(
                validator.WatchLogsSupplyError, "chart pins changed"
            ):
                validator.validate_public(path)

            altered = copy.deepcopy(source)
            altered["runtime_image_digests"]["docker.io/grafana/loki:3.7.6"] = (
                "sha256:" + "0" * 64
            )
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(
                validator.WatchLogsSupplyError, "image digests changed"
            ):
                validator.validate_public(path)

    def test_supply_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "watch-logs-supply.json"
            path.write_text(
                '{"schema_version":"1.0","schema_version":"2.0"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                validator.WatchLogsSupplyError, "duplicate JSON key"
            ):
                validator.read_lock(path)

    def test_stage_publishes_each_verified_chart_atomically(self) -> None:
        contents = {"loki": b"loki chart", "alloy": b"alloy chart"}
        lock = copy.deepcopy(validator.validate_public())
        for name, content in contents.items():
            lock["charts"][name]["sha256"] = hashlib.sha256(content).hexdigest()
            lock["charts"][name]["size_bytes"] = len(content)

        def opener(request: urllib.request.Request, **_kwargs: object) -> Response:
            name = "loki" if "loki-18.11.2" in request.full_url else "alloy"
            return Response(
                contents[name],
                f"https://release-assets.githubusercontent.com/{name}.tgz",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "watch"
            with mock.patch.object(stager, "validate_public", return_value=lock):
                paths = stager.stage(root, opener=opener)
            self.assertEqual(
                ["loki-18.11.2.tgz", "alloy-1.11.1.tgz"],
                [path.name for path in paths],
            )
            self.assertEqual(
                [contents["loki"], contents["alloy"]],
                [path.read_bytes() for path in paths],
            )
            self.assertTrue(
                all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)
            )
            self.assertEqual(0o700, stat.S_IMODE(root.stat().st_mode))

    def test_stage_rejects_an_oversized_download_without_publishing(self) -> None:
        lock = copy.deepcopy(validator.validate_public())
        lock["charts"]["loki"]["size_bytes"] = 4
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "watch"
            with (
                mock.patch.object(stager, "validate_public", return_value=lock),
                self.assertRaisesRegex(
                    stager.WatchLogsStageError,
                    "exceeds the locked size",
                ),
            ):
                stager.stage(
                    root,
                    opener=lambda *_args, **_kwargs: Response(
                        b"oversized",
                        "https://release-assets.githubusercontent.com/loki.tgz",
                    ),
                )
            self.assertFalse((root / "charts/loki-18.11.2.tgz").exists())
            self.assertEqual([], list((root / "charts").glob(".*.tgz.*")))

    def test_stage_rejects_wrong_existing_chart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "watch"
            chart = root / "charts/loki-18.11.2.tgz"
            chart.parent.mkdir(parents=True)
            chart.write_bytes(b"wrong")
            chart.chmod(0o600)
            with self.assertRaisesRegex(
                stager.WatchLogsStageError,
                "existing loki chart size differs",
            ):
                stager.stage(root, opener=mock.Mock())


if __name__ == "__main__":
    unittest.main()
