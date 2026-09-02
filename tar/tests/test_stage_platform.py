"""Test platform chart staging with an in-memory opener."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tar/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "stage_platform", ROOT / "tar/scripts/stage_platform.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load platform stager")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class StagePlatformTests(unittest.TestCase):
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            self.close()

        def geturl(self) -> str:
            return "https://github.com/shell/chart.tgz"

    def test_stages_both_locked_charts_with_private_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = module.supply.validate_platform()
            content = {
                chart["name"]: f"{chart['name']}-chart".encode()
                for chart in lock["charts"].values()
            }
            for chart in lock["charts"].values():
                chart["sha256"] = hashlib.sha256(content[chart["name"]]).hexdigest()
                chart["max_bytes"] = len(content[chart["name"]]) + 1
            with mock.patch.object(module.supply, "validate_platform", return_value=lock):
                calls = iter(content.values())
                files = module.stage(
                    Path(directory),
                    opener=lambda *_args, **_kwargs: self.Response(next(calls)),
                )
            self.assertEqual(len(files), 2)
            for path in files:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_reuses_only_matching_existing_chart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = module.supply.validate_platform()
            chart = next(iter(lock["charts"].values()))
            content = b"existing-chart"
            chart["sha256"] = hashlib.sha256(content).hexdigest()
            chart["max_bytes"] = len(content)
            root = Path(directory) / "charts"
            root.mkdir()
            root.chmod(0o700)
            target = root / f"{chart['name']}-{chart['version']}.tgz"
            target.write_bytes(content)
            target.chmod(0o600)
            other = next(item for item in lock["charts"].values() if item is not chart)
            with mock.patch.object(
                module, "charts", return_value=[chart]
            ), mock.patch.object(module.supply, "validate_platform", return_value=lock):
                self.assertEqual(module.stage(Path(directory)), [target])
            self.assertEqual(other["name"], "longhorn" if chart["name"] == "metallb" else "metallb")

    def test_rejects_oversized_download_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = module.supply.validate_platform()
            chart = next(iter(lock["charts"].values()))
            chart["max_bytes"] = 3
            with mock.patch.object(module, "charts", return_value=[chart]):
                with self.assertRaisesRegex(module.PlatformStageError, "size ceiling"):
                    module.stage(
                        Path(directory),
                        opener=lambda *_args, **_kwargs: self.Response(b"four"),
                    )

    def test_rejects_redirect_to_another_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = module.supply.validate_platform()
            chart = next(iter(lock["charts"].values()))

            class Redirected(self.Response):
                def geturl(self) -> str:
                    return "https://evil.example/chart.tgz"

            with mock.patch.object(module, "charts", return_value=[chart]):
                with self.assertRaisesRegex(module.PlatformStageError, "redirect"):
                    module.stage(
                        Path(directory), opener=lambda *_args, **_kwargs: Redirected(b"x")
                    )

    def test_rejects_symlinked_local_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            linked = root / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(module.PlatformStageError, "symlink"):
                module.stage(linked)


if __name__ == "__main__":
    unittest.main()
