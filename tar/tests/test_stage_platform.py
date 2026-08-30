"""Test platform chart staging with an in-memory opener."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


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
    def test_staging_is_blocked_before_filesystem_or_network_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(module.PlatformStageError, "blocked"):
                module.stage(Path(directory))


if __name__ == "__main__":
    unittest.main()
