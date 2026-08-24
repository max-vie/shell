"""Test the source-only Debian image workflow contract."""

from __future__ import annotations

import json
import os
import stat
import subprocess  # nosec B404
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast


INIT_ROOT = Path(__file__).parents[1]
IMAGE_ROOT = INIT_ROOT / "images"
PREPARE = IMAGE_ROOT / "scripts" / "prepare.sh"


class TestImageWorkflow(unittest.TestCase):
    def test_debian_lock_is_complete_and_pinned(self) -> None:
        value = cast(
            dict[str, Any],
            json.loads((IMAGE_ROOT / "images.lock.json").read_text(encoding="utf-8")),
        )
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(list(value["images"]), ["debian"])
        debian = value["images"]["debian"]
        self.assertEqual(debian["family"], "debian")
        self.assertEqual(debian["version"], "13")
        self.assertTrue(debian["source_url"].startswith("https://"))
        self.assertEqual(debian["checksum_algorithm"], "sha512")
        self.assertRegex(debian["checksum"], r"^[0-9a-f]{128}$")
        self.assertNotIn("/", debian["source_file"])
        self.assertNotIn("/", debian["output_file"])

    def test_image_scripts_are_executable(self) -> None:
        scripts = (
            PREPARE,
            IMAGE_ROOT / "scripts" / "validate.sh",
            IMAGE_ROOT / "files" / "prepare-guest.sh",
        )
        for script in scripts:
            with self.subTest(script=script.name):
                self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o755)

    def test_prepare_refuses_output_outside_private_checkout_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = os.environ.copy()
            environment["SHELL_IMAGE_ROOT"] = str(Path(temporary) / "outside")
            environment.pop("INIT_PUBLIC_KEY_FILE", None)
            completed = subprocess.run(  # nosec B603
                [str(PREPARE)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must stay under", completed.stderr)


if __name__ == "__main__":
    unittest.main()
