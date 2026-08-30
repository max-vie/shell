"""Test release-feed input generation without private values or SOPS."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sudo/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "generate_release_feed_inputs",
    ROOT / "sudo/scripts/generate_release_feed_inputs.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release-feed input generator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ReleaseFeedInputGenerationTests(unittest.TestCase):
    def private_root(self, temporary: str) -> tuple[Path, Path]:
        root = Path(temporary)
        root.chmod(0o700)
        directory = root / ".local/sudo/release-feed"
        directory.mkdir(parents=True, mode=0o700)
        for parent in (root / ".local", root / ".local/sudo", directory):
            parent.chmod(0o700)
        key = directory / "age-key.txt"
        key.write_text("AGE-SECRET-KEY-test\n", encoding="utf-8")
        key.chmod(0o600)
        return root, key

    @staticmethod
    def stage_fixture(_payload: object, output: Path, _age_key: Path) -> Path:
        staged = output.with_name(f".{output.name}.staged")
        staged.write_text("encrypted\n", encoding="utf-8")
        staged.chmod(0o600)
        return staged

    def test_check_only_needs_no_private_key(self) -> None:
        with (
            mock.patch.object(module.contracts, "validate_release_feed"),
            mock.patch.object(module.contracts, "validate_openbao"),
        ):
            self.assertEqual(0, module.main(["--check-only", "--approval", "source-only"]))

    def test_age_key_path_is_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, key = self.private_root(temporary)
            other = key.with_name("other-key.txt")
            other.write_text("AGE-SECRET-KEY-other\n", encoding="utf-8")
            other.chmod(0o600)
            with (
                mock.patch.object(module, "ROOT", root),
                mock.patch.object(module, "AGE_KEY", key),
            ):
                module.private_file(key, "SOPS age key", expected=key)
                with self.assertRaisesRegex(module.InputGenerationError, "path changed"):
                    module.private_file(other, "SOPS age key", expected=key)

    def test_pair_publication_rolls_back_on_second_link_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, key = self.private_root(temporary)
            directory = key.parent
            with (
                mock.patch.object(module, "ROOT", root),
                mock.patch.object(module, "AGE_KEY", key),
                mock.patch.object(module.contracts, "validate_release_feed"),
                mock.patch.object(
                    module, "stage_encrypted", side_effect=self.stage_fixture
                ),
                mock.patch.object(module.os, "link", side_effect=[None, OSError("failed")]),
            ):
                with self.assertRaisesRegex(module.InputGenerationError, "publication failed"):
                    module.generate(approval=module.APPROVAL, age_key=key)
            self.assertFalse((directory / module.INPUT_SET_NAME).exists())
            self.assertFalse(any(directory.glob(f".{module.INPUT_SET_NAME}.*")))

    def test_complete_pair_is_published_by_one_directory_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, key = self.private_root(temporary)
            with (
                mock.patch.object(module, "ROOT", root),
                mock.patch.object(module, "AGE_KEY", key),
                mock.patch.object(module.contracts, "validate_release_feed"),
                mock.patch.object(
                    module, "stage_encrypted", side_effect=self.stage_fixture
                ),
            ):
                paths = module.generate(approval=module.APPROVAL, age_key=key)
            self.assertEqual([path.name for path in paths], list(module.INPUT_NAMES))
            self.assertTrue(all(path.is_file() for path in paths))
            self.assertEqual(paths[0].parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
