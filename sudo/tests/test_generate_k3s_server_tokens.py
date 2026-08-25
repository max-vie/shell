"""Test the SUDO K3s server-token contract and private handoff."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, cast
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts" / "generate_k3s_server_tokens.py"
# The generator is a standalone command. Load it by path so tests do not turn
# the ignored SUDO working state into an importable package.
SPEC = importlib.util.spec_from_file_location("generate_k3s_server_tokens", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load SUDO generator: {SCRIPT}")
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class TestGenerateK3sServerTokens(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.contract_path = self.root / "sudo/secrets/k3s-server-token-contract.json"
        self.contract_path.parent.mkdir(parents=True)
        self.contract_path.write_text(
            json.dumps(self.contract_value()),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def contract_value(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "contract_version": "1.0.0",
            "contract_id": "k3s-server-token-contract",
            "policy_owner": "sudo",
            "consumer_owner": "init",
            "proof_status": "source-only",
            "token": dict(generator.EXPECTED_TOKEN),
            "storage": dict(generator.EXPECTED_STORAGE),
            "clusters": {
                name: dict(values)
                for name, values in generator.EXPECTED_CLUSTERS.items()
            },
        }

    def validate(self) -> dict[str, Any]:
        return cast(dict[str, Any], generator.validate_contract(self.contract_path))

    def generate(self, random_values: list[str] | None = None) -> tuple[int, str, str]:
        values = random_values or ["a" * 64, "b" * 64, "c" * 16, "d" * 16]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(generator.secrets, "token_hex", side_effect=values):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = generator.main(
                    ["--generate"],
                    repository_root=self.root,
                    contract_path=self.contract_path,
                )
        return result, stdout.getvalue(), stderr.getvalue()

    def token_paths(self) -> tuple[Path, Path]:
        return (
            self.root / ".local/sudo/k3s/gcp/server-token",
            self.root / ".local/sudo/k3s/proxmox/server-token",
        )

    def prepare_private_parent(self, path: Path) -> None:
        local_root = self.root / ".local"
        sudo_root = local_root / "sudo"
        k3s_root = sudo_root / "k3s"
        for directory in (local_root, sudo_root, k3s_root, path):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)

    def test_public_contract_is_exact(self) -> None:
        contract = self.validate()
        self.assertEqual(set(contract), generator.EXPECTED_TOP_LEVEL)
        self.assertEqual(contract["token"], generator.EXPECTED_TOKEN)
        self.assertEqual(contract["storage"], generator.EXPECTED_STORAGE)
        self.assertEqual(contract["clusters"], generator.EXPECTED_CLUSTERS)

    def test_contract_rejects_unknown_fields_and_malformed_encoding(self) -> None:
        altered = self.contract_value()
        altered["future"] = True
        self.contract_path.write_text(json.dumps(altered), encoding="utf-8")
        with self.assertRaisesRegex(generator.TokenContractError, "shape changed"):
            self.validate()

        self.contract_path.write_bytes(b"\xff")
        with self.assertRaisesRegex(generator.TokenContractError, "invalid JSON"):
            self.validate()

    def test_validate_only_writes_nothing(self) -> None:
        result = generator.main(
            ["--validate-only"],
            repository_root=self.root,
            contract_path=self.contract_path,
        )
        self.assertEqual(result, 0)
        self.assertFalse((self.root / ".local").exists())

    def test_generate_publishes_two_independent_private_tokens(self) -> None:
        result, stdout, stderr = self.generate()
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertNotIn("a" * 64, stdout)
        self.assertNotIn("b" * 64, stdout)

        paths = self.token_paths()
        self.assertEqual(paths[0].read_text(encoding="ascii"), "a" * 64 + "\n")
        self.assertEqual(paths[1].read_text(encoding="ascii"), "b" * 64 + "\n")
        for path in paths:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / ".local").stat().st_mode), 0o700)

    def test_generate_is_idempotent_for_two_valid_tokens(self) -> None:
        self.generate()
        paths = self.token_paths()
        baseline = [(path.stat().st_ino, path.read_bytes()) for path in paths]
        with mock.patch.object(
            generator.secrets, "token_hex", side_effect=AssertionError
        ):
            result = generator.generate_tokens(
                repository_root=self.root,
                contract_path=self.contract_path,
            )
        self.assertEqual(result, paths)
        self.assertEqual(
            [(path.stat().st_ino, path.read_bytes()) for path in paths],
            baseline,
        )

    def test_generate_refuses_partial_or_equal_state(self) -> None:
        first, second = self.token_paths()
        self.prepare_private_parent(first.parent)
        first.write_text("a" * 64 + "\n", encoding="ascii")
        first.chmod(0o600)
        with self.assertRaisesRegex(generator.TokenContractError, "partial"):
            generator.generate_tokens(
                repository_root=self.root,
                contract_path=self.contract_path,
            )

        self.prepare_private_parent(second.parent)
        second.write_text("a" * 64 + "\n", encoding="ascii")
        second.chmod(0o600)
        with self.assertRaisesRegex(generator.TokenContractError, "equal"):
            generator.generate_tokens(
                repository_root=self.root,
                contract_path=self.contract_path,
            )

    def test_generate_refuses_existing_malformed_token(self) -> None:
        first, _ = self.token_paths()
        self.prepare_private_parent(first.parent)
        first.write_text("x" * 64 + "\n", encoding="ascii")
        first.chmod(0o600)
        with self.assertRaisesRegex(generator.TokenContractError, "format is invalid"):
            generator.generate_tokens(
                repository_root=self.root,
                contract_path=self.contract_path,
            )

    def test_generate_refuses_unsafe_existing_local_root(self) -> None:
        local_root = self.root / ".local"
        local_root.mkdir(mode=0o755)
        local_root.chmod(0o755)
        result, stdout, stderr = self.generate()
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn("mode 0700", stderr)
        self.assertFalse((local_root / "sudo/k3s/gcp/server-token").exists())

    def test_generate_refuses_symlinked_output(self) -> None:
        local_root = self.root / ".local"
        local_root.mkdir(mode=0o700)
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (local_root / "sudo").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(
            generator.TokenContractError, "without following symlinks"
        ):
            generator.generate_tokens(
                repository_root=self.root,
                contract_path=self.contract_path,
            )
        self.assertEqual(list(outside.iterdir()), [])

    def test_generate_rejects_fifo_and_device_output(self) -> None:
        first, _ = self.token_paths()
        self.prepare_private_parent(first.parent)
        os.mkfifo(first)
        with self.assertRaisesRegex(generator.TokenContractError, "not a regular file"):
            generator.generate_tokens(
                repository_root=self.root,
                contract_path=self.contract_path,
            )

        first.unlink()
        first.symlink_to("/dev/null")
        with self.assertRaisesRegex(generator.TokenContractError, "not a regular file"):
            generator.generate_tokens(
                repository_root=self.root,
                contract_path=self.contract_path,
            )

    def test_generate_preserves_first_token_when_second_publication_fails(self) -> None:
        real_link = os.link
        calls = 0

        def link_once(*args: Any, **kwargs: Any) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected publication failure")
            real_link(*args, **kwargs)

        with mock.patch.object(generator.os, "link", side_effect=link_once):
            with self.assertRaisesRegex(OSError, "injected"):
                generator.generate_tokens(
                    repository_root=self.root,
                    contract_path=self.contract_path,
                )
        first, second = self.token_paths()
        self.assertTrue(first.is_file())
        self.assertFalse(second.exists())
        self.assertEqual(list(first.parent.glob(".*server-token.*")), [])

    def test_generate_returns_controlled_error_for_bad_contract(self) -> None:
        self.contract_path.write_bytes(b"\xff")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = generator.main(
                ["--generate"],
                repository_root=self.root,
                contract_path=self.contract_path,
            )
        self.assertEqual(result, 2)
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_private_directory_rejects_wrong_owner_metadata(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            metadata_values = list(os.fstat(descriptor))
            metadata_values[4] = os.geteuid() + 1
            wrong_owner = os.stat_result(metadata_values)
            with mock.patch.object(generator.os, "fstat", return_value=wrong_owner):
                with self.assertRaisesRegex(
                    generator.TokenContractError, "wrong owner"
                ):
                    generator._require_directory(descriptor, self.root)
        finally:
            os.close(descriptor)

    def test_created_private_directories_sync_their_parents(self) -> None:
        real_mkdir = os.mkdir
        real_fsync = os.fsync
        with (
            mock.patch.object(generator.os, "mkdir", wraps=real_mkdir) as mkdir_mock,
            mock.patch.object(generator.os, "fsync", wraps=real_fsync) as fsync_mock,
        ):
            descriptor = generator._open_private_directory(
                self.root / ".local/sudo/k3s/gcp",
                self.root.resolve(strict=True),
            )
            os.close(descriptor)

        self.assertEqual(mkdir_mock.call_count, 4)
        self.assertEqual(fsync_mock.call_count, 4)


if __name__ == "__main__":
    unittest.main()
