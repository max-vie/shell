"""Test the TAR-to-INIT K3s runtime supply handoff."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any, cast
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "scripts" / "stage_init_supply.py"
# The stager is a standalone command, not an installed Python package. Loading
# it by path keeps the test aligned with how the repository runs the script.
SPEC = importlib.util.spec_from_file_location("stage_init_supply", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load TAR stager: {SCRIPT}")
stager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stager)


class TestInitSupply(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.source = Path(self.temporary.name) / "k3s-source"
        self.content = b"synthetic K3s test fixture\n"
        self.source.write_bytes(self.content)
        # Replace only the binary size and digest in the isolated contract.
        # Tests can exercise staging without acquiring the real K3s binary.
        self.expected_k3s = dict(stager.EXPECTED_K3S_BINARY)
        self.expected_k3s["sha256"] = hashlib.sha256(self.content).hexdigest()
        self.expected_k3s["size"] = len(self.content)
        self.lock_path = self.root / "tar/manifests/init-k3s-runtime-supply.json"
        self.write_lock()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def lock_value(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "contract_version": "1.0.0",
            "contract_id": "init-k3s-runtime-supply",
            "policy_owner": "tar",
            "execution_owner": "init",
            "proof_status": "source-reference-only",
            "k3s_binary": dict(self.expected_k3s),
            "kube_vip_image": dict(stager.EXPECTED_KUBE_VIP_IMAGE),
        }

    def write_lock(self, value: dict[str, Any] | None = None) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.write_text(
            json.dumps(self.lock_value() if value is None else value),
            encoding="utf-8",
        )

    def validate_custom_lock(self) -> dict[str, Any]:
        with mock.patch.object(stager, "EXPECTED_K3S_BINARY", self.expected_k3s):
            return cast(dict[str, Any], stager.validate_lock(self.lock_path))

    def stage(self, source: Path | None = None) -> tuple[Path, Path]:
        # Every write stays below the temporary repository root. The command
        # line interface cannot override the production expected pins.
        with mock.patch.object(stager, "EXPECTED_K3S_BINARY", self.expected_k3s):
            return cast(
                tuple[Path, Path],
                stager.stage_supply(
                    self.source if source is None else source,
                    repository_root=self.root,
                    lock_path=self.lock_path,
                ),
            )

    def test_public_lock_has_the_exact_reviewed_contract(self) -> None:
        lock = stager.validate_lock()
        self.assertEqual(set(lock), stager.EXPECTED_TOP_LEVEL)
        self.assertEqual(lock["k3s_binary"], stager.EXPECTED_K3S_BINARY)
        self.assertEqual(lock["kube_vip_image"], stager.EXPECTED_KUBE_VIP_IMAGE)

    def test_lock_rejects_unknown_fields_platform_digest_and_size(self) -> None:
        cases: list[tuple[str, dict[str, Any], str]] = []
        unknown = self.lock_value()
        unknown["future"] = {}
        cases.append(("unknown field", unknown, "shape changed"))

        wrong_platform = self.lock_value()
        wrong_platform["kube_vip_image"]["platform"] = "linux/arm64"
        cases.append(("wrong platform", wrong_platform, "platform changed"))

        bad_digest = self.lock_value()
        bad_digest["kube_vip_image"]["digest"] = "sha256:not-a-digest"
        cases.append(("bad digest", bad_digest, "digest is invalid"))

        bad_size = self.lock_value()
        bad_size["k3s_binary"]["size"] = 0
        cases.append(("bad size", bad_size, "positive byte count"))

        for label, value, message in cases:
            with self.subTest(case=label):
                self.write_lock(value)
                with self.assertRaisesRegex(stager.SupplyError, message):
                    self.validate_custom_lock()

    def test_validate_only_creates_no_private_state(self) -> None:
        result = stager.main(
            ["--validate-only"],
            repository_root=self.root,
            lock_path=stager.LOCK_PATH,
        )
        self.assertEqual(result, 0)
        self.assertFalse((self.root / ".local").exists())

    def test_non_utf8_lock_returns_controlled_error(self) -> None:
        self.lock_path.write_bytes(b"\xff")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = stager.main(["--validate-only"], lock_path=self.lock_path)
        self.assertEqual(result, 2)
        self.assertIn("invalid JSON file", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_stage_publishes_private_binary_and_exact_handoff(self) -> None:
        destination, handoff_path = self.stage()
        self.assertEqual(destination.read_bytes(), self.content)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(handoff_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(handoff_path.parent.stat().st_mode), 0o700)

        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        self.assertEqual(
            handoff,
            {
                "shell_k3s_version": self.expected_k3s["version"],
                "shell_k3s_binary_path": str(destination),
                "shell_k3s_binary_sha256": self.expected_k3s["sha256"],
                "shell_k3s_api_vip_image_repository": stager.EXPECTED_KUBE_VIP_IMAGE[
                    "repository"
                ],
                "shell_k3s_api_vip_image_digest": stager.EXPECTED_KUBE_VIP_IMAGE[
                    "digest"
                ],
            },
        )
        self.assertNotIn("token", handoff_path.read_text(encoding="utf-8").lower())

    def test_stage_is_idempotent_for_matching_private_state(self) -> None:
        destination, handoff = self.stage()
        # Stable inode numbers prove the second run reused both files instead
        # of replacing already verified private state.
        baseline = (destination.stat().st_ino, handoff.stat().st_ino)
        repeated_destination, repeated_handoff = self.stage()
        self.assertEqual(
            (repeated_destination.stat().st_ino, repeated_handoff.stat().st_ino),
            baseline,
        )

    def test_stage_rejects_fifo_without_blocking_or_creating_state(self) -> None:
        fifo = Path(self.temporary.name) / "k3s-fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(stager.SupplyError, "not a regular file"):
            self.stage(fifo)
        self.assertFalse((self.root / ".local").exists())

    def test_stage_rejects_device_without_creating_state(self) -> None:
        with self.assertRaisesRegex(stager.SupplyError, "not a regular file"):
            self.stage(Path("/dev/null"))
        self.assertFalse((self.root / ".local").exists())

    def test_stage_rejects_symlinked_source_and_parent(self) -> None:
        source_link = Path(self.temporary.name) / "source-link"
        source_link.symlink_to(self.source)
        with self.assertRaisesRegex(stager.SupplyError, "not a regular file"):
            self.stage(source_link)

        real_parent = Path(self.temporary.name) / "real-parent"
        real_parent.mkdir()
        nested_source = real_parent / "k3s"
        nested_source.write_bytes(self.content)
        parent_link = Path(self.temporary.name) / "parent-link"
        parent_link.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(stager.SupplyError, "without following symlinks"):
            self.stage(parent_link / "k3s")
        self.assertFalse((self.root / ".local").exists())

    def test_stage_rejects_unsafe_private_root(self) -> None:
        local_root = self.root / ".local"
        local_root.mkdir()
        local_root.chmod(0o777)
        with self.assertRaisesRegex(stager.SupplyError, "group or world writable"):
            self.stage()
        self.assertFalse((local_root / "ansible/k3s-runtime-supply.json").exists())
        self.assertFalse((local_root / "tar/init-k3s-runtime/k3s").exists())

    def test_stage_rejects_symlinked_outputs(self) -> None:
        stage_parent = self.root / ".local/tar/init-k3s-runtime"
        stage_parent.mkdir(parents=True)
        (self.root / ".local").chmod(0o700)
        (self.root / ".local/tar").chmod(0o700)
        stage_parent.chmod(0o700)
        target = Path(self.temporary.name) / "outside-binary"
        target.write_bytes(self.content)
        (stage_parent / "k3s").symlink_to(target)
        with self.assertRaisesRegex(stager.SupplyError, "not a regular file"):
            self.stage()

        (stage_parent / "k3s").unlink()
        handoff_parent = self.root / ".local/ansible"
        handoff_parent.mkdir(mode=0o700, exist_ok=True)
        handoff_parent.chmod(0o700)
        handoff_target = Path(self.temporary.name) / "outside-handoff"
        handoff_target.write_text("{}\n", encoding="utf-8")
        (handoff_parent / "k3s-runtime-supply.json").symlink_to(handoff_target)
        with self.assertRaisesRegex(stager.SupplyError, "not a regular file"):
            self.stage()
        # Rejection must leave the symlink target and binary destination untouched.
        self.assertEqual(handoff_target.read_text(encoding="utf-8"), "{}\n")
        self.assertFalse((stage_parent / "k3s").exists())

    def test_stage_rejects_symlinked_output_parent(self) -> None:
        local_root = self.root / ".local"
        local_root.mkdir(mode=0o700)
        outside = Path(self.temporary.name) / "outside-output"
        outside.mkdir()
        (local_root / "ansible").symlink_to(outside, target_is_directory=True)

        with self.assertRaisesRegex(stager.SupplyError, "without following symlinks"):
            self.stage()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((local_root / "tar/init-k3s-runtime/k3s").exists())

    def test_stage_rejects_bad_size_before_creating_state(self) -> None:
        self.source.write_bytes(self.content + b"extra")
        with self.assertRaisesRegex(stager.SupplyError, "size does not match"):
            self.stage()
        self.assertFalse((self.root / ".local").exists())

    def test_stage_rejects_bad_checksum_and_cleans_temporary_files(self) -> None:
        self.source.write_bytes(b"x" * len(self.content))
        with self.assertRaisesRegex(stager.SupplyError, "does not match the lock"):
            self.stage()
        stage_parent = self.root / ".local/tar/init-k3s-runtime"
        self.assertFalse((stage_parent / "k3s").exists())
        self.assertEqual(list(stage_parent.glob(".k3s.*")), [])

    def test_stage_rejects_directory_source_before_creating_state(self) -> None:
        self.source.unlink()
        self.source.mkdir()
        with self.assertRaisesRegex(stager.SupplyError, "not a regular file"):
            self.stage()
        self.assertFalse((self.root / ".local").exists())

    def test_stage_refuses_mismatched_existing_state(self) -> None:
        destination, handoff = self.stage()
        # Existing private state is immutable to this command. An operator must
        # review and remove stale state before another supply can replace it.
        destination.write_bytes(b"x" * len(self.content))
        with self.assertRaisesRegex(stager.SupplyError, "differs from the lock"):
            self.stage()

        destination.write_bytes(self.content)
        destination.chmod(0o600)
        handoff.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(stager.SupplyError, "wrong size"):
            self.stage()

    def test_stale_handoff_blocks_before_binary_publication(self) -> None:
        handoff_parent = self.root / ".local/ansible"
        handoff_parent.mkdir(parents=True)
        (self.root / ".local").chmod(0o700)
        handoff_parent.chmod(0o700)
        handoff = handoff_parent / "k3s-runtime-supply.json"
        handoff.write_text("{}\n", encoding="utf-8")
        handoff.chmod(0o600)

        with self.assertRaisesRegex(stager.SupplyError, "wrong size"):
            self.stage()
        self.assertFalse((self.root / ".local/tar/init-k3s-runtime/k3s").exists())

    def test_valid_handoff_without_binary_fails_closed(self) -> None:
        destination, handoff = self.stage()
        destination.unlink()

        with self.assertRaisesRegex(
            stager.SupplyError, "handoff exists.*binary is missing"
        ):
            self.stage()
        self.assertTrue(handoff.is_file())
        self.assertFalse(destination.exists())

    def test_binary_without_handoff_recovers_without_replacing_binary(self) -> None:
        destination, handoff = self.stage()
        binary_inode = destination.stat().st_ino
        handoff.unlink()

        repeated_destination, repeated_handoff = self.stage()
        self.assertEqual(repeated_destination.stat().st_ino, binary_inode)
        self.assertTrue(repeated_handoff.is_file())

    def test_stage_rejects_source_destination_identity(self) -> None:
        destination, _ = self.stage()
        with self.assertRaisesRegex(stager.SupplyError, "same file"):
            self.stage(destination)

    def test_created_private_directories_sync_their_parents(self) -> None:
        real_mkdir = os.mkdir
        real_fsync = os.fsync
        with (
            mock.patch.object(stager.os, "mkdir", wraps=real_mkdir) as mkdir_mock,
            mock.patch.object(stager.os, "fsync", wraps=real_fsync) as fsync_mock,
        ):
            descriptor = stager._open_private_directory(
                self.root / ".local/ansible",
                self.root.resolve(strict=True),
            )
            os.close(descriptor)

        self.assertEqual(mkdir_mock.call_count, 2)
        self.assertEqual(fsync_mock.call_count, 2)

    def test_private_directory_rejects_wrong_owner_metadata(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            metadata_values = list(os.fstat(descriptor))
            metadata_values[4] = os.geteuid() + 1
            wrong_owner = os.stat_result(metadata_values)
            with mock.patch.object(stager.os, "fstat", return_value=wrong_owner):
                with self.assertRaisesRegex(stager.SupplyError, "wrong owner"):
                    stager._require_owned_directory(
                        descriptor,
                        self.root,
                        exact_private_mode=False,
                    )
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
