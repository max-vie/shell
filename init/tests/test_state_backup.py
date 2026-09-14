"""Test encrypted OpenTofu state backup boundaries."""

from __future__ import annotations

import importlib.util
import io
import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "init/scripts/backup_opentofu_state.py"
SPEC = importlib.util.spec_from_file_location("backup_opentofu_state", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load state backup helper")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class StateBackupTests(unittest.TestCase):
    def private_root(self, temporary: str) -> tuple[Path, Path, Path]:
        root = Path(temporary) / "repository"
        source_root = root / "init/opentofu/network"
        state_directory = root / ".local/opentofu/network"
        source_root.mkdir(parents=True, mode=0o700)
        state_directory.mkdir(parents=True, mode=0o700)
        state = state_directory / "terraform.tfstate"
        state.write_text(
            json.dumps({"lineage": "lineage", "serial": 3}),
            encoding="utf-8",
        )
        state.chmod(0o600)
        return root, source_root, state

    def test_requires_the_backup_approval(self) -> None:
        with self.assertRaisesRegex(helper.StateBackupError, "approval"):
            helper.backup(
                root="network",
                project="shell-project",
                commit="a" * 40,
                plan_sha256="b" * 64,
                destination=Path("/tmp/media"),
                recipient_file=helper.RECIPIENT,
                approval="wrong",
            )

    def test_rejects_nonremovable_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "media"
            destination.mkdir()

            def run(command: list[str], **_: object) -> SimpleNamespace:
                if command[0] == "findmnt":
                    source = b"/dev/sda3\n" if str(destination) not in command else b"/dev/sdb1\n"
                    return SimpleNamespace(returncode=0, stdout=source, stderr=b"")
                return SimpleNamespace(returncode=0, stdout=b"0\n", stderr=b"")

            with self.assertRaisesRegex(helper.StateBackupError, "not removable"):
                helper._removable_mount(destination, run_process=run)

    def test_backup_binds_state_and_plan_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source_root, state = self.private_root(temporary)
            media = Path(temporary) / "media"
            media.mkdir()
            with (
                mock.patch.object(helper, "ROOT", root),
                mock.patch.object(
                    helper,
                    "STATE_ROOTS",
                    {"network": source_root},
                ),
                mock.patch.object(
                    helper,
                    "STATE_PATHS",
                    {"network": state},
                ),
                mock.patch.object(helper, "_removable_mount"),
                mock.patch.object(helper, "_write_archive") as write_archive,
            ):
                def write_archive_file(
                    _state: Path,
                    _manifest: dict[str, object],
                    archive: Path,
                    _recipient: Path,
                    **_: object,
                ) -> None:
                    archive.write_bytes(b"encrypted")
                    archive.chmod(0o600)

                write_archive.side_effect = write_archive_file

                def run(command: list[str], **_: object) -> SimpleNamespace:
                    return SimpleNamespace(
                        returncode=0,
                        stdout=b"resource.example\n",
                        stderr=b"",
                    )

                output = helper.backup(
                    root="network",
                    project="shell-project",
                    commit="a" * 40,
                    plan_sha256="b" * 64,
                    destination=media,
                    recipient_file=helper.RECIPIENT,
                    approval=helper.BACKUP_APPROVAL,
                    run_process=run,
                )

            self.assertEqual(output.parent, media)
            manifest = write_archive.call_args.args[1]
            self.assertEqual(manifest["project_id"], "shell-project")
            self.assertEqual(manifest["plan_sha256"], "b" * 64)
            self.assertEqual(manifest["resource_addresses"], ["resource.example"])

    def test_restore_checks_manifest_and_resource_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, source_root, state = self.private_root(temporary)
            media = Path(temporary) / "media"
            media.mkdir()
            archive = media / "state.tar.age"
            archive.write_bytes(b"encrypted")
            archive.chmod(0o600)
            identity_directory = root / ".local/sudo/state-backup"
            identity_directory.mkdir(parents=True, mode=0o700)
            identity = identity_directory / "age-key.txt"
            identity.write_text("AGE-SECRET-KEY-test\n", encoding="ascii")
            identity.chmod(0o600)

            state_value = json.dumps({"lineage": "lineage", "serial": 3}).encode()
            manifest = {
                "schema_version": "1.0",
                "root": "network",
                "project_id": "shell-project",
                "commit": "a" * 40,
                "plan_sha256": "b" * 64,
                "state_sha256": hashlib.sha256(state_value).hexdigest(),
                "state_lineage": "lineage",
                "state_serial": 3,
                "resource_addresses": ["resource.example"],
            }
            plaintext_tar = Path(temporary) / "state.tar"
            with tarfile.open(plaintext_tar, "w") as bundle:
                state_info = tarfile.TarInfo("terraform.tfstate")
                state_info.size = len(state_value)
                bundle.addfile(state_info, io.BytesIO(state_value))
                manifest_value = json.dumps(manifest).encode()
                manifest_info = tarfile.TarInfo("manifest.json")
                manifest_info.size = len(manifest_value)
                bundle.addfile(manifest_info, io.BytesIO(manifest_value))

            with (
                mock.patch.object(helper, "ROOT", root),
                mock.patch.object(helper, "IDENTITY", identity),
                mock.patch.object(helper, "STATE_ROOTS", {"network": source_root}),
                mock.patch.object(helper, "STATE_PATHS", {"network": state}),
                mock.patch.object(helper, "_removable_mount"),
            ):
                def run(command: list[str], **_: object) -> SimpleNamespace:
                    if command[0] == "age":
                        output = Path(command[command.index("--output") + 1])
                        output.write_bytes(plaintext_tar.read_bytes())
                    return SimpleNamespace(
                        returncode=0,
                        stdout=b"resource.example\n",
                        stderr=b"",
                    )

                helper.restore_check(
                    archive=archive,
                    root="network",
                    project="shell-project",
                    commit="a" * 40,
                    plan_sha256="b" * 64,
                    identity=identity,
                    approval=helper.RESTORE_APPROVAL,
                    run_process=run,
                )


if __name__ == "__main__":
    unittest.main()
