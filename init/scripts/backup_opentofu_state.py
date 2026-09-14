#!/usr/bin/env python3
"""Create and verify encrypted OpenTofu state backups."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, cast


ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
AGE_RECIPIENT_PATTERN = re.compile(r"^age1[0-9a-z]+$")
BACKUP_APPROVAL = "environment-gcp/init/state-backup"
RESTORE_APPROVAL = "environment-gcp/init/state-restore"
RECIPIENT = ROOT / ".local/sudo/state-backup/recipient.txt"
IDENTITY = ROOT / ".local/sudo/state-backup/age-key.txt"

STATE_ROOTS = {
    "bootstrap": ROOT / "init/opentofu/gcp/bootstrap",
    "gcp/network": ROOT / "init/opentofu/gcp/network",
    "gcp/shared-nodes": ROOT / "init/opentofu/gcp/shared-nodes",
    "gcp/k3s": ROOT / "init/opentofu/gcp/k3s",
    "gcp/proxmox-host": ROOT / "init/opentofu/gcp/proxmox-host",
    "proxmox/k3s": ROOT / "init/opentofu/proxmox/k3s",
    "gcs-backup": ROOT / "init/opentofu/gcs-backup",
}
STATE_PATHS = {
    "bootstrap": ROOT / ".local/opentofu/gcp/bootstrap/terraform.tfstate",
    "gcp/network": ROOT / ".local/opentofu/gcp/network/terraform.tfstate",
    "gcp/shared-nodes": ROOT / ".local/opentofu/gcp/shared-nodes/terraform.tfstate",
    "gcp/k3s": ROOT / ".local/opentofu/gcp/k3s/terraform.tfstate",
    "gcp/proxmox-host": ROOT / ".local/opentofu/gcp/proxmox-host/terraform.tfstate",
    "proxmox/k3s": ROOT / ".local/opentofu/proxmox/k3s/terraform.tfstate",
    "gcs-backup": ROOT / ".local/opentofu/gcs-backup/terraform.tfstate",
}


class StateBackupError(RuntimeError):
    """The state backup workflow rejected its inputs or evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StateBackupError(message)


def _private_directory(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    require(value.is_dir() and not value.is_symlink(), f"{label} is missing")
    metadata = value.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE,
        f"{label} must be mode 0700",
    )
    return value


def _private_file(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    require(value.is_file() and not value.is_symlink(), f"{label} is missing")
    metadata = value.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
        f"{label} must be mode 0600",
    )
    _private_directory(value.parent, f"{label} directory")
    return value


def _external_file(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    require(value.is_file() and not value.is_symlink(), f"{label} is missing")
    metadata = value.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
        f"{label} must be mode 0600",
    )
    return value


def _root_value(root: str) -> tuple[Path, Path]:
    require(root in STATE_ROOTS, "root is not allow-listed")
    state_root = STATE_ROOTS[root]
    state_path = STATE_PATHS[root]
    require(state_root.is_dir() and not state_root.is_symlink(), "root source is missing")
    _private_directory(state_path.parent, "state directory")
    _private_file(state_path, "OpenTofu state")
    return state_root, state_path


def _valid_metadata(project: str, commit: str, plan_sha256: str) -> None:
    require(PROJECT_PATTERN.fullmatch(project) is not None, "project is invalid")
    require(COMMIT_PATTERN.fullmatch(commit) is not None, "commit must be a full SHA")
    require(SHA256_PATTERN.fullmatch(plan_sha256) is not None, "plan digest is invalid")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_state(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StateBackupError("OpenTofu state is not valid JSON") from error
    require(isinstance(value, dict), "OpenTofu state must be an object")
    require(isinstance(value.get("lineage"), str), "state lineage is missing")
    require(isinstance(value.get("serial"), int), "state serial is missing")
    return cast(dict[str, Any], value)


def _run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: int = 120,
    run_process: Callable[..., Any] = subprocess.run,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = run_process(
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise StateBackupError(f"{command[0]} could not complete") from error
    if result.returncode:
        raise StateBackupError(f"{command[0]} failed")
    return cast(subprocess.CompletedProcess[bytes], result)


def _state_addresses(
    root_path: Path,
    state_path: Path,
    *,
    tofu: str,
    run_process: Callable[..., Any],
) -> list[str]:
    result = _run(
        [
            tofu,
            f"-chdir={root_path}",
            "state",
            "list",
            f"-state={state_path}",
            "-no-color",
        ],
        run_process=run_process,
    )
    try:
        output = result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else result.stdout
    except UnicodeDecodeError as error:
        raise StateBackupError("tofu state list returned non-UTF-8 output") from error
    addresses = [line.strip() for line in output.splitlines() if line.strip()]
    require(addresses == sorted(addresses), "state addresses are not sorted")
    require(addresses, "OpenTofu state has no resources")
    return addresses


def _recipient(path: Path) -> str:
    require(path == RECIPIENT, "recipient path changed")
    value = _private_file(path, "state-backup recipient").read_text(encoding="ascii").strip()
    require(AGE_RECIPIENT_PATTERN.fullmatch(value) is not None, "age recipient is invalid")
    return value


def _identity(path: Path) -> Path:
    require(path == IDENTITY, "identity path changed")
    value = _private_file(path, "state-backup identity")
    first_line = value.read_text(encoding="ascii").splitlines()[0]
    require(first_line.startswith("AGE-SECRET-KEY-"), "age identity is invalid")
    return value


def _removable_mount(
    destination: Path,
    *,
    run_process: Callable[..., Any],
) -> None:
    value = Path(os.path.abspath(destination))
    require(value.is_dir() and not value.is_symlink(), "backup destination is missing")
    require(not value.is_relative_to(ROOT), "backup destination is inside the repository")
    root_mount_result = _run(
        ["findmnt", "--target", str(ROOT), "--noheadings", "--output", "SOURCE"],
        run_process=run_process,
    )
    root_mount_output = (
        root_mount_result.stdout.decode("utf-8")
        if isinstance(root_mount_result.stdout, bytes)
        else root_mount_result.stdout
    )
    root_source = root_mount_output.strip().split("[", 1)[0]
    mount_result = _run(
        ["findmnt", "--target", str(value), "--noheadings", "--output", "SOURCE"],
        run_process=run_process,
    )
    mounted_output = (
        mount_result.stdout.decode("utf-8")
        if isinstance(mount_result.stdout, bytes)
        else mount_result.stdout
    )
    mounted = mounted_output.strip()
    require(mounted and mounted.split("[", 1)[0] != root_source, "backup destination is not off-host media")
    source = mounted.split("[", 1)[0]
    removable_result = _run(
        ["lsblk", "--noheadings", "--output", "RM", source],
        run_process=run_process,
    )
    removable_output = (
        removable_result.stdout.decode("utf-8")
        if isinstance(removable_result.stdout, bytes)
        else removable_result.stdout
    )
    removable = removable_output.strip()
    require(removable == "1", "backup destination is not removable media")


def _manifest(
    *,
    root: str,
    project: str,
    commit: str,
    plan_sha256: str,
    state: dict[str, Any],
    state_sha256: str,
    addresses: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "root": root,
        "project_id": project,
        "commit": commit,
        "plan_sha256": plan_sha256,
        "state_sha256": state_sha256,
        "state_lineage": state["lineage"],
        "state_serial": state["serial"],
        "resource_addresses": addresses,
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
    }


def _write_archive(
    state: Path,
    manifest: dict[str, Any],
    archive: Path,
    recipient_file: Path,
    *,
    run_process: Callable[..., Any],
) -> None:
    with tempfile.TemporaryDirectory(prefix="shell-state-backup-", dir=ROOT / ".local") as directory:
        staging = Path(directory)
        staged_state = staging / "terraform.tfstate"
        staged_manifest = staging / "manifest.json"
        staged_state.write_bytes(state.read_bytes())
        staged_manifest.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        staged_state.chmod(PRIVATE_FILE_MODE)
        staged_manifest.chmod(PRIVATE_FILE_MODE)
        tar_path = staging / "state.tar"
        with tarfile.open(tar_path, mode="w") as bundle:
            bundle.add(staged_state, arcname="terraform.tfstate", recursive=False)
            bundle.add(staged_manifest, arcname="manifest.json", recursive=False)
        tar_path.chmod(PRIVATE_FILE_MODE)
        archive.parent.mkdir(parents=False, exist_ok=True)
        temporary = archive.with_name(f".{archive.name}.tmp")
        require(not temporary.exists() and not temporary.is_symlink(), "backup temporary file exists")
        _run(
            [
                "age",
                "--encrypt",
                "--recipient",
                _recipient(recipient_file),
                "--output",
                str(temporary),
                str(tar_path),
            ],
            run_process=run_process,
        )
        temporary.chmod(PRIVATE_FILE_MODE)
        os.replace(temporary, archive)
        archive.chmod(PRIVATE_FILE_MODE)


def backup(
    *,
    root: str,
    project: str,
    commit: str,
    plan_sha256: str,
    destination: Path,
    recipient_file: Path,
    approval: str,
    tofu: str = "tofu",
    run_process: Callable[..., Any] = subprocess.run,
) -> Path:
    require(approval == BACKUP_APPROVAL, f"approval must be {BACKUP_APPROVAL}")
    _valid_metadata(project, commit, plan_sha256)
    root_path, state_path = _root_value(root)
    _removable_mount(destination, run_process=run_process)
    state = _read_state(state_path)
    addresses = _state_addresses(root_path, state_path, tofu=tofu, run_process=run_process)
    state_sha256 = _sha256(state_path)
    manifest = _manifest(
        root=root,
        project=project,
        commit=commit,
        plan_sha256=plan_sha256,
        state=state,
        state_sha256=state_sha256,
        addresses=addresses,
    )
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    archive = destination / f"shell-opentofu-{root.replace('/', '-')}-{commit}-{timestamp}.tar.age"
    require(not archive.exists() and not archive.is_symlink(), "backup already exists")
    _write_archive(
        state_path,
        manifest,
        archive,
        recipient_file,
        run_process=run_process,
    )
    print(f"state backup created: root={root} resources={len(addresses)}")
    print(f"state backup sha256: {_sha256(archive)}")
    return archive


def _extract_archive(
    archive: Path,
    identity: Path,
    *,
    run_process: Callable[..., Any],
) -> tuple[Path, dict[str, Any], tempfile.TemporaryDirectory[str]]:
    _external_file(archive, "state backup")
    _identity(identity)
    temporary = tempfile.TemporaryDirectory(prefix="shell-state-restore-", dir=ROOT / ".local")
    directory = Path(temporary.name)
    try:
        decrypted = directory / "state.tar"
        _run(
            ["age", "--decrypt", "--identity", str(identity), "--output", str(decrypted), str(archive)],
            run_process=run_process,
        )
        decrypted.chmod(PRIVATE_FILE_MODE)
        with tarfile.open(decrypted, mode="r:") as bundle:
            members = bundle.getmembers()
            require(
                sorted(member.name for member in members) == ["manifest.json", "terraform.tfstate"],
                "backup archive contents changed",
            )
            for member in members:
                require(member.isfile() and not member.issym() and not member.islnk(), "backup contains unsafe archive entry")
                target = directory / member.name
                extracted = bundle.extractfile(member)
                require(extracted is not None, "backup archive entry cannot be read")
                target.write_bytes(extracted.read())
                target.chmod(PRIVATE_FILE_MODE)
        try:
            manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise StateBackupError("backup manifest is invalid") from error
        require(isinstance(manifest, dict), "backup manifest must be an object")
        return directory / "terraform.tfstate", cast(dict[str, Any], manifest), temporary
    except Exception:
        temporary.cleanup()
        raise


def restore_check(
    *,
    archive: Path,
    root: str,
    project: str,
    commit: str,
    plan_sha256: str,
    identity: Path,
    approval: str,
    tofu: str = "tofu",
    run_process: Callable[..., Any] = subprocess.run,
) -> None:
    require(approval == RESTORE_APPROVAL, f"approval must be {RESTORE_APPROVAL}")
    _valid_metadata(project, commit, plan_sha256)
    root_path, _ = _root_value(root)
    _removable_mount(archive.parent, run_process=run_process)
    restored, manifest, temporary = _extract_archive(
        archive,
        identity,
        run_process=run_process,
    )
    try:
        require(manifest.get("schema_version") == "1.0", "backup schema changed")
        require(manifest.get("root") == root, "backup root changed")
        require(manifest.get("project_id") == project, "backup project changed")
        require(manifest.get("commit") == commit, "backup commit changed")
        require(manifest.get("plan_sha256") == plan_sha256, "backup plan digest changed")
        require(manifest.get("state_sha256") == _sha256(restored), "backup state digest changed")
        addresses = _state_addresses(root_path, restored, tofu=tofu, run_process=run_process)
        require(addresses == manifest.get("resource_addresses"), "restored resource addresses changed")
        print(f"state restore verified: root={root} resources={len(addresses)}")
    finally:
        temporary.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", choices=sorted(STATE_ROOTS), required=True)
    common.add_argument("--project", required=True)
    common.add_argument("--commit", required=True)
    common.add_argument("--plan-sha256", required=True)
    common.add_argument("--tofu", default="tofu")
    common.add_argument("--approval", required=True)

    backup_parser = actions.add_parser("backup", parents=[common])
    backup_parser.add_argument("--destination-dir", type=Path, required=True)
    backup_parser.add_argument("--recipient-file", type=Path, default=RECIPIENT)

    restore_parser = actions.add_parser("restore-check", parents=[common])
    restore_parser.add_argument("--backup", type=Path, required=True)
    restore_parser.add_argument("--identity-file", type=Path, default=IDENTITY)

    args = parser.parse_args(argv)
    try:
        if args.action == "backup":
            backup(
                root=args.root,
                project=args.project,
                commit=args.commit,
                plan_sha256=args.plan_sha256,
                destination=args.destination_dir,
                recipient_file=args.recipient_file,
                approval=args.approval,
                tofu=args.tofu,
            )
        else:
            restore_check(
                archive=args.backup,
                root=args.root,
                project=args.project,
                commit=args.commit,
                plan_sha256=args.plan_sha256,
                identity=args.identity_file,
                approval=args.approval,
                tofu=args.tofu,
            )
        return 0
    except (OSError, StateBackupError, tarfile.TarError) as error:
        print(f"INIT state backup refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
