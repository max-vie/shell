#!/usr/bin/env python3
"""Validate and stage the TAR inputs consumed by INIT's K3s runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import urllib.parse
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPOSITORY_ROOT / "tar/manifests/init-k3s-runtime-supply.json"
STAGE_PATH = Path(".local/tar/init-k3s-runtime/k3s")
HANDOFF_PATH = Path(".local/ansible/k3s-runtime-supply.json")
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
READ_CHUNK_SIZE = 1024 * 1024

EXPECTED_TOP_LEVEL = {
    "schema_version",
    "contract_version",
    "contract_id",
    "policy_owner",
    "execution_owner",
    "proof_status",
    "k3s_binary",
    "kube_vip_image",
}
# Keep the reviewed pins in code as a second gate. A lock-only version change
# must fail validation until the matching code change is reviewed as well.
EXPECTED_K3S_BINARY: dict[str, object] = {
    "version": "v1.34.10+k3s1",
    "file_name": "k3s",
    "source": ("https://github.com/k3s-io/k3s/releases/download/v1.34.10%2Bk3s1/k3s"),
    "sha256": "e63a3511b2603fd1436a1ea8d228348a3b47334b45024801d41a8c0e2d22e8c4",
    "size": 80879800,
}
EXPECTED_KUBE_VIP_IMAGE: dict[str, object] = {
    "repository": "ghcr.io/kube-vip/kube-vip",
    "tag": "v1.0.4",
    "platform": "linux/amd64",
    "digest": "sha256:742d6713401a1238043319c76aceba174556301153bdd61b60bdfa1fe3907ed7",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SupplyError(ValueError):
    """A TAR supply input cannot be handed to INIT safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SupplyError(message)


def _read_json_object(path: Path) -> dict[str, Any]:
    # The lock is public, but accepting a symlink would let local state replace
    # the tracked policy file with unrelated JSON.
    require(path.is_file() and not path.is_symlink(), f"missing regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SupplyError(f"invalid JSON file: {path}") from error
    require(isinstance(value, dict), f"JSON value must be an object: {path}")
    return cast(dict[str, Any], value)


def validate_lock(path: Path = LOCK_PATH) -> dict[str, Any]:
    """Validate the fixed public supply contract without writing state."""

    lock = _read_json_object(path)
    # Exact key sets make contract expansion a reviewed schema change instead
    # of silently accepting fields that the consumer ignores.
    require(set(lock) == EXPECTED_TOP_LEVEL, "TAR supply lock shape changed")
    require(lock["schema_version"] == "1.0", "unsupported supply schema")
    require(lock["contract_version"] == "1.0.0", "unsupported contract version")
    require(lock["contract_id"] == "init-k3s-runtime-supply", "unexpected contract ID")
    require(lock["policy_owner"] == "tar", "TAR must own supply policy")
    require(lock["execution_owner"] == "init", "INIT must own execution")
    require(lock["proof_status"] == "source-reference-only", "invalid proof status")

    k3s = lock["k3s_binary"]
    require(isinstance(k3s, dict), "K3s binary entry must be an object")
    require(set(k3s) == set(EXPECTED_K3S_BINARY), "K3s binary shape changed")
    require(isinstance(k3s["version"], str), "K3s version must be a string")
    require(k3s["file_name"] == "k3s", "K3s filename changed")
    require(isinstance(k3s["source"], str), "K3s source must be a string")
    require(
        isinstance(k3s["sha256"], str)
        and SHA256_RE.fullmatch(k3s["sha256"]) is not None,
        "K3s SHA-256 is invalid",
    )
    require(
        isinstance(k3s["size"], int)
        and not isinstance(k3s["size"], bool)
        and k3s["size"] > 0,
        "K3s size must be a positive byte count",
    )
    source = urllib.parse.urlsplit(k3s["source"])
    # Reject credentials and lookalike hosts before the exact pin comparison
    # below checks the complete release URL.
    require(
        source.scheme == "https"
        and source.hostname == "github.com"
        and source.username is None
        and source.password is None,
        "K3s source must be the credential-free official HTTPS release URL",
    )
    require(k3s == EXPECTED_K3S_BINARY, "K3s binary pin changed")

    kube_vip = lock["kube_vip_image"]
    require(isinstance(kube_vip, dict), "Kube-VIP image entry must be an object")
    require(
        set(kube_vip) == set(EXPECTED_KUBE_VIP_IMAGE),
        "Kube-VIP image shape changed",
    )
    require(
        all(isinstance(value, str) for value in kube_vip.values()),
        "Kube-VIP image values must be strings",
    )
    require(kube_vip["platform"] == "linux/amd64", "Kube-VIP platform changed")
    require(
        isinstance(kube_vip["digest"], str)
        and IMAGE_DIGEST_RE.fullmatch(kube_vip["digest"]) is not None,
        "Kube-VIP digest is invalid",
    )
    require(kube_vip == EXPECTED_KUBE_VIP_IMAGE, "Kube-VIP image pin changed")
    return lock


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    require(nofollow != 0 and directory != 0, "platform lacks safe directory flags")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _path_open_flags() -> int:
    path_only = getattr(os, "O_PATH", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    require(path_only != 0 and nofollow != 0, "platform lacks safe path flags")
    return path_only | os.O_CLOEXEC | nofollow


def _file_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    require(nofollow != 0 and nonblock != 0, "platform lacks safe file flags")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | nonblock


def _open_absolute_directory(path: Path, label: str) -> int:
    """Open an absolute directory without following any path component."""

    require(path.is_absolute(), f"{label} must be an absolute path")
    parts = path.parts
    require(
        bool(parts) and parts[0] == os.sep,
        f"{label} must start at the filesystem root",
    )
    require(".." not in parts, f"{label} must not contain parent traversal")

    flags = _directory_open_flags()
    try:
        current = os.open(os.sep, flags)
    except OSError as error:
        raise SupplyError("cannot open the filesystem root safely") from error
    try:
        for part in parts[1:]:
            try:
                following = os.open(part, flags, dir_fd=current)
            except OSError as error:
                raise SupplyError(
                    f"cannot open {label} without following symlinks: {path}"
                ) from error
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def _require_owned_directory(
    descriptor: int,
    path: Path,
    *,
    exact_private_mode: bool,
) -> None:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    require(stat.S_ISDIR(metadata.st_mode), f"private path is not a directory: {path}")
    require(
        metadata.st_uid == os.geteuid(),
        f"private directory has the wrong owner: {path}",
    )
    require(
        mode & 0o022 == 0,
        f"private directory is group or world writable: {path}",
    )
    if exact_private_mode:
        require(
            mode == PRIVATE_DIRECTORY_MODE,
            f"private directory must have mode 0700: {path}",
        )


def _open_private_directory(path: Path, repository_root: Path) -> int:
    """Create and hold a trusted repository-local private directory."""

    require(path.is_absolute(), f"private directory path must be absolute: {path}")
    try:
        relative = path.relative_to(repository_root)
    except ValueError as error:
        raise SupplyError(
            f"private directory escaped the repository: {path}"
        ) from error

    current = _open_absolute_directory(repository_root, "repository root")
    current_path = repository_root
    try:
        _require_owned_directory(current, current_path, exact_private_mode=False)
        for part in relative.parts:
            created = False
            try:
                os.mkdir(part, PRIVATE_DIRECTORY_MODE, dir_fd=current)
                created = True
            except FileExistsError:
                pass
            except OSError as error:
                raise SupplyError(f"cannot create private directory: {path}") from error
            if created:
                # Persist the new child name before it becomes a parent for a
                # later artifact or handoff publication.
                os.fsync(current)

            try:
                following = os.open(part, _directory_open_flags(), dir_fd=current)
            except OSError as error:
                raise SupplyError(
                    f"cannot open private directory without following symlinks: {path}"
                ) from error
            os.close(current)
            current = following
            current_path /= part
            # Fail rather than changing permissions on existing private state.
            # The shared `.local` root and every owned child must already be 0700.
            _require_owned_directory(
                current,
                current_path,
                exact_private_mode=True,
            )
        return current
    except Exception:
        os.close(current)
        raise


def _open_regular_at(
    parent: int,
    name: str,
    display_path: Path,
    label: str,
) -> tuple[int, os.stat_result]:
    """Open a regular file without blocking on special files or following links."""

    try:
        path_descriptor = os.open(name, _path_open_flags(), dir_fd=parent)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise SupplyError(f"cannot inspect {label} safely: {display_path}") from error

    try:
        path_metadata = os.fstat(path_descriptor)
        require(
            stat.S_ISREG(path_metadata.st_mode),
            f"{label} is not a regular file: {display_path}",
        )
        try:
            descriptor = os.open(name, _file_open_flags(), dir_fd=parent)
        except OSError as error:
            raise SupplyError(f"cannot open {label} safely: {display_path}") from error
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ):
            os.close(descriptor)
            raise SupplyError(f"{label} changed while it was opened: {display_path}")
        return descriptor, metadata
    finally:
        os.close(path_descriptor)


def _open_regular(path: Path, label: str) -> tuple[int, os.stat_result]:
    require(path.is_absolute(), f"{label} path must be absolute")
    require(path.name not in {"", ".", ".."}, f"{label} path is invalid")
    parent = _open_absolute_directory(path.parent, f"{label} parent")
    try:
        return _open_regular_at(parent, path.name, path, label)
    finally:
        os.close(parent)


def _hash_descriptor(descriptor: int, expected_size: int, label: str) -> str:
    # Read exactly the locked size. This bounds work even if another process
    # appends to the opened file while it is being checked.
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(READ_CHUNK_SIZE, remaining))
        require(bool(chunk), f"{label} ended before its locked size")
        digest.update(chunk)
        remaining -= len(chunk)
    require(os.read(descriptor, 1) == b"", f"{label} exceeds its locked size")
    return digest.hexdigest()


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        require(written > 0, "private file write made no progress")
        view = view[written:]


def _copy_and_hash(
    source: int,
    output: int,
    expected_size: int,
    label: str,
) -> str:
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        chunk = os.read(source, min(READ_CHUNK_SIZE, remaining))
        require(bool(chunk), f"{label} ended before its locked size")
        digest.update(chunk)
        _write_all(output, chunk)
        remaining -= len(chunk)
    require(os.read(source, 1) == b"", f"{label} exceeds its locked size")
    return digest.hexdigest()


def _verify_existing(
    parent: int,
    name: str,
    display_path: Path,
    expected_sha256: str,
    expected_size: int,
    source_metadata: os.stat_result | None = None,
) -> bool:
    try:
        descriptor, metadata = _open_regular_at(
            parent,
            name,
            display_path,
            "existing private output",
        )
    except FileNotFoundError:
        return False
    try:
        if source_metadata is not None:
            require(
                (metadata.st_dev, metadata.st_ino)
                != (source_metadata.st_dev, source_metadata.st_ino),
                "source and staged destination are the same file",
            )
        require(
            stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
            f"private file must have mode 0600: {display_path}",
        )
        require(
            metadata.st_size == expected_size,
            f"existing private file has the wrong size: {display_path}",
        )
        require(
            _hash_descriptor(descriptor, expected_size, "existing private file")
            == expected_sha256,
            f"existing private file differs from the lock: {display_path}",
        )
        return True
    finally:
        os.close(descriptor)


def _create_temporary(parent: int, target_name: str) -> tuple[int, str]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    require(nofollow != 0, "platform lacks safe temporary-file flags")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow
    for _ in range(100):
        name = f".{target_name}.{secrets.token_hex(8)}"
        try:
            descriptor = os.open(name, flags, PRIVATE_FILE_MODE, dir_fd=parent)
        except FileExistsError:
            continue
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        return descriptor, name
    raise SupplyError(f"cannot allocate a private temporary file for {target_name}")


def _unlink_temporary(parent: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=parent)
    except FileNotFoundError:
        return
    os.fsync(parent)


def _publish_temporary(
    parent: int,
    temporary_name: str,
    target_name: str,
    display_path: Path,
    expected_sha256: str,
    expected_size: int,
    source_metadata: os.stat_result | None = None,
) -> None:
    try:
        os.link(
            temporary_name,
            target_name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
    except FileExistsError:
        require(
            _verify_existing(
                parent,
                target_name,
                display_path,
                expected_sha256,
                expected_size,
                source_metadata,
            ),
            f"private output changed during publication: {display_path}",
        )
    else:
        # Make the new target name durable before the handoff can be published
        # as the readiness marker.
        os.fsync(parent)


def _publish_bytes(parent: int, name: str, display_path: Path, content: bytes) -> None:
    expected_sha256 = hashlib.sha256(content).hexdigest()
    expected_size = len(content)
    if _verify_existing(parent, name, display_path, expected_sha256, expected_size):
        return

    descriptor, temporary_name = _create_temporary(parent, name)
    try:
        try:
            _write_all(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _publish_temporary(
            parent,
            temporary_name,
            name,
            display_path,
            expected_sha256,
            expected_size,
        )
    finally:
        _unlink_temporary(parent, temporary_name)


def _stage_binary(
    source: int,
    source_metadata: os.stat_result,
    parent: int,
    name: str,
    display_path: Path,
    expected_sha256: str,
    expected_size: int,
) -> None:
    # Reuse is allowed only when both the staged output and the current source
    # still match the lock. This keeps repeated runs fail closed.
    if _verify_existing(
        parent,
        name,
        display_path,
        expected_sha256,
        expected_size,
        source_metadata,
    ):
        require(
            _hash_descriptor(source, expected_size, "K3s source binary")
            == expected_sha256,
            "K3s source binary does not match the lock",
        )
        return

    descriptor, temporary_name = _create_temporary(parent, name)
    try:
        try:
            # Hash the same descriptor that is copied. Reopening the source by
            # path here would reintroduce a check-use race.
            digest = _copy_and_hash(
                source,
                descriptor,
                expected_size,
                "K3s source binary",
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        require(digest == expected_sha256, "K3s source binary does not match the lock")
        _publish_temporary(
            parent,
            temporary_name,
            name,
            display_path,
            expected_sha256,
            expected_size,
            source_metadata,
        )
    finally:
        _unlink_temporary(parent, temporary_name)


def stage_supply(
    source: Path,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    lock_path: Path = LOCK_PATH,
) -> tuple[Path, Path]:
    """Stage one verified local K3s binary and publish the INIT handoff."""

    repository_root = repository_root.resolve(strict=True)
    lock = validate_lock(lock_path)
    expected_sha256 = cast(str, lock["k3s_binary"]["sha256"])
    expected_size = cast(int, lock["k3s_binary"]["size"])

    # Validate the caller-controlled source before creating repository state.
    source_descriptor, source_metadata = _open_regular(source, "K3s source binary")
    try:
        require(
            source_metadata.st_size == expected_size,
            "K3s source binary size does not match the lock",
        )

        destination = repository_root / STAGE_PATH
        handoff_path = repository_root / HANDOFF_PATH
        handoff = {
            "shell_k3s_version": lock["k3s_binary"]["version"],
            "shell_k3s_binary_path": str(destination),
            "shell_k3s_binary_sha256": expected_sha256,
            "shell_k3s_api_vip_image_repository": lock["kube_vip_image"]["repository"],
            "shell_k3s_api_vip_image_digest": lock["kube_vip_image"]["digest"],
        }
        rendered = (json.dumps(handoff, indent=2) + "\n").encode()

        # Reject a stale handoff before publishing a previously missing binary.
        handoff_parent = _open_private_directory(
            handoff_path.parent,
            repository_root,
        )
        try:
            handoff_exists = _verify_existing(
                handoff_parent,
                handoff_path.name,
                handoff_path,
                hashlib.sha256(rendered).hexdigest(),
                len(rendered),
            )

            stage_parent = _open_private_directory(
                destination.parent,
                repository_root,
            )
            try:
                binary_exists = _verify_existing(
                    stage_parent,
                    destination.name,
                    destination,
                    expected_sha256,
                    expected_size,
                    source_metadata,
                )
                require(
                    not handoff_exists or binary_exists,
                    "private handoff exists while staged binary is missing",
                )
                _stage_binary(
                    source_descriptor,
                    source_metadata,
                    stage_parent,
                    destination.name,
                    destination,
                    expected_sha256,
                    expected_size,
                )
                # The handoff is the readiness marker, so publish it only after
                # the binary exists and matches the lock.
                _publish_bytes(
                    handoff_parent,
                    handoff_path.name,
                    handoff_path,
                    rendered,
                )
            finally:
                os.close(stage_parent)
        finally:
            os.close(handoff_parent)
        return destination, handoff_path
    finally:
        os.close(source_descriptor)


def main(
    argv: list[str] | None = None,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    lock_path: Path = LOCK_PATH,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--k3s-binary", type=Path, metavar="ABSOLUTE_PATH")
    args = parser.parse_args(argv)
    try:
        if args.validate_only:
            # Validation is intentionally write-free. Real staging requires a
            # separately supplied absolute path to local artifact bytes.
            validate_lock(lock_path)
            print("validated TAR K3s runtime supply lock")
        else:
            destination, handoff = stage_supply(
                args.k3s_binary,
                repository_root=repository_root,
                lock_path=lock_path,
            )
            print(f"staged verified K3s binary: {destination}")
            print(f"published private INIT handoff: {handoff}")
        return 0
    except (SupplyError, OSError, UnicodeError) as error:
        print(f"TAR supply staging failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
