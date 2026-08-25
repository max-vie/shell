#!/usr/bin/env python3
"""Validate and create the two private K3s server-token handoffs."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPOSITORY_ROOT / "sudo/secrets/k3s-server-token-contract.json"
TOKEN_RE = re.compile(r"^[0-9a-f]{64}\n$")
TOKEN_BYTES = 32
TOKEN_LENGTH = 64
SERVER_TOKEN_FILE = "server-token"
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600

EXPECTED_TOP_LEVEL = {
    "schema_version",
    "contract_version",
    "contract_id",
    "policy_owner",
    "consumer_owner",
    "proof_status",
    "token",
    "storage",
    "clusters",
}
EXPECTED_TOKEN = {
    "type": "server",
    "format": "short-password",
    "purpose": "initial-self-signed-ca-bootstrap",
    "random_bytes": TOKEN_BYTES,
    "encoding": "lowercase-hex",
    "encoded_length": TOKEN_LENGTH,
    "trailing_newline": True,
}
EXPECTED_STORAGE = {
    "root": ".local/sudo/k3s",
    "directory_mode": "0700",
    "file_mode": "0600",
    "owner": "current-user",
    "ignored": True,
    "publication": "create-only",
    "rotation": "manual",
}
EXPECTED_CLUSTERS = {
    "gcp": {
        "inventory_group": "gcp_k3s_servers",
        "token_path": f".local/sudo/k3s/gcp/{SERVER_TOKEN_FILE}",
    },
    "proxmox": {
        "inventory_group": "proxmox_k3s_servers",
        "token_path": f".local/sudo/k3s/proxmox/{SERVER_TOKEN_FILE}",
    },
}


class TokenContractError(ValueError):
    """A server-token contract or private handoff is unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TokenContractError(message)


def _read_json_object(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TokenContractError(f"invalid JSON file: {path}") from error
    require(isinstance(value, dict), f"JSON value must be an object: {path}")
    return cast(dict[str, Any], value)


def validate_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    """Validate the public token policy without reading private state."""

    contract = _read_json_object(path)
    require(set(contract) == EXPECTED_TOP_LEVEL, "server-token contract shape changed")
    require(contract["schema_version"] == "1.0", "unsupported server-token schema")
    require(contract["contract_version"] == "1.0.0", "unsupported server-token version")
    require(
        contract["contract_id"] == "k3s-server-token-contract",
        "unexpected server-token contract ID",
    )
    require(contract["policy_owner"] == "sudo", "SUDO must own server-token policy")
    require(
        contract["consumer_owner"] == "init",
        "INIT must consume the server-token handoff",
    )
    require(
        contract["proof_status"] == "source-only", "invalid server-token proof status"
    )

    token = contract["token"]
    require(isinstance(token, dict), "token policy must be an object")
    require(token == EXPECTED_TOKEN, "token policy changed")

    storage = contract["storage"]
    require(isinstance(storage, dict), "token storage policy must be an object")
    require(storage == EXPECTED_STORAGE, "token storage policy changed")

    clusters = contract["clusters"]
    require(isinstance(clusters, dict), "cluster token map must be an object")
    require(clusters == EXPECTED_CLUSTERS, "cluster token map changed")
    for cluster, values in clusters.items():
        require(cluster in {"gcp", "proxmox"}, "unexpected K3s cluster")
        require(isinstance(values, dict), f"token values must be an object: {cluster}")
        token_path = values["token_path"]
        require(
            isinstance(token_path, str)
            and token_path.startswith(".local/sudo/k3s/")
            and ".." not in Path(token_path).parts,
            f"token path escaped private state: {cluster}",
        )
    return contract


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    require(nofollow != 0 and directory != 0, "platform lacks safe directory flags")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _path_flags() -> int:
    path_only = getattr(os, "O_PATH", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    require(path_only != 0 and nofollow != 0, "platform lacks safe path flags")
    return path_only | os.O_CLOEXEC | nofollow


def _file_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    require(nofollow != 0 and nonblock != 0, "platform lacks safe file flags")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | nonblock


def _open_absolute_directory(path: Path, label: str) -> int:
    require(path.is_absolute(), f"{label} must be absolute")
    parts = path.parts
    require(bool(parts) and parts[0] == os.sep, f"{label} must start at root")
    require(".." not in parts, f"{label} contains parent traversal")
    try:
        current = os.open(os.sep, _directory_flags())
    except OSError as error:
        raise TokenContractError("cannot open the filesystem root safely") from error
    try:
        for part in parts[1:]:
            try:
                following = os.open(part, _directory_flags(), dir_fd=current)
            except OSError as error:
                raise TokenContractError(
                    f"cannot open {label} without following symlinks: {path}"
                ) from error
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def _require_directory(descriptor: int, path: Path) -> None:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    require(stat.S_ISDIR(metadata.st_mode), f"private path is not a directory: {path}")
    require(
        metadata.st_uid == os.geteuid(), f"private path has the wrong owner: {path}"
    )
    require(mode == PRIVATE_DIRECTORY_MODE, f"private path must have mode 0700: {path}")


def _open_private_directory(path: Path, repository_root: Path) -> int:
    require(path.is_absolute(), f"private directory must be absolute: {path}")
    try:
        relative = path.relative_to(repository_root)
    except ValueError as error:
        raise TokenContractError(f"private path escaped repository: {path}") from error

    current = _open_absolute_directory(repository_root, "repository root")
    current_path = repository_root
    try:
        root_metadata = os.fstat(current)
        require(
            stat.S_ISDIR(root_metadata.st_mode), "repository root is not a directory"
        )
        require(
            root_metadata.st_uid == os.geteuid(), "repository root has the wrong owner"
        )
        require(
            stat.S_IMODE(root_metadata.st_mode) & 0o022 == 0,
            "repository root is writable by group or world",
        )
        for part in relative.parts:
            created = False
            try:
                os.mkdir(part, PRIVATE_DIRECTORY_MODE, dir_fd=current)
                created = True
            except FileExistsError:
                pass
            except OSError as error:
                raise TokenContractError(
                    f"cannot create private directory: {path}"
                ) from error
            if created:
                os.fsync(current)
            try:
                following = os.open(part, _directory_flags(), dir_fd=current)
            except OSError as error:
                raise TokenContractError(
                    f"cannot open private directory without following symlinks: {path}"
                ) from error
            os.close(current)
            current = following
            current_path /= part
            _require_directory(current, current_path)
        return current
    except Exception:
        os.close(current)
        raise


def _open_regular_at(parent: int, name: str, path: Path) -> tuple[int, os.stat_result]:
    try:
        path_descriptor = os.open(name, _path_flags(), dir_fd=parent)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise TokenContractError(
            f"cannot inspect private token safely: {path}"
        ) from error
    try:
        path_metadata = os.fstat(path_descriptor)
        require(
            stat.S_ISREG(path_metadata.st_mode),
            f"private token is not a regular file: {path}",
        )
        try:
            descriptor = os.open(name, _file_flags(), dir_fd=parent)
        except OSError as error:
            raise TokenContractError(
                f"cannot open private token safely: {path}"
            ) from error
        metadata = os.fstat(descriptor)
        require(
            (metadata.st_dev, metadata.st_ino)
            == (path_metadata.st_dev, path_metadata.st_ino),
            f"private token changed while opening: {path}",
        )
        return descriptor, metadata
    finally:
        os.close(path_descriptor)


def _read_existing_token(parent: int, name: str, path: Path) -> str | None:
    try:
        descriptor, metadata = _open_regular_at(parent, name, path)
    except FileNotFoundError:
        return None
    try:
        require(
            stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
            f"private token must have mode 0600: {path}",
        )
        require(
            metadata.st_size == TOKEN_LENGTH + 1,
            f"private token has the wrong size: {path}",
        )
        value = os.read(descriptor, TOKEN_LENGTH + 1)
        require(
            os.read(descriptor, 1) == b"",
            f"private token is larger than expected: {path}",
        )
        text = value.decode("ascii")
        require(
            TOKEN_RE.fullmatch(text) is not None,
            f"private token format is invalid: {path}",
        )
        return text
    except UnicodeError as error:
        raise TokenContractError(f"private token format is invalid: {path}") from error
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        require(written > 0, "private token write made no progress")
        view = view[written:]


def _publish_token(parent: int, name: str, path: Path, content: bytes) -> None:
    existing = _read_existing_token(parent, name, path)
    require(existing is None, f"private token already exists: {path}")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    require(nofollow != 0, "platform lacks safe temporary-file flags")
    temporary_name = f".{name}.{secrets.token_hex(8)}"
    descriptor = os.open(
        temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow,
        PRIVATE_FILE_MODE,
        dir_fd=parent,
    )
    try:
        try:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            _write_all(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise TokenContractError(
                f"private token appeared during publication: {path}"
            ) from error
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.fsync(parent)


def generate_tokens(
    *,
    repository_root: Path = REPOSITORY_ROOT,
    contract_path: Path = CONTRACT_PATH,
) -> tuple[Path, Path]:
    """Generate both cluster tokens and publish them without replacement."""

    repository_root = repository_root.resolve(strict=True)
    contract = validate_contract(contract_path)
    cluster_paths = {
        cluster: repository_root / values["token_path"]
        for cluster, values in cast(
            dict[str, dict[str, str]], contract["clusters"]
        ).items()
    }
    parents: dict[str, int] = {}
    try:
        for cluster, path in cluster_paths.items():
            parents[cluster] = _open_private_directory(path.parent, repository_root)
        existing = {
            cluster: _read_existing_token(
                parent, cluster_paths[cluster].name, cluster_paths[cluster]
            )
            for cluster, parent in parents.items()
        }
        if all(value is not None for value in existing.values()):
            require(
                len({cast(str, value) for value in existing.values()}) == 2,
                "existing server tokens must not be equal",
            )
            return cluster_paths["gcp"], cluster_paths["proxmox"]
        require(
            not any(value is not None for value in existing.values()),
            "partial server-token state requires manual recovery",
        )

        tokens = [secrets.token_hex(TOKEN_BYTES), secrets.token_hex(TOKEN_BYTES)]
        require(tokens[0] != tokens[1], "generated server tokens must be independent")
        rendered = {
            cluster: f"{token}\n".encode("ascii")
            for cluster, token in zip(("gcp", "proxmox"), tokens)
        }
        for cluster in ("gcp", "proxmox"):
            _publish_token(
                parents[cluster],
                cluster_paths[cluster].name,
                cluster_paths[cluster],
                rendered[cluster],
            )
        return cluster_paths["gcp"], cluster_paths["proxmox"]
    finally:
        for descriptor in parents.values():
            os.close(descriptor)


def main(
    argv: list[str] | None = None,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    contract_path: Path = CONTRACT_PATH,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--generate", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.validate_only:
            validate_contract(contract_path)
            print("validated K3s server-token contract")
        else:
            gcp_path, proxmox_path = generate_tokens(
                repository_root=repository_root,
                contract_path=contract_path,
            )
            print(f"validated private server-token paths: {gcp_path}, {proxmox_path}")
        return 0
    except (TokenContractError, OSError, UnicodeError) as error:
        print(f"SUDO server-token operation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
