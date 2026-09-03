#!/usr/bin/env python3
"""Create encrypted FreeIPA bootstrap inputs after explicit approval."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import string
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Callable

import validate_access_contracts as contracts


ROOT = Path(__file__).resolve().parents[2]
APPROVAL = "environment-gcp/sudo/freeipa-inputs"
PRIVATE_ROOT = ROOT / ".local/sudo/identity"
AGE_KEY = PRIVATE_ROOT / "age-key.txt"
OUTPUT = PRIVATE_ROOT / "freeipa.sops.json"
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
REQUIRED_KEYS = (
    "directory_manager_password",
    "admin_password",
    "proof_operator_password",
    "proof_denied_password",
)
PASSWORD_ALPHABET = string.ascii_letters + string.digits


class FreeIPAInputError(RuntimeError):
    """SUDO refused to create FreeIPA bootstrap inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FreeIPAInputError(message)


def private_directory(path: Path, root: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    require(path.is_relative_to(root), f"{label} escaped the repository")
    require(path.is_dir() and not path.is_symlink(), f"{label} is missing")
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE,
        f"{label} must be mode 0700",
    )
    return path


def ensure_private_directory(path: Path, root: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    require(path.is_relative_to(root), f"{label} escaped the repository")
    current = root
    for part in path.relative_to(root).parts:
        current /= part
        if current.exists() or current.is_symlink():
            require(not current.is_symlink() and current.is_dir(), f"{label} is unsafe")
            metadata = current.stat()
            require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
            require(
                stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE,
                f"{label} parent must be mode 0700",
            )
        else:
            current.mkdir(mode=PRIVATE_DIRECTORY_MODE)
    return private_directory(path, root, label)


def private_file(path: Path, root: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    require(path.is_relative_to(root), f"{label} escaped the repository")
    require(path.is_file() and not path.is_symlink(), f"{label} is missing")
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
        f"{label} must be mode 0600",
    )
    private_directory(path.parent, root, f"{label} directory")
    return path


def run(
    command: list[str],
    *,
    input_text: str | None = None,
) -> str:
    try:
        completed = subprocess.run(  # nosec B603
            command,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FreeIPAInputError(f"{command[0]} could not complete") from error
    if completed.returncode:
        raise FreeIPAInputError(f"{command[0]} failed")
    return completed.stdout


def recipient(age_key: Path, run_command: Callable[..., str]) -> str:
    value = run_command(["age-keygen", "-y", str(age_key)]).strip()
    require(value.startswith("age1"), "age key did not produce a recipient")
    return value


def stage_encrypted(
    payload: dict[str, str],
    output: Path,
    age_key: Path,
    *,
    run_command: Callable[..., str],
) -> Path:
    ciphertext = run_command(
        [
            "sops",
            "--encrypt",
            "--age",
            recipient(age_key, run_command),
            "--input-type",
            "json",
            "--output-type",
            "json",
            "/dev/stdin",
        ],
        input_text=json.dumps(payload, separators=(",", ":")),
    )
    try:
        document = json.loads(ciphertext)
    except json.JSONDecodeError as error:
        raise FreeIPAInputError("SOPS output is not valid JSON") from error
    require(
        isinstance(document, dict) and isinstance(document.get("sops"), dict),
        "SOPS output is invalid",
    )
    require(
        all(value not in ciphertext for value in payload.values()),
        "SOPS output contains plaintext password material",
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(ciphertext)
            if not ciphertext.endswith("\n"):
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def password(length: int) -> str:
    require(length > 0, "password length must be positive")
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


def generate(
    *,
    approval: str,
    repository_root: Path = ROOT,
    age_key: Path | None = None,
    output: Path | None = None,
    rotate: bool = False,
    run_command: Callable[..., str] = run,
) -> Path:
    require(approval == APPROVAL, f"approval must be {APPROVAL}")
    documents = contracts.validate_contracts(repository_root)
    profile = documents["freeipa"]
    private_root = ensure_private_directory(
        repository_root / ".local/sudo/identity",
        repository_root,
        "FreeIPA private directory",
    )
    expected_age_key = private_root / "age-key.txt"
    expected_output = private_root / "freeipa.sops.json"
    age_key = Path(os.path.abspath(age_key or expected_age_key))
    output = Path(os.path.abspath(output or expected_output))
    require(age_key == expected_age_key, "FreeIPA age-key path changed")
    require(output == expected_output, "FreeIPA input path changed")
    private_file(age_key, repository_root, "FreeIPA SOPS/age key")
    require(not output.is_symlink(), "FreeIPA input must not be a symlink")
    require(rotate or not output.exists(), "FreeIPA input exists; pass --rotate")

    secret_contract = profile["secret_contract"]
    require(
        secret_contract["required_keys"] == list(REQUIRED_KEYS),
        "FreeIPA secret keys changed",
    )
    constraints = secret_contract["constraints"]
    payload = {
        name: password(24 if name == "directory_manager_password" else 32)
        for name in REQUIRED_KEYS
    }
    for name, value in payload.items():
        constraint = constraints[name]
        require(
            constraint["min_length"] <= len(value) <= constraint["max_length"]
            and all(character in PASSWORD_ALPHABET for character in value),
            f"generated {name} violates its contract",
        )

    temporary = stage_encrypted(
        payload,
        output,
        age_key,
        run_command=run_command,
    )
    try:
        if rotate:
            os.replace(temporary, output)
        else:
            try:
                os.link(temporary, output, follow_symlinks=False)
            except FileExistsError as error:
                raise FreeIPAInputError(
                    "FreeIPA input appeared during publication"
                ) from error
            temporary.unlink()
        output.chmod(PRIVATE_FILE_MODE)
        descriptor = os.open(
            output.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--age-key", type=Path, default=AGE_KEY)
    parser.add_argument("--rotate", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check_only:
            contracts.validate_contracts(ROOT)
            print("validated FreeIPA input generation contract")
            return 0
        path = generate(
            approval=args.approval,
            age_key=args.age_key,
            rotate=args.rotate,
        )
        print(f"created {path.relative_to(ROOT)}")
        return 0
    except (OSError, FreeIPAInputError, contracts.AccessContractError) as error:
        print(f"SUDO FreeIPA input generation refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
