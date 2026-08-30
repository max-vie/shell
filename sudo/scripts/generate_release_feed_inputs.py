#!/usr/bin/env python3
"""Create encrypted release-feed bootstrap inputs after explicit approval."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any

import validate_stateful_inputs as contracts


ROOT = Path(__file__).resolve().parents[2]
APPROVAL = "environment-gcp/sudo/release-feed-inputs"
AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
INPUT_SET_NAME = "input-set"
INPUT_NAMES = ("harbor.sops.json", "release-feed.sops.json")


class InputGenerationError(RuntimeError):
    """SUDO refused to generate release-feed inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InputGenerationError(message)


def private_directory(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    require(value.is_relative_to(ROOT), f"{label} must remain inside the repository")
    require(value.is_dir() and not value.is_symlink(), f"{label} is missing")
    require(stat.S_IMODE(value.stat().st_mode) == 0o700, f"{label} must be mode 0700")
    require(value.stat().st_uid == os.geteuid(), f"{label} has the wrong owner")
    return value


def ensure_private_directory(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    require(value.is_relative_to(ROOT), f"{label} must remain inside the repository")
    current = ROOT
    for part in value.relative_to(ROOT).parts:
        current = current / part
        if current.exists() or current.is_symlink():
            require(not current.is_symlink() and current.is_dir(), f"{label} is unsafe")
            require(
                stat.S_IMODE(current.stat().st_mode) == 0o700
                and current.stat().st_uid == os.geteuid(),
                f"{label} parent must be owned and mode 0700",
            )
        else:
            current.mkdir(mode=0o700)
    return private_directory(value, label)


def private_file(path: Path, label: str, *, expected: Path | None = None) -> Path:
    value = Path(os.path.abspath(path))
    require(value.is_relative_to(ROOT), f"{label} must remain inside the repository")
    if expected is not None:
        require(value == Path(os.path.abspath(expected)), f"{label} path changed")
    require(value.is_file() and not value.is_symlink(), f"{label} is missing")
    require(stat.S_IMODE(value.stat().st_mode) == 0o600, f"{label} must be mode 0600")
    require(value.stat().st_uid == os.geteuid(), f"{label} has the wrong owner")
    private_directory(value.parent, f"{label} directory")
    return value


def run(command: list[str], *, label: str, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(  # nosec B603
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InputGenerationError(f"{label} could not complete") from error
    if result.returncode:
        raise InputGenerationError(f"{label} failed")
    return result.stdout


def recipient(age_key: Path) -> str:
    output = run(
        [
            "age-keygen",
            "-y",
            str(private_file(age_key, "SOPS age key", expected=AGE_KEY)),
        ],
        label="age recipient derivation",
    )
    value = output.strip()
    require(value.startswith("age1"), "age key did not produce an age recipient")
    return value


def stage_encrypted(payload: dict[str, Any], output: Path, age_key: Path) -> Path:
    private_directory(output.parent, "release-feed private directory")
    require(
        not output.exists() and not output.is_symlink(),
        f"refusing to replace {output.name}",
    )
    ciphertext = run(
        [
            "sops",
            "--encrypt",
            "--age",
            recipient(age_key),
            "--input-type",
            "json",
            "--output-type",
            "json",
            "/dev/stdin",
        ],
        label=f"encrypt {output.name}",
        input_text=json.dumps(payload, separators=(",", ":")),
    )
    try:
        document = json.loads(ciphertext)
    except json.JSONDecodeError as error:
        raise InputGenerationError(f"encrypted {output.name} is invalid") from error
    require(isinstance(document, dict) and "sops" in document, "SOPS output is invalid")
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=f".{output.name}.",
        delete=False,
    ) as staged:
        os.fchmod(staged.fileno(), stat.S_IRUSR | stat.S_IWUSR)
        staged.write(ciphertext)
        staged.write("\n" if not ciphertext.endswith("\n") else "")
        staged.flush()
        os.fsync(staged.fileno())
        return Path(staged.name)


def token() -> str:
    return secrets.token_urlsafe(32)


def generate(*, approval: str, age_key: Path = AGE_KEY) -> list[Path]:
    require(approval == APPROVAL, f"approval must be {APPROVAL}")
    contracts.validate_release_feed()
    directory = ensure_private_directory(
        ROOT / ".local/sudo/release-feed",
        "release-feed private directory",
    )
    input_set = directory / INPUT_SET_NAME
    require(
        not input_set.exists() and not input_set.is_symlink(),
        "refusing to replace release-feed input set",
    )
    staging_directory = Path(
        tempfile.mkdtemp(prefix=f".{INPUT_SET_NAME}.", dir=directory)
    )
    staging_directory.chmod(0o700)
    staging_paths = [staging_directory / name for name in INPUT_NAMES]
    payloads = [
        {
            "admin_password": token(),
            "core_key": token(),
            "core_xsrf_key": token(),
            "jobservice_secret": token(),
            "registry_http_secret": token(),
            "database_password": token(),
            "registry_username": "harbor_registry",
            "registry_password": token(),
        },
        {"read_token": token(), "write_token": token()},
    ]
    staged_sources: list[Path] = []
    renamed = False
    try:
        for payload, path in zip(payloads, staging_paths, strict=True):
            staged_sources.append(stage_encrypted(payload, path, age_key))
        for source, destination in zip(staged_sources, staging_paths, strict=True):
            os.link(source, destination, follow_symlinks=False)
            source.unlink()
        descriptor = os.open(
            staging_directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(staging_directory, input_set)
        renamed = True
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        cleanup_root = input_set if renamed else staging_directory
        for name in INPUT_NAMES:
            path = cleanup_root / name
            path.unlink(missing_ok=True)
        for path in staged_sources:
            path.unlink(missing_ok=True)
        cleanup_root.rmdir()
        raise InputGenerationError("release-feed input publication failed") from error
    finally:
        for path in staged_sources:
            path.unlink(missing_ok=True)
    return [input_set / name for name in INPUT_NAMES]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--age-key", type=Path, default=AGE_KEY)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check_only:
            contracts.validate_release_feed()
            contracts.validate_openbao()
            print("validated release-feed input generation contracts")
        else:
            for path in generate(
                approval=args.approval,
                age_key=args.age_key,
            ):
                print(f"created {path.relative_to(ROOT)}")
    except (OSError, InputGenerationError, contracts.StatefulInputError) as error:
        print(f"SUDO release-feed input generation refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
