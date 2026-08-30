"""Small SOPS/age helpers for MAKE's private handoffs."""

from __future__ import annotations

import json
import os
import stat
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]


class SopsError(RuntimeError):
    """A private SOPS handoff failed its local safety checks."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SopsError(message)


def private_file(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    require(value.is_relative_to(ROOT), f"{label} must stay in the repository")
    require(value.is_file() and not value.is_symlink(), f"{label} is missing")
    require(stat.S_IMODE(value.stat().st_mode) == 0o600, f"{label} must be mode 0600")
    require(value.stat().st_uid == os.geteuid(), f"{label} has the wrong owner")
    current = value.parent
    while current != ROOT:
        require(not current.is_symlink(), f"{label} parent is symlinked")
        require(
            current.is_dir() and stat.S_IMODE(current.stat().st_mode) == 0o700,
            f"{label} parent must be mode 0700",
        )
        require(current.stat().st_uid == os.geteuid(), f"{label} parent owner changed")
        current = current.parent
    return value


def run(
    command: list[str],
    *,
    label: str,
    environment: dict[str, str],
    input_text: str | None = None,
) -> str:
    try:
        result = subprocess.run(  # nosec B603
            command,
            env=environment,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SopsError(f"{label} could not complete") from error
    if result.returncode:
        raise SopsError(f"{label} failed")
    return result.stdout


def decrypt_json(path: Path, age_key: Path) -> dict[str, Any]:
    ciphertext = private_file(path, "SOPS handoff")
    key = private_file(age_key, "SOPS age key")
    environment = os.environ.copy()
    environment["SOPS_AGE_KEY_FILE"] = str(key)
    raw = run(
        [
            "sops",
            "--decrypt",
            "--input-type",
            "json",
            "--output-type",
            "json",
            str(ciphertext),
        ],
        label="SOPS decrypt",
        environment=environment,
    )

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for name, item in pairs:
            require(name not in value, "duplicate JSON key in decrypted handoff")
            value[name] = item
        return value

    try:
        document = json.loads(raw, object_pairs_hook=reject)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SopsError("decrypted SOPS handoff is invalid JSON") from error
    require(isinstance(document, dict), "decrypted SOPS handoff is not an object")
    return cast(dict[str, Any], document)


def encrypt_json(document: dict[str, Any], output: Path, age_key: Path) -> None:
    """Encrypt one value-bearing handoff without exposing its contents."""

    output = Path(os.path.abspath(output))
    require(output.is_relative_to(ROOT), "SOPS output must stay in the repository")
    require(
        not output.exists() and not output.is_symlink(),
        "refusing to replace SOPS output",
    )
    directory = output.parent
    require(
        directory.is_dir() and not directory.is_symlink(),
        "SOPS output directory is missing",
    )
    require(
        stat.S_IMODE(directory.stat().st_mode) == 0o700,
        "SOPS output directory must be mode 0700",
    )
    require(
        directory.stat().st_uid == os.geteuid(),
        "SOPS output directory owner changed",
    )
    key = private_file(age_key, "SOPS age key")
    recipient = run(
        ["age-keygen", "-y", str(key)],
        label="age recipient derivation",
        environment=os.environ.copy(),
    ).strip()
    require(recipient.startswith("age1"), "age recipient is invalid")
    ciphertext = run(
        [
            "sops",
            "--encrypt",
            "--age",
            recipient,
            "--input-type",
            "json",
            "--output-type",
            "json",
            "/dev/stdin",
        ],
        label="SOPS encryption",
        environment=os.environ.copy(),
        input_text=json.dumps(document, separators=(",", ":")),
    )
    try:
        encrypted = json.loads(ciphertext)
    except json.JSONDecodeError as error:
        raise SopsError("SOPS encryption returned invalid JSON") from error
    require(isinstance(encrypted, dict) and "sops" in encrypted, "SOPS output is invalid")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=directory)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(ciphertext)
            stream.write("\n" if not ciphertext.endswith("\n") else "")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output, follow_symlinks=False)
        private_file(output, "encrypted SOPS output")
        directory_descriptor = os.open(
            directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise SopsError("SOPS encryption failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
