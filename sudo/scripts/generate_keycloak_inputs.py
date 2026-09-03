#!/usr/bin/env python3
"""Create encrypted Keycloak runtime inputs after explicit approval."""

from __future__ import annotations

import argparse
import os
import secrets
import string
import sys
from pathlib import Path
from typing import Callable

import generate_freeipa_inputs as encrypted
import validate_access_contracts as contracts


ROOT = Path(__file__).resolve().parents[2]
APPROVAL = "environment-gcp/sudo/keycloak-inputs"
PRIVATE_ROOT = ROOT / ".local/sudo/keycloak"
AGE_KEY = PRIVATE_ROOT / "age-key.txt"
OUTPUT = PRIVATE_ROOT / "keycloak.sops.json"
PASSWORD_ALPHABET = string.ascii_letters + string.digits
REQUIRED_KEYS = (
    "database_username",
    "database_password",
    "bootstrap_admin_username",
    "bootstrap_admin_password",
    "ldap_bind_password",
)


class KeycloakInputError(RuntimeError):
    """SUDO refused to create Keycloak runtime inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KeycloakInputError(message)


def password(length: int = 48) -> str:
    require(length > 0, "password length must be positive")
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


def generate(
    *,
    approval: str,
    repository_root: Path = ROOT,
    age_key: Path | None = None,
    output: Path | None = None,
    rotate: bool = False,
    run_command: Callable[..., str] = encrypted.run,
) -> Path:
    require(approval == APPROVAL, f"approval must be {APPROVAL}")
    documents = contracts.validate_contracts(repository_root)
    profile = documents["keycloak"]
    private_root = encrypted.ensure_private_directory(
        repository_root / ".local/sudo/keycloak",
        repository_root,
        "Keycloak private directory",
    )
    expected_age_key = private_root / "age-key.txt"
    expected_output = private_root / "keycloak.sops.json"
    age_key = Path(os.path.abspath(age_key or expected_age_key))
    output = Path(os.path.abspath(output or expected_output))
    require(age_key == expected_age_key, "Keycloak age-key path changed")
    require(output == expected_output, "Keycloak input path changed")
    encrypted.private_file(age_key, repository_root, "Keycloak SOPS/age key")
    require(not output.is_symlink(), "Keycloak input must not be a symlink")
    require(rotate or not output.exists(), "Keycloak input exists; pass --rotate")

    keycloak_profile = profile["identity"]
    require(
        keycloak_profile["bind_principal"] == "keycloak-bind",
        "Keycloak bind principal changed",
    )
    payload = {
        "database_username": "keycloak",
        "database_password": password(),
        "bootstrap_admin_username": "sso-bootstrap",
        "bootstrap_admin_password": password(),
        "ldap_bind_password": password(),
    }
    require(tuple(payload) == REQUIRED_KEYS, "Keycloak input keys changed")

    temporary = encrypted.stage_encrypted(
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
                raise KeycloakInputError(
                    "Keycloak input appeared during publication"
                ) from error
            temporary.unlink()
        output.chmod(encrypted.PRIVATE_FILE_MODE)
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
            print("validated Keycloak input generation contract")
            return 0
        path = generate(
            approval=args.approval,
            age_key=args.age_key,
            rotate=args.rotate,
        )
        print(f"created {path.relative_to(ROOT)}")
        return 0
    except (OSError, KeycloakInputError, contracts.AccessContractError) as error:
        print(f"SUDO Keycloak input generation refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
