#!/usr/bin/env python3
"""Create the protected Cosign trust handoffs after explicit approval."""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Callable

SCRIPT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_ROOT))
TAR_SCRIPTS = SCRIPT_ROOT.parents[1] / "tar/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))

import generate_freeipa_inputs as encrypted  # noqa: E402
import validate_access_contracts as contracts  # noqa: E402
import validate_kubernetes_supply as supply  # noqa: E402


ROOT = SCRIPT_ROOT.parents[1]
APPROVAL = "environment-gcp/sudo/cosign-key-generation"
PRIVATE_ROOT = ROOT / ".local/sudo/kubernetes/cosign"
AGE_KEY = PRIVATE_ROOT / "age-key.txt"
PRIVATE_OUTPUT = PRIVATE_ROOT / "cosign.sops.json"
PUBLIC_OUTPUT = PRIVATE_ROOT / "cosign-public.sops.json"
COSIGN_BINARY = ROOT / ".local/tar/kubernetes/tools/cosign"
PRIVATE_FILE_MODE = 0o600
EXECUTABLE_MODE = 0o700
PEM = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9][A-Z0-9 ]*)-----\r?\n.+?\r?\n"
    r"-----END (?P=label)-----\r?\n?\Z",
    re.DOTALL,
)


class CosignInputError(RuntimeError):
    """SUDO refused to create Cosign trust inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CosignInputError(message)


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> str:
    try:
        completed = subprocess.run(  # nosec B603
            command,
            input=input_text,
            env=environment or os.environ.copy(),
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CosignInputError(f"{command[0]} could not complete") from error
    if completed.returncode:
        raise CosignInputError(f"{command[0]} failed")
    return completed.stdout


def require_pem(value: str, label: str, expected: str) -> None:
    match = PEM.fullmatch(value)
    require(
        match is not None
        and (
            match.group("label") == expected
            or (
                expected == "PRIVATE KEY"
                and match.group("label").endswith(" PRIVATE KEY")
            )
        ),
        f"{label} is not a complete {expected} PEM block",
    )


def require_cosign_binary(path: Path, repository_root: Path) -> Path:
    require(path == COSIGN_BINARY, "Cosign binary path changed")
    require(path.is_file() and not path.is_symlink(), "staged Cosign binary is missing")
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), "staged Cosign binary has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == EXECUTABLE_MODE,
        "staged Cosign binary must be mode 0700",
    )
    lock = supply.validate_public()
    tool = lock["tools"]["cosign"]
    require(metadata.st_size == tool["size"], "staged Cosign binary size changed")
    digest = supply.sha256_file(path)
    require(digest == tool["source_sha256"], "staged Cosign binary checksum changed")
    require(path.is_relative_to(repository_root), "staged Cosign binary escaped the repository")
    return path


def key_pair(
    cosign: Path,
    password: str,
    *,
    run_command: Callable[..., str],
) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="shell-cosign-") as directory:
        work = Path(directory)
        run_command(
            [str(cosign), "generate-key-pair"],
            cwd=work,
            environment={**os.environ, "COSIGN_PASSWORD": password},
        )
        private = work / "cosign.key"
        public = work / "cosign.pub"
        require(private.is_file() and public.is_file(), "Cosign did not create a key pair")
        private_value = private.read_text(encoding="ascii")
        public_value = public.read_text(encoding="ascii")
        require_pem(private_value, "Cosign private key", "PRIVATE KEY")
        require_pem(public_value, "Cosign public key", "PUBLIC KEY")
        return private_value, public_value


def publish(
    temporary: Path,
    output: Path,
    *,
    rotate: bool,
) -> None:
    require(not output.is_symlink(), "Cosign trust output must not be a symlink")
    if rotate:
        os.replace(temporary, output)
    else:
        try:
            os.link(temporary, output, follow_symlinks=False)
        except FileExistsError as error:
            raise CosignInputError("Cosign trust output appeared during publication") from error
        temporary.unlink()
    output.chmod(PRIVATE_FILE_MODE)


def generate(
    *,
    approval: str,
    repository_root: Path = ROOT,
    age_key: Path | None = None,
    cosign: Path | None = None,
    rotate: bool = False,
    run_command: Callable[..., str] = run,
) -> tuple[Path, Path]:
    require(approval == APPROVAL, f"approval must be {APPROVAL}")
    contracts.validate_contracts(repository_root)
    supply.validate_public()
    private_root = encrypted.ensure_private_directory(
        repository_root / ".local/sudo/kubernetes/cosign",
        repository_root,
        "Cosign private directory",
    )
    expected_age_key = private_root / "age-key.txt"
    expected_private = private_root / "cosign.sops.json"
    expected_public = private_root / "cosign-public.sops.json"
    age_key = Path(os.path.abspath(age_key or expected_age_key))
    cosign = Path(os.path.abspath(cosign or COSIGN_BINARY))
    require(age_key == expected_age_key, "Cosign age-key path changed")
    require(cosign == COSIGN_BINARY, "Cosign binary path changed")
    encrypted.private_file(age_key, repository_root, "Cosign SOPS/age key")
    require_cosign_binary(cosign, repository_root)
    for output in (expected_private, expected_public):
        require(not output.is_symlink(), "Cosign trust output must not be a symlink")
        require(rotate or not output.exists(), "Cosign trust output exists; pass --rotate")

    password = encrypted.password(48)
    private_value, public_value = key_pair(
        cosign,
        password,
        run_command=run_command,
    )
    private_temporary = encrypted.stage_encrypted(
        {"private_key": private_value, "password": password, "public_key": public_value},
        expected_private,
        age_key,
        run_command=run_command,
    )
    public_temporary = encrypted.stage_encrypted(
        {"public_key": public_value},
        expected_public,
        age_key,
        run_command=run_command,
    )
    try:
        publish(private_temporary, expected_private, rotate=rotate)
        publish(public_temporary, expected_public, rotate=rotate)
    finally:
        private_temporary.unlink(missing_ok=True)
        public_temporary.unlink(missing_ok=True)
    return expected_private, expected_public


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--age-key", type=Path, default=AGE_KEY)
    parser.add_argument("--cosign", type=Path, default=COSIGN_BINARY)
    parser.add_argument("--rotate", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check_only:
            contracts.validate_contracts(ROOT)
            supply.validate_public()
            print("validated Cosign trust input contract")
            return 0
        private, public = generate(
            approval=args.approval,
            age_key=args.age_key,
            cosign=args.cosign,
            rotate=args.rotate,
        )
        print(f"created Cosign trust handoffs: {private.name}, {public.name}")
        return 0
    except (OSError, CosignInputError, contracts.AccessContractError, supply.SupplyError) as error:
        print(f"SUDO Cosign trust generation refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
