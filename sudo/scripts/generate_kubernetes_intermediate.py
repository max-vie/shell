#!/usr/bin/env python3
"""Generate one SUDO-owned Kubernetes intermediate CA handoff.

The offline root key stays outside the repository. This command signs one
cluster intermediate, encrypts its certificate and key with SOPS/age, and
publishes only private local outputs. The tracked root certificate is public
trust data and is never replaced by this command.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_ROOT_CERTIFICATE = REPOSITORY_ROOT / "sudo/pki/shell-offline-root.crt.pem"
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
CLUSTERS = ("gcp", "proxmox")
PEM_BLOCK = re.compile(
    r"\A-----BEGIN (?P<label>[A-Z0-9][A-Z0-9 ]*)-----\r?\n"
    r".+?\r?\n-----END (?P=label)-----\r?\n?\Z",
    re.DOTALL,
)


class GenerationError(RuntimeError):
    """A Kubernetes intermediate cannot be generated safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GenerationError(message)


def require_pem(value: str, label: str, expected_label: str) -> None:
    match = PEM_BLOCK.fullmatch(value)
    require(
        match is not None
        and (
            match.group("label") == expected_label
            or (
                expected_label == "PRIVATE KEY"
                and match.group("label").endswith(" PRIVATE KEY")
            )
        ),
        f"{label} is not a complete {expected_label} PEM block",
    )


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
) -> str:
    """Run a local crypto or encryption command without printing payloads."""

    completed = subprocess.run(  # nosec B603
        command,
        input=input_text,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip().splitlines()
        suffix = detail[-1] if detail else f"exit {completed.returncode}"
        raise GenerationError(f"{command[0]} failed: {suffix}")
    return completed.stdout


def cluster_paths(repository_root: Path, cluster: str) -> dict[str, Path]:
    if cluster not in CLUSTERS:
        raise GenerationError("cluster must be one of: gcp, proxmox")
    private_root = repository_root / ".local/sudo/kubernetes"
    return {
        "private_root": private_root,
        "cluster_root": private_root / cluster,
        "root_key": private_root / "pki/shell-offline-root-ca.key.pem",
        "root_certificate": repository_root / "sudo/pki/shell-offline-root.crt.pem",
        "age_key": private_root / "age-key.txt",
        "intermediate_key": private_root / cluster / "shell-cluster-intermediate-ca.key.pem",
        "intermediate_certificate": private_root / cluster / "shell-cluster-intermediate.crt.pem",
        "handoff": private_root
        / cluster
        / "cluster-intermediate.sops.json",
    }


def _check_repository_path(path: Path, repository_root: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    repository_root = Path(os.path.abspath(repository_root))
    require(not repository_root.is_symlink(), "repository root must not be a symlink")
    try:
        relative = path.relative_to(repository_root)
    except ValueError as error:
        raise GenerationError(f"{label} escaped the repository") from error
    current = repository_root
    for component in relative.parts:
        current /= component
        require(not current.is_symlink(), f"{label} contains a symlink: {current}")
    return path


def _check_no_symlink_components(path: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        require(not current.is_symlink(), f"{label} contains a symlink: {current}")
    return path


def ensure_private_directory(
    path: Path, label: str, *, repository_root: Path = REPOSITORY_ROOT
) -> None:
    path = _check_repository_path(path, repository_root, label)
    repository_root = Path(os.path.abspath(repository_root))
    relative = path.relative_to(repository_root)
    require(bool(relative.parts), f"{label} must be below the repository root")
    current = repository_root
    for component in relative.parts:
        current /= component
        try:
            current.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            pass
        require(not current.is_symlink(), f"{label} contains a symlink: {current}")
        require(current.is_dir(), f"{label} must be a directory")
        require(current.stat().st_uid == os.geteuid(), f"{label} has the wrong owner")
        require(
            stat.S_IMODE(current.stat().st_mode) == PRIVATE_DIRECTORY_MODE,
            f"{label} must have mode 0700",
        )


def require_private_file(
    path: Path,
    label: str,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    within_repository: bool = False,
) -> None:
    path = (
        _check_repository_path(path, repository_root, label)
        if within_repository
        else _check_no_symlink_components(path, label)
    )
    require(not path.is_symlink() and path.is_file(), f"{label} must be a regular file")
    require(path.stat().st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(path.stat().st_mode) == PRIVATE_FILE_MODE,
        f"{label} must have mode 0600",
    )


def require_public_file(
    path: Path, label: str, *, repository_root: Path = REPOSITORY_ROOT
) -> None:
    path = _check_repository_path(path, repository_root, label)
    require(not path.is_symlink() and path.is_file(), f"{label} must be a regular file")


def require_replaceable(path: Path, rotate: bool, label: str) -> None:
    require(not path.is_symlink(), f"{label} must not be a symlink")
    require(rotate or not path.exists(), f"{label} exists; pass --rotate to replace it")


def handoff_payload(
    *,
    cluster: str,
    certificate: str,
    private_key: str,
    root_ca: str,
) -> str:
    """Build the short-lived JSON plaintext consumed by MAKE."""

    require(cluster in CLUSTERS, "cluster must be one of: gcp, proxmox")
    for label, value in (
        ("intermediate certificate", certificate),
        ("intermediate private key", private_key),
        ("root certificate", root_ca),
    ):
        expected = "PRIVATE KEY" if label == "intermediate private key" else "CERTIFICATE"
        require_pem(value, label, expected)
    return json.dumps(
        {
            "schema_version": "1.0",
            "contract_id": "kubernetes-ecosystem-input-contract",
            "cluster": cluster,
            "issuer": "shell-cluster-intermediate",
            "cluster_intermediate": {
                "certificate": certificate,
                "private_key": private_key,
                "root_ca": root_ca,
            },
        },
        indent=2,
    ) + "\n"


def _write_private(path: Path, contents: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(PRIVATE_FILE_MODE)
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _encrypt_handoff(
    payload: str,
    *,
    age_key: Path,
    output: Path,
    temporary_directory: Path,
    rotate: bool,
    repository_root: Path,
    run_command: Callable[..., str],
) -> None:
    require_private_file(
        age_key,
        "SOPS/age identity",
        repository_root=repository_root,
        within_repository=True,
    )
    require_replaceable(output, rotate, "cluster intermediate handoff")
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=temporary_directory,
        prefix=".plaintext-",
        suffix=".json",
        delete=False,
    ) as plaintext_stream:
        plaintext = Path(plaintext_stream.name)
        plaintext_stream.write(payload)
    plaintext.chmod(PRIVATE_FILE_MODE)
    encrypted = output.with_name(f".{output.name}.encrypted")
    try:
        require(not encrypted.exists() and not encrypted.is_symlink(), "stale encrypted temporary exists")
        recipient = run_command(["age-keygen", "-y", str(age_key)]).strip()
        require(recipient.startswith("age1"), "SOPS/age identity did not yield a recipient")
        run_command(
            [
                "sops",
                "--encrypt",
                "--age",
                recipient,
                "--input-type",
                "json",
                "--output-type",
                "json",
                "--output",
                str(encrypted),
                str(plaintext),
            ]
        )
        encrypted.chmod(PRIVATE_FILE_MODE)
        os.replace(encrypted, output)
        output.chmod(PRIVATE_FILE_MODE)
        directory = os.open(
            output.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        plaintext.unlink(missing_ok=True)
        encrypted.unlink(missing_ok=True)


def generate(
    *,
    cluster: str,
    repository_root: Path = REPOSITORY_ROOT,
    root_key: Path | None = None,
    age_key: Path | None = None,
    rotate: bool = False,
    run_command: Callable[..., str] = run,
) -> dict[str, str]:
    paths = cluster_paths(repository_root, cluster)
    root_key = root_key or paths["root_key"]
    age_key = age_key or paths["age_key"]
    private_root = paths["private_root"]
    cluster_root = paths["cluster_root"]
    ensure_private_directory(
        private_root, "Kubernetes private root", repository_root=repository_root
    )
    ensure_private_directory(
        cluster_root, "cluster private root", repository_root=repository_root
    )
    if root_key == paths["root_key"]:
        ensure_private_directory(
            root_key.parent,
            "offline root key directory",
            repository_root=repository_root,
        )
    require(root_key.is_absolute(), "offline root key path must be absolute")
    require(age_key.is_absolute(), "SOPS/age identity path must be absolute")
    require_private_file(
        root_key,
        "offline root key",
        repository_root=repository_root,
        within_repository=root_key == paths["root_key"],
    )
    require_private_file(
        age_key,
        "SOPS/age identity",
        repository_root=repository_root,
        within_repository=True,
    )
    require_public_file(
        paths["root_certificate"],
        "public root certificate",
        repository_root=repository_root,
    )
    for path, label in (
        (paths["intermediate_key"], "intermediate key"),
        (paths["intermediate_certificate"], "intermediate certificate"),
        (paths["handoff"], "cluster intermediate handoff"),
    ):
        require_replaceable(path, rotate, label)

    with tempfile.TemporaryDirectory(prefix=".intermediate-", dir=cluster_root) as temporary_name:
        temporary = Path(temporary_name)
        key = temporary / paths["intermediate_key"].name
        certificate = temporary / paths["intermediate_certificate"].name
        csr = temporary / "shell-cluster-intermediate.csr.pem"
        extensions = temporary / "intermediate.extensions"
        serial = temporary / "root-ca.serial"
        run_command(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(key),
            ]
        )
        key.chmod(PRIVATE_FILE_MODE)
        run_command(
            [
                "openssl",
                "req",
                "-new",
                "-sha256",
                "-key",
                str(key),
                "-out",
                str(csr),
                "-subj",
                f"/O=SHELL/CN=SHELL {cluster} Cluster Intermediate CA",
            ]
        )
        extensions.write_text(
            "basicConstraints=critical,CA:TRUE,pathlen:0\n"
            "keyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n",
            encoding="utf-8",
        )
        run_command(
            [
                "openssl",
                "x509",
                "-req",
                "-sha256",
                "-days",
                "1825",
                "-in",
                str(csr),
                "-CA",
                str(paths["root_certificate"]),
                "-CAkey",
                str(root_key),
                "-CAcreateserial",
                "-CAserial",
                str(serial),
                "-out",
                str(certificate),
                "-extfile",
                str(extensions),
            ]
        )
        run_command(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(paths["root_certificate"]),
                str(certificate),
            ]
        )
        payload = handoff_payload(
            cluster=cluster,
            certificate=certificate.read_text(encoding="utf-8"),
            private_key=key.read_text(encoding="utf-8"),
            root_ca=paths["root_certificate"].read_text(encoding="ascii"),
        )
        _write_private(paths["intermediate_key"], key.read_text(encoding="utf-8"))
        _write_private(
            paths["intermediate_certificate"],
            certificate.read_text(encoding="utf-8"),
        )
        _encrypt_handoff(
            payload,
            age_key=age_key,
            output=paths["handoff"],
            temporary_directory=cluster_root,
            rotate=rotate,
            repository_root=repository_root,
            run_command=run_command,
        )
    return {
        "intermediate_key": str(paths["intermediate_key"]),
        "intermediate_certificate": str(paths["intermediate_certificate"]),
        "handoff": str(paths["handoff"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster", choices=CLUSTERS, required=True)
    parser.add_argument("--root-key", type=Path)
    parser.add_argument("--age-key", type=Path)
    parser.add_argument("--rotate", action="store_true")
    args = parser.parse_args(argv)
    try:
        outputs = generate(
            cluster=args.cluster,
            root_key=args.root_key,
            age_key=args.age_key,
            rotate=args.rotate,
        )
    except (GenerationError, OSError, subprocess.SubprocessError) as error:
        print(f"Kubernetes intermediate generation failed: {error}", file=sys.stderr)
        return 2
    for label, path in outputs.items():
        print(f"{label}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
