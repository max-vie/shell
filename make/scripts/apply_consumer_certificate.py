#!/usr/bin/env python3
"""Apply or verify the MAKE Forgejo consumer certificate."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Any, Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPOSITORY_ROOT / "make/certificates/forgejo-tls.json"
ROOT_CERTIFICATE = REPOSITORY_ROOT / "sudo/pki/shell-offline-root.crt.pem"
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
APPROVALS = {
    "gcp": "make/cluster-trust/gcp",
    "proxmox": "make/cluster-trust/proxmox",
}
CLUSTERS = {
    "gcp": REPOSITORY_ROOT / ".local/ansible/kubeconfig/gcp.yaml",
    "proxmox": REPOSITORY_ROOT / ".local/ansible/kubeconfig/proxmox.yaml",
}
CERT_MANAGER_CRD = "certificates.cert-manager.io"
CERT_MANAGER_NAMESPACE = "cert-manager"
CLUSTER_ISSUER_NAME = "shell-cluster-intermediate"
CONSUMER_SECRET_NAME = "forgejo-tls"
CERTIFICATE_PEM = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
PEM_BLOCK = re.compile(
    r"\A-----BEGIN (?P<label>[A-Z0-9][A-Z0-9 ]*)-----\r?\n"
    r".+?\r?\n-----END (?P=label)-----\r?\n?\Z",
    re.DOTALL,
)


class ConsumerCertificateError(RuntimeError):
    """The MAKE consumer certificate operation failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConsumerCertificateError(message)


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


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, "duplicate JSON key in consumer manifest")
        document[key] = value
    return document


def run(command: list[str], *, input_text: str | None = None) -> str:
    completed = subprocess.run(  # nosec B603
        command,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip().splitlines()
        suffix = detail[-1] if detail else f"exit {completed.returncode}"
        raise ConsumerCertificateError(f"{command[0]} failed: {suffix}")
    return completed.stdout


def _check_repository_path(path: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    require(path.is_relative_to(REPOSITORY_ROOT), f"{label} must remain inside the repository")
    current = REPOSITORY_ROOT
    for component in path.relative_to(REPOSITORY_ROOT).parts:
        current /= component
        require(not current.is_symlink(), f"{label} contains a symlink: {current}")
    return path


def require_private_file(path: Path, label: str) -> None:
    path = _check_repository_path(path, label)
    require(not path.is_symlink() and path.is_file(), f"{label} must be a regular file")
    require(path.stat().st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(stat.S_IMODE(path.stat().st_mode) == PRIVATE_FILE_MODE, f"{label} must be mode 0600")
    current = path.parent
    while current != REPOSITORY_ROOT:
        require(not current.is_symlink(), f"{label} parent contains a symlink: {current}")
        require(current.is_dir(), f"{label} parent is not a directory")
        require(
            current.stat().st_uid == os.geteuid()
            and stat.S_IMODE(current.stat().st_mode) == PRIVATE_DIRECTORY_MODE,
            f"{label} parent must be owned and mode 0700",
        )
        current = current.parent
    require(current == REPOSITORY_ROOT, f"{label} escaped the repository")


def require_public_file(path: Path, label: str) -> None:
    path = _check_repository_path(path, label)
    require(not path.is_symlink() and path.is_file(), f"{label} must be a regular file")


def kubectl_base(cluster: str) -> list[str]:
    try:
        kubeconfig = CLUSTERS[cluster]
    except KeyError as error:
        raise ConsumerCertificateError("cluster must be one of: gcp, proxmox") from error
    require_private_file(kubeconfig, f"{cluster} kubeconfig")
    return ["kubectl", "--kubeconfig", str(kubeconfig)]


def load_manifest() -> dict[str, Any]:
    require_public_file(MANIFEST, "consumer certificate manifest")
    try:
        document = json.loads(
            MANIFEST.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConsumerCertificateError("consumer certificate manifest is invalid JSON") from error
    require(isinstance(document, dict), "consumer certificate manifest is not an object")
    require(
        document
        == {
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": {
                "name": "forgejo-tls",
                "namespace": "default",
                "annotations": {
                    "shell.platform/owner": "make",
                    "shell.platform/issuer": "shell-cluster-intermediate",
                },
            },
            "spec": {
                "secretName": "forgejo-tls",
                "issuerRef": {
                    "name": "shell-cluster-intermediate",
                    "kind": "ClusterIssuer",
                },
                "dnsNames": ["forgejo.shell.internal"],
            },
        },
        "consumer certificate manifest changed",
    )
    return document


def check_prerequisites(
    cluster: str, *, run_command: Callable[..., str] = run
) -> None:
    """Check cert-manager and the SUDO issuer before creating a Certificate."""

    base = kubectl_base(cluster)
    run_command(
        [*base, "get", "namespace", CERT_MANAGER_NAMESPACE, "--output", "name"]
    )
    run_command([*base, "get", "namespace", "default", "--output", "name"])
    run_command([*base, "get", "crd", CERT_MANAGER_CRD, "--output", "name"])
    raw = run_command(
        [
            *base,
            "get",
            "clusterissuer",
            CLUSTER_ISSUER_NAME,
            "--output",
            "json",
        ]
    )
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise ConsumerCertificateError("ClusterIssuer prerequisite is not JSON") from error
    require(isinstance(document, dict), "ClusterIssuer prerequisite is not an object")
    metadata = document.get("metadata")
    require(isinstance(metadata, dict), "ClusterIssuer prerequisite metadata is missing")
    annotations = metadata.get("annotations")
    require(
        metadata.get("name") == CLUSTER_ISSUER_NAME
        and isinstance(annotations, dict)
        and annotations.get("shell.platform/owner") == "sudo",
        "ClusterIssuer prerequisite ownership changed",
    )
    require(
        document.get("spec") == {"ca": {"secretName": CLUSTER_ISSUER_NAME}},
        "ClusterIssuer prerequisite is not backed by the SUDO Secret",
    )
    output = run_command(
        [
            *base,
            "wait",
            "--for=condition=Ready",
            f"clusterissuer/{CLUSTER_ISSUER_NAME}",
            "--timeout=180s",
        ]
    )
    require("condition met" in output, "ClusterIssuer prerequisite is not ready")


def apply_certificate(cluster: str, *, run_command: Callable[..., str] = run) -> None:
    load_manifest()
    check_prerequisites(cluster, run_command=run_command)
    run_command(
        [
            *kubectl_base(cluster),
            "apply",
            "--server-side",
            "--field-manager=make-consumer-certificate",
            "--filename",
            str(MANIFEST),
        ]
    )


def wait_ready(cluster: str, *, run_command: Callable[..., str] = run) -> None:
    output = run_command(
        [
            *kubectl_base(cluster),
            "wait",
            "--for=condition=Ready",
            "certificate/forgejo-tls",
            "--namespace",
            "default",
            "--timeout=180s",
        ]
    )
    require("condition met" in output, "consumer Certificate readiness output was incomplete")


def read_secret(cluster: str, *, run_command: Callable[..., str] = run) -> dict[str, str]:
    raw = run_command(
        [
            *kubectl_base(cluster),
            "get",
            "secret",
            "forgejo-tls",
            "--namespace",
            "default",
            "--output",
            "json",
        ]
    )
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise ConsumerCertificateError("consumer TLS Secret readback is not JSON") from error
    require(isinstance(document, dict), "consumer TLS Secret readback is not an object")
    metadata = document.get("metadata")
    require(isinstance(metadata, dict), "consumer TLS Secret metadata is missing")
    require(
        metadata.get("name") == CONSUMER_SECRET_NAME
        and metadata.get("namespace") == "default",
        "consumer TLS Secret identity changed",
    )
    require(document.get("type") == "kubernetes.io/tls", "consumer TLS Secret type changed")
    data = document.get("data")
    require(isinstance(data, dict) and set(data) == {"tls.crt", "tls.key", "ca.crt"}, "consumer TLS Secret keys changed")
    result: dict[str, str] = {}
    for key in ("tls.crt", "ca.crt"):
        value = data[key]
        require(isinstance(value, str), f"consumer TLS Secret {key} is invalid")
        try:
            result[key] = base64.b64decode(value, validate=True).decode("ascii")
        except (binascii.Error, UnicodeError) as error:
            raise ConsumerCertificateError(f"consumer TLS Secret {key} is not base64 PEM") from error
    key_value = data["tls.key"]
    require(isinstance(key_value, str), "consumer TLS Secret private key is invalid")
    try:
        private_key = base64.b64decode(key_value, validate=True).decode("ascii")
    except (binascii.Error, UnicodeError) as error:
        raise ConsumerCertificateError("consumer TLS Secret private key is not base64 PEM") from error
    require_pem(private_key, "consumer TLS Secret private key", "PRIVATE KEY")
    return result


def verify_certificate_owner(cluster: str, *, run_command: Callable[..., str] = run) -> None:
    raw = run_command(
        [
            *kubectl_base(cluster),
            "get",
            "certificate",
            "forgejo-tls",
            "--namespace",
            "default",
            "--output",
            "json",
        ]
    )
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise ConsumerCertificateError("consumer Certificate readback is not JSON") from error
    require(isinstance(document, dict), "consumer Certificate readback is not an object")
    metadata = document.get("metadata")
    require(isinstance(metadata, dict), "consumer Certificate metadata is missing")
    require(
        metadata.get("name") == CONSUMER_SECRET_NAME
        and metadata.get("namespace") == "default",
        "consumer Certificate identity changed",
    )
    annotations = metadata.get("annotations")
    require(
        isinstance(annotations, dict)
        and annotations.get("shell.platform/owner") == "make"
        and annotations.get("shell.platform/issuer") == CLUSTER_ISSUER_NAME,
        "consumer Certificate ownership changed",
    )
    spec = document.get("spec", {})
    require(isinstance(spec, dict), "consumer Certificate spec is missing")
    require(
        spec.get("issuerRef")
        == {"name": CLUSTER_ISSUER_NAME, "kind": "ClusterIssuer"},
        "consumer Certificate issuer changed",
    )
    require(spec.get("secretName") == CONSUMER_SECRET_NAME, "consumer Certificate Secret changed")
    require(spec.get("dnsNames") == ["forgejo.shell.internal"], "consumer Certificate DNS names changed")


def verify_chain(secret: dict[str, str]) -> None:
    require_public_file(ROOT_CERTIFICATE, "SUDO public root certificate")
    root = ROOT_CERTIFICATE.read_text(encoding="ascii")
    require(secret["ca.crt"] == root, "consumer TLS Secret CA does not match SUDO root")
    certificates = CERTIFICATE_PEM.findall(secret["tls.crt"])
    require(len(certificates) >= 2, "consumer TLS Secret lacks an intermediate chain")
    with tempfile.TemporaryDirectory(prefix=".consumer-certificate-") as directory:
        temporary = Path(directory)
        leaf = temporary / "leaf.pem"
        chain = temporary / "chain.pem"
        root_path = temporary / "root.pem"
        leaf.write_text(certificates[0] + "\n", encoding="ascii")
        chain.write_text("\n".join(certificates[1:]) + "\n", encoding="ascii")
        root_path.write_text(root, encoding="ascii")
        openssl = shutil.which("openssl")
        if openssl is None:
            raise ConsumerCertificateError(
                "openssl is required for certificate verification"
            )
        completed = subprocess.run(  # nosec B603
            [
                openssl,
                "verify",
                "-CAfile",
                str(root_path),
                "-untrusted",
                str(chain),
                "-purpose",
                "sslserver",
                "-verify_hostname",
                "forgejo.shell.internal",
                str(leaf),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        require(completed.returncode == 0, "consumer certificate chain or hostname verification failed")


def apply(cluster: str, *, run_command: Callable[..., str] = run) -> None:
    apply_certificate(cluster, run_command=run_command)
    wait_ready(cluster, run_command=run_command)
    verify_certificate_owner(cluster, run_command=run_command)
    verify_chain(read_secret(cluster, run_command=run_command))


def verify(cluster: str, *, run_command: Callable[..., str] = run) -> None:
    verify_certificate_owner(cluster, run_command=run_command)
    verify_chain(read_secret(cluster, run_command=run_command))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("apply", "verify"))
    parser.add_argument("--cluster", choices=CLUSTERS, required=True)
    parser.add_argument("--approval")
    args = parser.parse_args(argv)
    try:
        if args.action == "apply":
            require(args.approval == APPROVALS[args.cluster], "the exact cluster-trust approval is required")
            apply(args.cluster)
        else:
            verify(args.cluster)
    except (ConsumerCertificateError, OSError) as error:
        print(f"consumer certificate operation failed: {error}", file=sys.stderr)
        return 2
    print(f"completed consumer certificate {args.action}: {args.cluster}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
