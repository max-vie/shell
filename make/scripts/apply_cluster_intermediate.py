#!/usr/bin/env python3
"""Apply or verify one SUDO cluster-intermediate handoff."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any, Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ROOT_CERTIFICATE = REPOSITORY_ROOT / "sudo/pki/shell-offline-root.crt.pem"
ISSUER_MANIFEST = REPOSITORY_ROOT / "make/cert-manager/cluster-issuer.json"
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
APPROVALS = {
    "gcp": "make/cluster-trust/gcp",
    "proxmox": "make/cluster-trust/proxmox",
}
CLUSTERS = {
    "gcp": {
        "handoff": REPOSITORY_ROOT
        / ".local/sudo/kubernetes/gcp/cluster-intermediate.sops.json",
        "kubeconfig": REPOSITORY_ROOT / ".local/ansible/kubeconfig/gcp.yaml",
    },
    "proxmox": {
        "handoff": REPOSITORY_ROOT
        / ".local/sudo/kubernetes/proxmox/cluster-intermediate.sops.json",
        "kubeconfig": REPOSITORY_ROOT
        / ".local/ansible/kubeconfig/proxmox.yaml",
    },
}
AGE_KEY = REPOSITORY_ROOT / ".local/sudo/kubernetes/age-key.txt"
CERT_MANAGER_NAMESPACE = "cert-manager"
CERT_MANAGER_CRDS = (
    "certificates.cert-manager.io",
    "clusterissuers.cert-manager.io",
)
PEM_BLOCK = re.compile(
    r"\A-----BEGIN (?P<label>[A-Z0-9][A-Z0-9 ]*)-----\r?\n"
    r".+?\r?\n-----END (?P=label)-----\r?\n?\Z",
    re.DOTALL,
)


class ClusterIntermediateError(RuntimeError):
    """The SUDO cluster-intermediate handoff failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ClusterIntermediateError(message)


def require_pem(value: str, label: str, expected_label: str) -> None:
    match = PEM_BLOCK.fullmatch(value)
    require(
        match is not None and match.group("label") == expected_label,
        f"{label} is not a complete {expected_label} PEM block",
    )


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, "duplicate JSON key in cluster handoff")
        document[key] = value
    return document


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
) -> str:
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
        raise ClusterIntermediateError(f"{command[0]} failed: {suffix}")
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
    require(
        path.is_relative_to(REPOSITORY_ROOT),
        f"{label} must remain inside the repository",
    )
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


def load_json(path: Path, label: str, *, private: bool) -> dict[str, Any]:
    if private:
        require_private_file(path, label)
    else:
        require_public_file(path, label)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ClusterIntermediateError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def load_issuer_manifest() -> dict[str, Any]:
    document = load_json(ISSUER_MANIFEST, "ClusterIssuer manifest", private=False)
    require(
        document
        == {
            "apiVersion": "cert-manager.io/v1",
            "kind": "ClusterIssuer",
            "metadata": {
                "name": "shell-cluster-intermediate",
                "annotations": {
                    "shell.platform/owner": "sudo",
                    "shell.platform/input": "kubernetes-ecosystem-input-contract",
                },
            },
            "spec": {
                "ca": {"secretName": "shell-cluster-intermediate"}
            },
        },
        "ClusterIssuer manifest changed",
    )
    return document


def decrypt_handoff(
    cluster: str,
    *,
    run_command: Callable[..., str] = run,
) -> dict[str, str]:
    try:
        handoff_path = CLUSTERS[cluster]["handoff"]
    except KeyError as error:
        raise ClusterIntermediateError("cluster must be one of: gcp, proxmox") from error
    require_private_file(handoff_path, "SUDO cluster-intermediate handoff")
    require_private_file(AGE_KEY, "SOPS/age identity")
    require_public_file(ROOT_CERTIFICATE, "SUDO public root certificate")
    environment = os.environ.copy()
    environment["SOPS_AGE_KEY_FILE"] = str(AGE_KEY)
    raw = run_command(
        [
            "sops",
            "--decrypt",
            "--input-type",
            "json",
            "--output-type",
            "json",
            str(handoff_path),
        ],
        environment=environment,
    )
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ClusterIntermediateError("decrypted cluster handoff is not valid JSON") from error
    require(isinstance(document, dict), "decrypted cluster handoff is not an object")
    require(
        set(document)
        == {"schema_version", "contract_id", "cluster", "issuer", "cluster_intermediate"},
        "decrypted cluster handoff shape changed",
    )
    require(document["schema_version"] == "1.0", "decrypted cluster handoff schema changed")
    require(document["contract_id"] == "kubernetes-ecosystem-input-contract", "decrypted handoff contract changed")
    require(document["cluster"] == cluster, "decrypted handoff cluster changed")
    require(document["issuer"] == "shell-cluster-intermediate", "decrypted handoff issuer changed")
    payload = document["cluster_intermediate"]
    require(
        isinstance(payload, dict)
        and set(payload) == {"certificate", "private_key", "root_ca"},
        "decrypted cluster-intermediate keys changed",
    )
    root_ca = ROOT_CERTIFICATE.read_text(encoding="ascii")
    result: dict[str, str] = {}
    for key in ("certificate", "private_key", "root_ca"):
        value = payload[key]
        require(isinstance(value, str), f"decrypted {key} PEM is missing")
        expected = "PRIVATE KEY" if key == "private_key" else "CERTIFICATE"
        require_pem(value, f"decrypted {key}", expected)
        result[key] = value
    require(result["root_ca"] == root_ca, "cluster handoff root does not match SUDO public root")
    return result


def kubeconfig_for(cluster: str) -> Path:
    try:
        return CLUSTERS[cluster]["kubeconfig"]
    except KeyError as error:
        raise ClusterIntermediateError("cluster must be one of: gcp, proxmox") from error


def kubectl_base(cluster: str) -> list[str]:
    kubeconfig = kubeconfig_for(cluster)
    require_private_file(kubeconfig, f"{cluster} kubeconfig")
    return ["kubectl", "--kubeconfig", str(kubeconfig)]


def secret_manifest(payload: dict[str, str]) -> tuple[str, dict[str, str]]:
    values = {
        "tls.crt": payload["certificate"],
        "tls.key": payload["private_key"],
        "ca.crt": payload["root_ca"],
    }
    encoded = {
        key: base64.b64encode(value.encode("utf-8")).decode("ascii")
        for key, value in values.items()
    }
    document = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "shell-cluster-intermediate",
            "namespace": "cert-manager",
            "labels": {"shell.platform/owner": "sudo"},
        },
        "type": "kubernetes.io/tls",
        "data": encoded,
    }
    return json.dumps(document, indent=2) + "\n", encoded


def check_prerequisites(
    cluster: str, *, run_command: Callable[..., str] = run
) -> None:
    """Check cert-manager's namespace and CRDs before any resource apply."""

    base = kubectl_base(cluster)
    run_command(
        [
            *base,
            "get",
            "namespace",
            CERT_MANAGER_NAMESPACE,
            "--output",
            "name",
        ]
    )
    for crd in CERT_MANAGER_CRDS:
        run_command([*base, "get", "crd", crd, "--output", "name"])


def validate_apply(
    cluster: str,
    secret: str,
    issuer: dict[str, Any],
    *,
    run_command: Callable[..., str] = run,
) -> None:
    """Validate both owned resources server-side before the first mutation."""

    documents = f"{secret}---\n{json.dumps(issuer, indent=2)}\n"
    run_command(
        [
            *kubectl_base(cluster),
            "apply",
            "--server-side",
            "--dry-run=server",
            "--field-manager=make-cluster-trust",
            "--filename",
            "-",
        ],
        input_text=documents,
    )


def verify_secret(
    cluster: str,
    expected: dict[str, str],
    *,
    run_command: Callable[..., str] = run,
) -> None:
    raw = run_command(
        [
            *kubectl_base(cluster),
            "get",
            "secret",
            "shell-cluster-intermediate",
            "--namespace",
            "cert-manager",
            "--output",
            "json",
        ],
    )
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise ClusterIntermediateError("cluster Secret readback is not JSON") from error
    require(isinstance(document, dict), "cluster Secret readback is not an object")
    metadata = document.get("metadata")
    require(isinstance(metadata, dict), "cluster Secret metadata is missing")
    require(
        metadata.get("name") == "shell-cluster-intermediate"
        and metadata.get("namespace") == "cert-manager",
        "cluster Secret identity changed",
    )
    require(
        metadata.get("labels") == {"shell.platform/owner": "sudo"},
        "cluster Secret ownership changed",
    )
    require(document.get("type") == "kubernetes.io/tls", "cluster Secret type changed")
    require(document.get("data") == expected, "cluster Secret does not match the SUDO handoff")


def verify_issuer(
    cluster: str,
    *,
    run_command: Callable[..., str] = run,
) -> None:
    output = run_command(
        [
            *kubectl_base(cluster),
            "wait",
            "--for=condition=Ready",
            "clusterissuer/shell-cluster-intermediate",
            "--timeout=180s",
        ],
    )
    require("condition met" in output, "ClusterIssuer readiness output was incomplete")
    raw = run_command(
        [
            *kubectl_base(cluster),
            "get",
            "clusterissuer",
            "shell-cluster-intermediate",
            "--output",
            "json",
        ],
    )
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise ClusterIntermediateError("ClusterIssuer readback is not JSON") from error
    metadata = document.get("metadata")
    require(isinstance(metadata, dict), "ClusterIssuer metadata is missing")
    require(
        metadata.get("name") == "shell-cluster-intermediate"
        and metadata.get("annotations")
        == {
            "shell.platform/owner": "sudo",
            "shell.platform/input": "kubernetes-ecosystem-input-contract",
        },
        "ClusterIssuer ownership changed",
    )
    spec = document.get("spec")
    require(isinstance(spec, dict), "ClusterIssuer readback has no spec")
    ca = spec.get("ca")
    require(isinstance(ca, dict), "ClusterIssuer has no CA configuration")
    require(
        spec == {"ca": {"secretName": "shell-cluster-intermediate"}},
        "ClusterIssuer is not backed by the SUDO Secret",
    )


def apply(cluster: str, *, run_command: Callable[..., str] = run) -> None:
    issuer = load_issuer_manifest()
    payload = decrypt_handoff(cluster, run_command=run_command)
    secret, encoded = secret_manifest(payload)
    check_prerequisites(cluster, run_command=run_command)
    validate_apply(cluster, secret, issuer, run_command=run_command)
    try:
        run_command(
            [
                *kubectl_base(cluster),
                "apply",
                "--server-side",
                "--field-manager=make-cluster-trust",
                "--filename",
                "-",
            ],
            input_text=secret,
        )
        verify_secret(cluster, encoded, run_command=run_command)
        run_command(
            [
                *kubectl_base(cluster),
                "apply",
                "--server-side",
                "--field-manager=make-cluster-trust",
                "--filename",
                str(ISSUER_MANIFEST),
            ],
        )
        verify_issuer(cluster, run_command=run_command)
    except ClusterIntermediateError as error:
        raise ClusterIntermediateError(
            "cluster trust apply may be partially applied; run verify before retry: "
            f"{error}"
        ) from error


def verify(cluster: str, *, run_command: Callable[..., str] = run) -> None:
    payload = decrypt_handoff(cluster, run_command=run_command)
    _secret, encoded = secret_manifest(payload)
    verify_secret(cluster, encoded, run_command=run_command)
    verify_issuer(cluster, run_command=run_command)


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
    except (ClusterIntermediateError, OSError) as error:
        print(f"cluster intermediate operation failed: {error}", file=sys.stderr)
        return 2
    print(f"completed cluster intermediate {args.action}: {args.cluster}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
