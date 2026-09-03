#!/usr/bin/env python3
"""Apply or verify the private INIT-generated Velero GCS credential."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, cast

import sops_helpers
import validate_velero


ROOT = Path(__file__).resolve().parents[2]
CREDENTIALS = ROOT / ".local/init/gcs-backup/credentials.json"
KUBECONFIG = ROOT / ".local/ansible/kubeconfig/gcp.yaml"
NAMESPACE = "velero"
SECRET_NAME = "velero-object-store"
SECRET_KEY = "cloud"
APPROVAL = "environment-gcp/make/velero-credentials"
REQUIRED_KEYS = {
    "type",
    "project_id",
    "private_key_id",
    "private_key",
    "client_email",
    "client_id",
    "auth_uri",
    "token_uri",
    "auth_provider_x509_cert_url",
    "client_x509_cert_url",
}
ALLOWED_KEYS = REQUIRED_KEYS | {"universe_domain"}


class VeleroCredentialError(RuntimeError):
    """The Velero GCS credential handoff cannot be applied safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VeleroCredentialError(message)


def fixed_path(path: Path, expected: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    target = Path(os.path.abspath(expected))
    require(value == target, f"{label} path changed")
    return target


def credentials(path: Path = CREDENTIALS) -> dict[str, Any]:
    private = sops_helpers.private_file(path, "Velero GCS credentials")
    try:
        document = json.loads(private.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VeleroCredentialError("Velero GCS credentials are invalid JSON") from error
    require(isinstance(document, dict), "Velero GCS credentials are not an object")
    document = cast(dict[str, Any], document)
    require(set(document) <= ALLOWED_KEYS and REQUIRED_KEYS <= set(document), "Velero GCS credential keys changed")
    require(document["type"] == "service_account", "Velero GCS credential type changed")
    for key in REQUIRED_KEYS - {"type", "private_key"}:
        require(isinstance(document[key], str) and bool(document[key]), f"Velero GCS credential field is empty: {key}")
    private_key = document["private_key"]
    require(
        isinstance(private_key, str)
        and private_key.startswith("-----BEGIN PRIVATE KEY-----")
        and private_key.rstrip().endswith("-----END PRIVATE KEY-----"),
        "Velero GCS private key is not a PKCS8 PEM value",
    )
    require(
        re.fullmatch(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$", document["project_id"])
        is not None,
        "Velero GCS project ID is invalid",
    )
    return document


def secret_manifest(document: dict[str, Any]) -> str:
    return yaml_dump(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": SECRET_NAME,
                "namespace": NAMESPACE,
                "labels": {
                    "app.kubernetes.io/part-of": "shell-platform",
                    "shell.platform/owner": "sudo",
                },
            },
            "type": "Opaque",
            "stringData": {SECRET_KEY: json.dumps(document, separators=(",", ":"))},
        }
    )


def yaml_dump(document: dict[str, Any]) -> str:
    import yaml

    return yaml.safe_dump(document, sort_keys=False)


def kubectl(kubeconfig: Path, *arguments: str) -> list[str]:
    return ["kubectl", "--kubeconfig", str(kubeconfig), *arguments]


def require_namespace(kubeconfig: Path) -> None:
    sops_helpers.run(
        kubectl(kubeconfig, "get", "namespace", NAMESPACE, "--output", "name"),
        label="Velero namespace readback",
        environment=os.environ.copy(),
    )


def apply(kubeconfig: Path, document: dict[str, Any]) -> None:
    require_namespace(kubeconfig)
    sops_helpers.run(
        kubectl(
            kubeconfig,
            "apply",
            "--server-side",
            "--field-manager=make-velero-credentials",
            "--filename",
            "-",
        ),
        label="Velero GCS credential apply",
        environment=os.environ.copy(),
        input_text=secret_manifest(document),
    )


def verify(kubeconfig: Path) -> None:
    require_namespace(kubeconfig)
    sops_helpers.run(
        kubectl(kubeconfig, "get", "secret", SECRET_NAME, "--namespace", NAMESPACE, "--output", "name"),
        label="Velero GCS credential verification",
        environment=os.environ.copy(),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "apply", "verify"))
    parser.add_argument("--approval", default="")
    parser.add_argument("--credentials", type=Path, default=CREDENTIALS)
    parser.add_argument("--kubeconfig", type=Path, default=KUBECONFIG)
    args = parser.parse_args(argv)
    try:
        if args.action == "check":
            validate_velero.validate()
            print("validated Velero GCS credential source")
            return 0
        validate_velero.validate()
        if args.action == "apply":
            require(args.approval == APPROVAL, f"approval must be {APPROVAL}")
        credential_path = fixed_path(args.credentials, CREDENTIALS, "Velero credentials")
        kubeconfig = fixed_path(args.kubeconfig, KUBECONFIG, "GCP kubeconfig")
        if args.action == "apply":
            apply(kubeconfig, credentials(credential_path))
            print("applied Velero GCS credential Secret")
        else:
            verify(kubeconfig)
            print("verified Velero GCS credential Secret")
        return 0
    except (
        OSError,
        VeleroCredentialError,
        sops_helpers.SopsError,
        validate_velero.VeleroValidationError,
        validate_velero.access.AccessContractError,
        validate_velero.supply.SupplyError,
    ) as error:
        print(f"MAKE Velero credential operation refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
