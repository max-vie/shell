#!/usr/bin/env python3
"""Apply or verify the protected Keycloak inputs owned by MAKE."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import yaml

import sops_helpers
import validate_keycloak


ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / ".local/sudo/keycloak/keycloak.sops.json"
AGE_KEY = ROOT / ".local/sudo/keycloak/age-key.txt"
FREEIPA_CA = ROOT / ".local/sudo/keycloak/freeipa-ca.crt"
KUBECONFIG = ROOT / ".local/ansible/kubeconfig/gcp.yaml"
NAMESPACE = "shell-identity"
APPROVAL = "environment-gcp/make/keycloak-secrets"
SECRET_NAMES = ("keycloak-database", "keycloak-bootstrap", "keycloak-runtime")


class KeycloakSecretError(RuntimeError):
    """The protected Keycloak handoff cannot be applied safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KeycloakSecretError(message)


def fixed_path(path: Path, expected: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    target = Path(os.path.abspath(expected))
    require(value == target, f"{label} path changed")
    return target


def protected_input(path: Path, age_key: Path) -> dict[str, Any]:
    document = sops_helpers.decrypt_json(path, age_key)
    require(
        set(document)
        == {
            "database_username",
            "database_password",
            "bootstrap_admin_username",
            "bootstrap_admin_password",
            "ldap_bind_password",
        },
        "Keycloak input keys changed",
    )
    require(document["database_username"] == "keycloak", "Keycloak database identity changed")
    require(document["bootstrap_admin_username"] == "sso-bootstrap", "Keycloak bootstrap identity changed")
    for name in (
        "database_password",
        "bootstrap_admin_password",
        "ldap_bind_password",
    ):
        value = document[name]
        require(
            isinstance(value, str)
            and 32 <= len(value) <= 64
            and value.isascii()
            and value.isalnum(),
            f"Keycloak private input is invalid: {name}",
        )
    return document


def freeipa_ca(path: Path) -> str:
    certificate = sops_helpers.private_file(path, "FreeIPA CA handoff")
    try:
        value = certificate.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise KeycloakSecretError("FreeIPA CA handoff is not readable ASCII") from error
    require(
        "-----BEGIN CERTIFICATE-----" in value
        and "-----END CERTIFICATE-----" in value
        and "PRIVATE KEY" not in value,
        "FreeIPA CA handoff is not a certificate-only PEM file",
    )
    return value


def documents(document: dict[str, Any], ca: str) -> list[dict[str, Any]]:
    return [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": NAMESPACE,
                "labels": {
                    "app.kubernetes.io/part-of": "shell-platform",
                    "pod-security.kubernetes.io/enforce": "restricted",
                    "pod-security.kubernetes.io/audit": "restricted",
                    "pod-security.kubernetes.io/warn": "restricted",
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "shell-freeipa-ca",
                "namespace": NAMESPACE,
                "labels": {
                    "app.kubernetes.io/part-of": "shell-platform",
                    "shell.platform/managed-by": "make-keycloak-secrets",
                },
            },
            "data": {"ca.crt": ca},
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "keycloak-database", "namespace": NAMESPACE},
            "type": "Opaque",
            "stringData": {
                "username": document["database_username"],
                "password": document["database_password"],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "keycloak-bootstrap", "namespace": NAMESPACE},
            "type": "Opaque",
            "stringData": {
                "username": document["bootstrap_admin_username"],
                "password": document["bootstrap_admin_password"],
            },
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "keycloak-runtime", "namespace": NAMESPACE},
            "type": "Opaque",
            "stringData": {"ldap_bind_password": document["ldap_bind_password"]},
        },
    ]


def serialized(resources: list[dict[str, Any]]) -> str:
    return yaml.safe_dump_all(resources, sort_keys=False)


def apply(kubeconfig: Path, resources: list[dict[str, Any]]) -> None:
    kubeconfig = sops_helpers.private_file(kubeconfig, "GCP kubeconfig")
    sops_helpers.run(
        [
            "kubectl",
            "--kubeconfig",
            str(kubeconfig),
            "apply",
            "--server-side",
            "--field-manager=make-keycloak-secrets",
            "--filename",
            "-",
        ],
        label="Keycloak protected secret apply",
        environment=os.environ.copy(),
        input_text=serialized(resources),
    )


def verify(kubeconfig: Path) -> None:
    kubeconfig = sops_helpers.private_file(kubeconfig, "GCP kubeconfig")
    for name in SECRET_NAMES:
        sops_helpers.run(
            [
                "kubectl",
                "--kubeconfig",
                str(kubeconfig),
                "get",
                "secret",
                name,
                "--namespace",
                NAMESPACE,
                "--output",
                "name",
            ],
            label=f"Keycloak secret verification: {name}",
            environment=os.environ.copy(),
        )
    sops_helpers.run(
        [
            "kubectl",
            "--kubeconfig",
            str(kubeconfig),
            "get",
            "configmap",
            "shell-freeipa-ca",
            "--namespace",
            NAMESPACE,
            "--output",
            "name",
        ],
        label="FreeIPA CA ConfigMap verification",
        environment=os.environ.copy(),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "apply", "verify"))
    parser.add_argument("--approval", default="")
    parser.add_argument("--input", type=Path, default=INPUT)
    parser.add_argument("--age-key", type=Path, default=AGE_KEY)
    parser.add_argument("--freeipa-ca", type=Path, default=FREEIPA_CA)
    parser.add_argument("--kubeconfig", type=Path, default=KUBECONFIG)
    args = parser.parse_args(argv)
    try:
        if args.action == "check":
            validate_keycloak.validate()
            print("validated Keycloak protected-secret source")
            return 0
        if args.action == "apply":
            require(args.approval == APPROVAL, f"approval must be {APPROVAL}")
            validate_keycloak.validate()
            input_path = fixed_path(args.input, INPUT, "Keycloak input")
            age_key = fixed_path(args.age_key, AGE_KEY, "Keycloak age key")
            ca_path = fixed_path(args.freeipa_ca, FREEIPA_CA, "FreeIPA CA")
            kubeconfig = fixed_path(args.kubeconfig, KUBECONFIG, "GCP kubeconfig")
            document = protected_input(input_path, age_key)
            apply(kubeconfig, documents(document, freeipa_ca(ca_path)))
            print("applied Keycloak protected inputs")
            return 0
        validate_keycloak.validate()
        verify(fixed_path(args.kubeconfig, KUBECONFIG, "GCP kubeconfig"))
        print("verified Keycloak protected input resources")
        return 0
    except (
        OSError,
        KeycloakSecretError,
        sops_helpers.SopsError,
        validate_keycloak.KeycloakValidationError,
        validate_keycloak.access.AccessContractError,
    ) as error:
        print(f"MAKE Keycloak protected-secret operation refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
