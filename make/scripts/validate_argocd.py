#!/usr/bin/env python3
"""Validate the source-only Argo CD bootstrap boundary."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
VALUES = ROOT / "make/gitops/bootstrap/argocd/values.yaml"
PROJECT = ROOT / "make/gitops/bootstrap/argocd/project.yaml"
ROOT_APPLICATION = ROOT / "make/gitops/bootstrap/argocd/root-application.yaml"
OPENBAO_APPLICATION = ROOT / "make/gitops/applications/children/openbao.yaml"
REPOSITORY_CA = ROOT / "make/gitops/bootstrap/argocd/repository-ca.yaml"
ROOT_CERTIFICATE = ROOT / "sudo/pki/shell-offline-root.crt.pem"


class ArgoValidationError(ValueError):
    """Argo CD source validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArgoValidationError(message)


def validate() -> None:
    for path in (
        VALUES,
        PROJECT,
        ROOT_APPLICATION,
        REPOSITORY_CA,
        OPENBAO_APPLICATION,
    ):
        require(
            path.is_file() and not path.is_symlink(),
            f"Argo source is missing: {path.name}",
        )
    try:
        values = yaml.safe_load(VALUES.read_text(encoding="utf-8"))
        project = yaml.safe_load(PROJECT.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ArgoValidationError("Argo source is not valid YAML") from error
    require(isinstance(values, dict), "Argo values must be a mapping")
    require(
        values["server"]["service"]["type"] == "ClusterIP",
        "Argo server must remain ClusterIP",
    )
    require(
        values["configs"]["cm"]["admin.enabled"] == "false",
        "Argo built-in admin must stay disabled",
    )
    require(
        values.get("dex", {}).get("enabled") is False, "Argo Dex must stay disabled"
    )
    require("oidc" not in str(values).lower(), "Argo OIDC is outside this slice")
    require(
        "keycloak" not in str(values).lower(), "Argo Keycloak is outside this slice"
    )
    require(isinstance(project, dict), "Argo project must be a mapping")
    spec = project.get("spec", {})
    require(
        spec.get("sourceRepos")
        == [
            "https://forgejo.shell.internal/shell/make.git",
            "registry.shell.internal/shell/charts",
        ],
        "Argo source repository allow-list changed",
    )
    destinations = spec.get("destinations", [])
    require(
        {item.get("namespace") for item in destinations} == {"argocd", "openbao"},
        "Argo destination allow-list changed",
    )
    root = ROOT_APPLICATION.read_text(encoding="utf-8")
    child = OPENBAO_APPLICATION.read_text(encoding="utf-8")
    require("path: gitops/applications/children" in root, "Argo root path changed")
    require("chart: openbao" in child, "Argo must manage OpenBao")
    require(
        "namespace: release-feed" not in root,
        "Argo must not own release-feed in this slice",
    )
    ca = REPOSITORY_CA.read_text(encoding="utf-8")
    require(
        "forgejo.shell.internal:" in ca and "registry.shell.internal:" in ca,
        "Argo repository CA handoff is incomplete",
    )
    require(
        "BEGIN PRIVATE KEY" not in ca,
        "Argo repository CA handoff contains private material",
    )
    require(
        ROOT_CERTIFICATE.is_file() and not ROOT_CERTIFICATE.is_symlink(),
        "SUDO root certificate is missing",
    )
    require(
        "".join(ROOT_CERTIFICATE.read_text(encoding="ascii").split())
        in "".join(ca.split()),
        "Argo repository CA handoff does not match SUDO trust",
    )


def main() -> int:
    try:
        validate()
    except (OSError, ArgoValidationError) as error:
        print(f"MAKE Argo CD validation failed: {error}", file=sys.stderr)
        return 2
    print("validated Argo CD GitOps source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
