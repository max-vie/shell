#!/usr/bin/env python3
"""Register the existing Forgejo handoff as an Argo CD read-only repository."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

import k3s_transport as transport
import register_forgejo_repository as forgejo_contract
import sops_helpers
import validate_harbor_robots


ROOT = Path(__file__).resolve().parents[2]
HANDOFF = ROOT / ".local/sudo/delivery/forgejo-repository.sops.json"
AGE_KEY = ROOT / ".local/sudo/delivery/age-key.txt"
HARBOR_HANDOFF = ROOT / ".local/sudo/release-feed/harbor-robots.sops.json"
HARBOR_AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
APPROVAL = "environment-gcp/make/argocd-repository"
REPOSITORY_URL = "https://forgejo.shell.internal/shell/make.git"


class ArgoRepositoryError(RuntimeError):
    """Argo CD repository registration was refused."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArgoRepositoryError(message)


def manifest(document: dict[str, Any]) -> str:
    require(
        document.get("url") == REPOSITORY_URL
        and isinstance(document.get("username"), str)
        and isinstance(document.get("api_token"), str)
        and document["username"]
        and document["api_token"],
        "Forgejo repository handoff is incomplete",
    )
    return (
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "shell-make-repository",
                    "namespace": "argocd",
                    "labels": {"argocd.argoproj.io/secret-type": "repository"},
                },
                "stringData": {
                    "type": "git",
                    "url": REPOSITORY_URL,
                    "username": document["username"],
                    "password": document["api_token"],
                    "insecureSkipServerVerification": "false",
                },
            }
        )
        + "\n"
    )


def harbor_manifest(document: dict[str, Any]) -> str:
    item = document.get("puller")
    require(isinstance(item, dict), "Harbor puller handoff is missing")
    item = cast(dict[str, Any], item)
    username = item.get("username")
    password = item.get("password")
    require(
        isinstance(username, str)
        and isinstance(password, str)
        and bool(username)
        and bool(password),
        "Harbor puller handoff is incomplete",
    )
    username = cast(str, username)
    password = cast(str, password)
    return (
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "shell-harbor-charts",
                    "namespace": "argocd",
                    "labels": {"argocd.argoproj.io/secret-type": "repository"},
                },
                "stringData": {
                    "type": "helm",
                    "url": "registry.shell.internal/shell/charts",
                    "name": "harbor",
                    "enableOCI": "true",
                    "username": username,
                    "password": password,
                },
            }
        )
        + "\n"
    )


def validate_source() -> None:
    forgejo_contract.validate_repository_document(
        {
            "schema_version": "1.0",
            "contract_id": "delivery-input-contract",
            "class": "forgejo_repository",
            "issuer": "forgejo-after-bootstrap",
            "deployment_target": "delivery-node-only",
            "one_time_bootstrap": True,
            "rotation": "explicit-approved",
            "forgejo_repository": {
                "url": REPOSITORY_URL,
                "username": forgejo_contract.BOT_USERNAME,
                "api_token": "0" * 40,
            },
        }
    )
    validate_harbor_robots.validate()


def apply(inventory: list[Path]) -> None:
    values = sops_helpers.decrypt_json(HANDOFF, AGE_KEY)
    harbor = sops_helpers.decrypt_json(HARBOR_HANDOFF, HARBOR_AGE_KEY)
    connection = transport.resolve_connection(inventory)
    transport.ssh(
        "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
        "create namespace argocd --dry-run=client -o yaml | "
        "sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl apply "
        "--server-side --field-manager=make-argocd-repository --filename -",
        connection,
        label="Argo CD namespace bootstrap",
    )
    transport.ssh(
        "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
        "apply --server-side --field-manager=make-argocd-repository --filename -",
        connection,
        label="Argo CD Forgejo repository handoff",
        input_text=manifest(values) + "---\n" + harbor_manifest(harbor),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check_only:
            validate_source()
            print("validated Argo CD repository source")
            return 0
        raise ArgoRepositoryError(
            "Argo CD repository registration is blocked until runtime images "
            "and the GitOps source revision are pinned"
        )
        require(args.approval == APPROVAL, f"approval must be {APPROVAL}")
        require(args.inventory, "private INIT inventories are required")
        apply(args.inventory)
    except (
        OSError,
        ArgoRepositoryError,
        transport.TransportError,
        sops_helpers.SopsError,
        forgejo_contract.RepositoryError,
        validate_harbor_robots.HarborRobotError,
    ) as error:
        print(f"MAKE Argo CD repository operation refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
