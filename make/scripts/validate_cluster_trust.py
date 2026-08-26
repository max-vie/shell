#!/usr/bin/env python3
"""Validate the source-only MAKE cluster-trust contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPOSITORY_ROOT / "make/contracts/cluster-trust-requirements.json"
SOURCE_CONTRACTS = {
    "kubernetes_profile": "sudo/access/kubernetes-ecosystem-profile.json",
    "kubernetes_inputs": "sudo/secrets/kubernetes-ecosystem-input-contract.json",
    "kubernetes_supply": "tar/manifests/kubernetes-ecosystem-supply.json",
    "init_runtime_launcher": "init/scripts/run_k3s_runtime.py",
}
MANIFEST_PATHS = {
    "issuer": "make/cert-manager/cluster-issuer.json",
    "consumer_certificate": "make/certificates/forgejo-tls.json",
    "values": "make/cert-manager/values.yaml",
}
CLUSTER_SECRET_NAME = "shell-cluster-intermediate"  # nosec B105
CONSUMER_SECRET_NAME = "forgejo-tls"  # nosec B105


class ClusterTrustError(ValueError):
    """The MAKE cluster-trust contract is invalid or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ClusterTrustError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def read_json(path: Path, label: str) -> dict[str, Any]:
    for component in (path, *path.parents):
        require(not component.is_symlink(), f"unsafe symlinked {label}: {component}")
    require(path.is_file(), f"missing regular {label}: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ClusterTrustError(f"invalid JSON for {label}: {path}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


def read_reference(
    repository_root: Path, relative: str, label: str
) -> dict[str, Any] | Path:
    path = repository_root / relative
    if path.suffix == ".json":
        return read_json(path, label)
    for component in (path, *path.parents):
        require(not component.is_symlink(), f"unsafe symlinked {label}: {component}")
    require(path.is_file(), f"missing regular {label}: {path}")
    return path


def validate_manifests(contract: dict[str, Any], repository_root: Path) -> None:
    manifests = contract["manifests"]
    require(manifests == MANIFEST_PATHS, "cluster-trust manifest paths changed")
    issuer = cast(
        dict[str, Any],
        read_reference(repository_root, manifests["issuer"], "issuer manifest"),
    )
    require(
        issuer
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
        "issuer manifest changed",
    )
    certificate = cast(
        dict[str, Any],
        read_reference(
            repository_root,
            manifests["consumer_certificate"],
            "consumer certificate manifest",
        ),
    )
    require(
        certificate
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
    values_path = cast(Path, read_reference(repository_root, manifests["values"], "cert-manager values"))
    values = values_path.read_text(encoding="utf-8")
    require("networkPolicy:\n  enabled: false" in values, "cert-manager values must match the Flannel foundation")
    require("latest" not in values, "cert-manager values must not use latest images")
    for digest in (
        "sha256:e370f7800a53078e9d74324287a7d52b553864e55f5b4e521f911c3f6c7da203",
        "sha256:c33cca307541e2d58861a55b1af5f390b7e19c8741e48b433693b73a7cce88b3",
        "sha256:ad1dcc5b2fccc420f9b3fbee7ce8a869450c540fd4f2f41de2d95b1ca0c4d701",
        "sha256:68b3c5029dc63e64a6b6435337d7dc0eb169f889a48a02d999d1f22f31865b33",
    ):
        require(digest in values, f"cert-manager image digest is missing: {digest}")


def validate_source_contracts(contract: dict[str, Any], repository_root: Path) -> None:
    require(contract["source_contracts"] == SOURCE_CONTRACTS, "cluster-trust source references changed")
    profile = cast(dict[str, Any], read_reference(repository_root, SOURCE_CONTRACTS["kubernetes_profile"], "SUDO Kubernetes profile"))
    require(profile.get("contract_id") == "kubernetes-ecosystem-profile", "SUDO Kubernetes profile changed")
    require(profile.get("proof_status") == "source-only", "SUDO Kubernetes profile proof changed")
    profile_contracts = profile.get("required_contracts")
    if not isinstance(profile_contracts, dict):
        raise ClusterTrustError("SUDO Kubernetes profile contract map changed")
    require(
        profile_contracts.get("cluster_trust")
        == {
            "owner": "make",
            "status": "source-defined",
            "contract": "make/contracts/cluster-trust-requirements.json",
            "handoff_status": "not-defined",
        },
        "SUDO cluster-trust contract reference changed",
    )
    inputs = cast(dict[str, Any], read_reference(repository_root, SOURCE_CONTRACTS["kubernetes_inputs"], "SUDO Kubernetes inputs"))
    require(inputs.get("contract_id") == "kubernetes-ecosystem-input-contract", "SUDO Kubernetes input contract changed")
    require(inputs.get("proof_status") == "source-only", "SUDO Kubernetes input proof changed")
    custody = inputs.get("private_custody")
    if not isinstance(custody, dict):
        raise ClusterTrustError("SUDO Kubernetes custody changed")
    require(custody.get("storage") == "sops-age", "SUDO Kubernetes custody changed")
    clusters = inputs.get("clusters")
    if not isinstance(clusters, dict):
        raise ClusterTrustError("SUDO cluster handoffs changed")
    require(set(clusters) == {"gcp", "proxmox"}, "SUDO cluster handoffs changed")
    supply = cast(dict[str, Any], read_reference(repository_root, SOURCE_CONTRACTS["kubernetes_supply"], "TAR Kubernetes supply"))
    require(supply.get("contract_id") == "kubernetes-ecosystem-supply", "TAR Kubernetes supply changed")
    require(supply.get("proof_status") == "source-reference-only", "TAR Kubernetes supply proof changed")
    read_reference(repository_root, SOURCE_CONTRACTS["init_runtime_launcher"], "INIT runtime launcher")


def validate_contract(
    path: Path = CONTRACT_PATH, *, repository_root: Path = REPOSITORY_ROOT
) -> dict[str, Any]:
    contract = read_json(path, "cluster-trust contract")
    require(
        set(contract)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "producer_owners",
            "consumer_owners",
            "proof_status",
            "cluster_scope",
            "source_contracts",
            "kubeconfig_pattern",
            "resources",
            "manifests",
            "excluded_fields",
        },
        "cluster-trust contract shape changed",
    )
    require(contract["schema_version"] == "1.0", "cluster-trust schema changed")
    require(contract["contract_version"] == "1.0.0", "cluster-trust version changed")
    require(contract["contract_id"] == "cluster-trust-requirements", "cluster-trust ID changed")
    require(contract["policy_owner"] == "make", "MAKE must own cluster-trust requirements")
    require(contract["producer_owners"] == ["sudo", "tar", "init"], "cluster-trust producers changed")
    require(contract["consumer_owners"] == ["make"], "cluster-trust consumers changed")
    require(contract["proof_status"] == "source-only", "cluster-trust proof changed")
    require(contract["cluster_scope"] == ["gcp", "proxmox"], "cluster-trust clusters changed")
    require(contract["kubeconfig_pattern"] == ".local/ansible/kubeconfig/{cluster}.yaml", "cluster-trust kubeconfig pattern changed")
    require(
        contract["resources"]
        == {
            "issuer": {
                "api_version": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "name": "shell-cluster-intermediate",
                "namespace": "cert-manager",
                "secret_name": CLUSTER_SECRET_NAME,
                "owner": "sudo",
            },
            "consumer_certificate": {
                "api_version": "cert-manager.io/v1",
                "kind": "Certificate",
                "name": "forgejo-tls",
                "namespace": "default",
                "secret_name": CONSUMER_SECRET_NAME,
                "issuer_name": CLUSTER_SECRET_NAME,
                "issuer_kind": "ClusterIssuer",
                "dns_names": ["forgejo.shell.internal"],
                "owner": "make",
            },
        },
        "cluster-trust resources changed",
    )
    require(contract["excluded_fields"] == ["credentials", "private_keys", "tokens", "kubeconfig_data"], "cluster-trust exclusions changed")
    validate_source_contracts(contract, repository_root)
    validate_manifests(contract, repository_root)
    return contract


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    args = parser.parse_args(argv)
    try:
        validate_contract(args.contract)
    except (ClusterTrustError, OSError) as error:
        print(f"cluster-trust validation failed: {error}", file=sys.stderr)
        return 2
    print("validated MAKE cluster-trust requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
