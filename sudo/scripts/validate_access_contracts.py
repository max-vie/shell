#!/usr/bin/env python3
"""Validate the public SUDO identity and access contracts offline."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ACCESS_DIRECTORY = Path("sudo/access")
CONTRACT_FILES = {
    "delivery": "delivery-host-profile.json",
    "freeipa": "freeipa-host-profile.json",
    "identity": "identity-model.json",
    "kubernetes": "kubernetes-ecosystem-profile.json",
}
CONTRACT_VERSIONS = {
    "delivery-host-profile": "2.0.0",
    "freeipa-host-profile": "2.0.0",
    "identity-model": "1.0.0",
    "kubernetes-ecosystem-profile": "1.0.0",
}
COMMON_FIELDS = {
    "schema_version",
    "contract_version",
    "contract_id",
    "description",
    "policy_owner",
    "consumer_owners",
    "proof_status",
}
CLUSTERS = ["gcp", "proxmox"]
GROUPS = ["platform-admins", "platform-operators", "auditors"]
UNDECIDED = "undecided"


class AccessContractError(ValueError):
    """A public SUDO access contract is invalid or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AccessContractError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def resolve_repository_file(
    path: Path,
    *,
    repository_root: Path,
    label: str,
) -> Path:
    require(not path.is_symlink(), f"missing regular {label}: {path}")
    try:
        resolved_root = repository_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise AccessContractError(f"missing regular {label}: {path}") from error
    require(
        resolved_path.is_relative_to(resolved_root),
        f"unsafe {label}: outside repository",
    )
    require(resolved_path.is_file(), f"missing regular {label}: {path}")
    return resolved_path


def read_json_object(
    path: Path,
    label: str,
    *,
    repository_root: Path,
) -> dict[str, Any]:
    resolved_path = resolve_repository_file(
        path,
        repository_root=repository_root,
        label=label,
    )
    try:
        value = json.loads(
            resolved_path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AccessContractError(f"invalid JSON for {label}: {path}") from error
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    return cast(dict[str, Any], value)


def require_common(
    document: dict[str, Any],
    *,
    label: str,
    contract_id: str,
    consumers: list[str],
    fields: set[str],
) -> None:
    require(set(document) == COMMON_FIELDS | fields, f"{label} shape changed")
    require(document["schema_version"] == "1.0", f"{label} schema changed")
    require(
        document["contract_version"] == CONTRACT_VERSIONS[contract_id],
        f"{label} version changed",
    )
    require(document["contract_id"] == contract_id, f"{label} ID changed")
    require(
        isinstance(document["description"], str)
        and bool(document["description"].strip()),
        f"{label} description is empty",
    )
    require(document["policy_owner"] == "sudo", f"{label} owner must be SUDO")
    require(document["consumer_owners"] == consumers, f"{label} consumers changed")
    require(
        document["proof_status"] == "source-only",
        f"{label} must remain source-only",
    )


def require_reference(
    value: Any,
    *,
    expected: str,
    repository_root: Path,
    label: str,
) -> None:
    require(value == expected, f"{label} reference changed")
    relative = Path(expected)
    require(
        not relative.is_absolute() and ".." not in relative.parts, f"unsafe {label}"
    )
    resolve_repository_file(
        repository_root / relative,
        repository_root=repository_root,
        label=label,
    )


def validate_identity(document: dict[str, Any]) -> None:
    label = "identity model"
    require_common(
        document,
        label=label,
        contract_id="identity-model",
        consumers=["init", "make"],
        fields={
            "identity_authority",
            "cluster_scope",
            "groups",
            "default_access",
            "implementation",
        },
    )
    require(document["identity_authority"] == "freeipa", "identity authority changed")
    require(document["cluster_scope"] == CLUSTERS, "identity cluster scope changed")
    require(
        document["groups"]
        == {
            "platform-admins": {"access_level": "admin"},
            "platform-operators": {"access_level": "operate"},
            "auditors": {"access_level": "read-only"},
        },
        "identity groups changed",
    )
    require(document["default_access"] == "deny", "default access must deny")
    require(
        document["implementation"]
        == {
            "init": "host-and-directory-groups",
            "make": "workload-authorization",
            "status": "not-defined",
        },
        "identity implementation boundary changed",
    )


def validate_freeipa(document: dict[str, Any], repository_root: Path) -> None:
    label = "FreeIPA host profile"
    require_common(
        document,
        label=label,
        contract_id="freeipa-host-profile",
        consumers=["init"],
        fields={
            "platform_scope",
            "placement",
            "served_clusters",
            "inventory_group",
            "host",
            "identity",
            "network",
            "execution",
            "private_custody",
            "required_contracts",
        },
    )
    require(document["platform_scope"] == "shared", "FreeIPA scope changed")
    require(document["placement"] == "gcp", "FreeIPA placement changed")
    require(document["served_clusters"] == CLUSTERS, "FreeIPA clusters changed")
    require(document["inventory_group"] == "identity_nodes", "FreeIPA group changed")
    require(
        document["host"] == {"name": "identity-01", "ip_address": "10.77.0.210"},
        "FreeIPA host identity changed",
    )
    identity = document["identity"]
    require(
        isinstance(identity, dict)
        and set(identity) == {"authority", "roles", "groups", "identity_model"},
        "FreeIPA identity shape changed",
    )
    require(identity["authority"] == "freeipa", "FreeIPA authority changed")
    require(identity["roles"] == ["identity", "internal-dns"], "FreeIPA roles changed")
    require(identity["groups"] == GROUPS, "FreeIPA groups changed")
    require_reference(
        identity["identity_model"],
        expected="sudo/access/identity-model.json",
        repository_root=repository_root,
        label="FreeIPA identity model",
    )
    require(
        document["network"]
        == {
            "tcp_ports": [53, 80, 88, 389, 443, 464, 636],
            "udp_ports": [53, 88, 464],
        },
        "FreeIPA network contract changed",
    )
    execution = document["execution"]
    require(
        isinstance(execution, dict)
        and set(execution) == {"owner", "playbook", "mode", "status"},
        "FreeIPA execution shape changed",
    )
    require(
        execution["owner"] == "init"
        and execution["mode"] == "contract-preview"
        and execution["status"] == "blocked-by-required-contracts",
        "FreeIPA execution boundary changed",
    )
    require_reference(
        execution["playbook"],
        expected="init/ansible/playbooks/configure-identity-service.yml",
        repository_root=repository_root,
        label="FreeIPA execution playbook",
    )
    require(
        document["private_custody"]
        == {
            "root": ".local/sudo/identity",
            "tracked": False,
            "directory_mode": "0700",
            "file_mode": "0600",
            "secret_store": UNDECIDED,
        },
        "FreeIPA private custody changed",
    )
    require(
        document["required_contracts"]
        == {
            "identity_configuration": {
                "owner": "sudo",
                "status": "not-defined",
                "required_fields": ["dns_domain", "kerberos_realm", "dns_forwarders"],
            },
            "identity_credentials": {
                "owner": "sudo",
                "status": "not-defined",
                "required_keys": ["directory_manager_password", "admin_password"],
            },
            "operating_system": {
                "owner": "init",
                "decision_owner": "man",
                "status": "not-defined",
            },
            "artifact_supply": {"owner": "tar", "status": "not-defined"},
        },
        "FreeIPA required contracts changed",
    )


def validate_delivery(document: dict[str, Any], repository_root: Path) -> None:
    label = "delivery host profile"
    require_common(
        document,
        label=label,
        contract_id="delivery-host-profile",
        consumers=["init", "make"],
        fields={
            "platform_scope",
            "placement",
            "served_clusters",
            "inventory_group",
            "host",
            "trust",
            "execution",
            "required_contracts",
        },
    )
    require(document["platform_scope"] == "shared", "delivery scope changed")
    require(document["placement"] == "gcp", "delivery placement changed")
    require(document["served_clusters"] == CLUSTERS, "delivery clusters changed")
    require(document["inventory_group"] == "delivery_nodes", "delivery group changed")
    require(
        document["host"]
        == {
            "name": "delivery-01",
            "ip_address": "10.77.0.211",
            "operating_system": "debian-13",
            "intended_roles": ["forgejo", "rootless-runner"],
        },
        "delivery host identity changed",
    )
    trust = document["trust"]
    require(
        isinstance(trust, dict)
        and set(trust) == {"identity_host_profile", "identity_model"},
        "delivery trust shape changed",
    )
    require_reference(
        trust["identity_host_profile"],
        expected="sudo/access/freeipa-host-profile.json",
        repository_root=repository_root,
        label="delivery identity host profile",
    )
    require_reference(
        trust["identity_model"],
        expected="sudo/access/identity-model.json",
        repository_root=repository_root,
        label="delivery identity model",
    )
    execution = document["execution"]
    require(
        isinstance(execution, dict)
        and set(execution) == {"owner", "playbook", "mode", "status"},
        "delivery execution shape changed",
    )
    require(
        execution["owner"] == "init"
        and execution["mode"] == "contract-preview"
        and execution["status"] == "blocked-by-required-contracts",
        "delivery execution boundary changed",
    )
    require_reference(
        execution["playbook"],
        expected="init/ansible/playbooks/configure-delivery-node.yml",
        repository_root=repository_root,
        label="delivery execution playbook",
    )
    require(
        document["required_contracts"]
        == {
            "workload_configuration": {"owner": "make", "status": "not-defined"},
            "service_endpoints": {"owner": "make", "status": "not-defined"},
            "delivery_credentials": {"owner": "sudo", "status": "not-defined"},
        },
        "delivery required contracts changed",
    )


def validate_kubernetes(document: dict[str, Any], repository_root: Path) -> None:
    label = "Kubernetes ecosystem profile"
    require_common(
        document,
        label=label,
        contract_id="kubernetes-ecosystem-profile",
        consumers=["make"],
        fields={"cluster_scope", "identity", "required_contracts"},
    )
    require(document["cluster_scope"] == CLUSTERS, "Kubernetes cluster scope changed")
    identity = document["identity"]
    require(
        isinstance(identity, dict)
        and set(identity)
        == {"authority", "identity_host_profile", "identity_model", "required_groups"},
        "Kubernetes identity shape changed",
    )
    require(identity["authority"] == "freeipa", "Kubernetes authority changed")
    require(identity["required_groups"] == GROUPS, "Kubernetes groups changed")
    require_reference(
        identity["identity_host_profile"],
        expected="sudo/access/freeipa-host-profile.json",
        repository_root=repository_root,
        label="Kubernetes identity host profile",
    )
    require_reference(
        identity["identity_model"],
        expected="sudo/access/identity-model.json",
        repository_root=repository_root,
        label="Kubernetes identity model",
    )
    require(
        document["required_contracts"]
        == {
            "authentication_integration": {"owner": "make", "status": "not-defined"},
            "workload_authorization": {
                "owner": "make",
                "policy_owner": "sudo",
                "status": "not-defined",
            },
            "service_endpoints": {"owner": "make", "status": "not-defined"},
        },
        "Kubernetes required contracts changed",
    )


def validate_contracts(
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, dict[str, Any]]:
    """Validate public access contracts and their source references offline."""

    access_root = repository_root / ACCESS_DIRECTORY
    documents = {
        name: read_json_object(
            access_root / filename,
            name,
            repository_root=repository_root,
        )
        for name, filename in CONTRACT_FILES.items()
    }
    validate_identity(documents["identity"])
    validate_freeipa(documents["freeipa"], repository_root)
    validate_delivery(documents["delivery"], repository_root)
    validate_kubernetes(documents["kubernetes"], repository_root)
    return documents


def main() -> int:
    try:
        documents = validate_contracts(REPOSITORY_ROOT)
    except AccessContractError as error:
        print(f"access contract validation failed: {error}", file=sys.stderr)
        return 2
    print(f"validated {len(documents)} SUDO access contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
