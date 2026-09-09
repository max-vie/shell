#!/usr/bin/env python3
"""Validate the public SUDO identity and access contracts offline."""

from __future__ import annotations

import importlib.util
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
    "keycloak": "keycloak-profile.json",
    "kubernetes": "kubernetes-ecosystem-profile.json",
    "operator": "operator-access-profile.json",
}
CONTRACT_VERSIONS = {
    "delivery-host-profile": "2.0.0",
    "delivery-input-contract": "1.0.0",
    "freeipa-host-profile": "2.1.0",
    "freeipa-input-contract": "1.0.0",
    "velero-gcs-input-contract": "1.0.0",
    "identity-model": "1.1.0",
    "cosign-trust-input-contract": "1.0.0",
    "keycloak-input-contract": "1.0.0",
    "keycloak-profile": "1.0.0",
    "kubernetes-ecosystem-profile": "1.0.0",
    "kubernetes-ecosystem-input-contract": "1.0.0",
    "operator-access-profile": "1.0.0",
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
SOPS_AGE = "sops-age"
PLAINTEXT_AGE_IDENTITY = "plaintext-age-identity"
SERVICE_GENERATED_PRIVATE_STATE = "service-generated-private-state"


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
            "init": "freeipa-host-and-directory-groups",
            "make": "workload-authorization",
            "status": "source-defined",
        },
        "identity implementation boundary changed",
    )


def validate_operator(document: dict[str, Any]) -> None:
    label = "operator access profile"
    require_common(
        document,
        label=label,
        contract_id="operator-access-profile",
        consumers=["init"],
        fields={"access_boundary", "value_policy"},
    )
    require(
        document["access_boundary"]
        == {
            "human_bootstrap": {
                "principal_type": "human",
                "authentication": "user-authenticated",
                "can_impersonate": "shell-local-deployer",
                "max_token_lifetime_seconds": 3600,
                "binding_scope": "service-account-only",
                "grant": {
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "target": "shell-local-deployer",
                },
            },
            "deployment_service_account": {
                "principal_type": "service-account",
                "logical_name": "shell-local-deployer",
                "service_account_keys": "prohibited",
                "role_classes": [
                    {
                        "name": "network-operator",
                        "scope": "project",
                        "permissions": [
                            "compute.firewalls.create",
                            "compute.firewalls.delete",
                            "compute.firewalls.get",
                            "compute.firewalls.update",
                            "compute.globalOperations.get",
                            "compute.networks.create",
                            "compute.networks.delete",
                            "compute.networks.get",
                            "compute.networks.update",
                            "compute.projects.get",
                            "compute.regionOperations.get",
                            "compute.regions.get",
                            "compute.routers.create",
                            "compute.routers.delete",
                            "compute.routers.get",
                            "compute.routers.update",
                            "compute.subnetworks.create",
                            "compute.subnetworks.delete",
                            "compute.subnetworks.get",
                            "compute.subnetworks.setPrivateIpGoogleAccess",
                            "compute.subnetworks.update",
                        ],
                    }
                    ,
                    {
                        "name": "iap-tunnel-operator",
                        "scope": "declared-vm",
                        "permissions": ["iap.tunnelInstances.accessViaIAP"],
                    },
                ],
                "forbidden_roles": [
                    "roles/owner",
                    "roles/editor",
                    "roles/viewer",
                ],
            },
        },
        "operator access boundary changed",
    )
    require(
        document["value_policy"]
        == {
            "project_identifiers": "omitted",
            "billing_identifiers": "omitted",
            "secret_values": "omitted",
        },
        "operator value policy changed",
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
            "managed_dns_records",
            "execution",
            "private_custody",
            "secret_contract",
            "required_contracts",
            "runtime",
        },
    )
    require(document["platform_scope"] == "shared", "FreeIPA scope changed")
    require(document["placement"] == "gcp", "FreeIPA placement changed")
    require(document["served_clusters"] == CLUSTERS, "FreeIPA clusters changed")
    require(document["inventory_group"] == "identity_nodes", "FreeIPA group changed")
    require(
        document["host"]
        == {
            "name": "identity-01",
            "fqdn": "identity-01.shell.internal",
            "ip_address": "10.77.0.210",
            "operating_system": "almalinux-9",
        },
        "FreeIPA host identity changed",
    )
    identity = document["identity"]
    require(
        isinstance(identity, dict)
        and set(identity)
        == {
            "authority",
            "domain",
            "realm",
            "dns_forwarders",
            "roles",
            "groups",
            "proof_principals",
            "identity_model",
        },
        "FreeIPA identity shape changed",
    )
    require(identity["authority"] == "freeipa", "FreeIPA authority changed")
    require(identity["domain"] == "shell.internal", "FreeIPA domain changed")
    require(identity["realm"] == "SHELL.INTERNAL", "FreeIPA realm changed")
    require(
        identity["dns_forwarders"] == ["1.1.1.1", "9.9.9.9"],
        "FreeIPA DNS forwarders changed",
    )
    require(identity["roles"] == ["identity", "internal-dns"], "FreeIPA roles changed")
    require(identity["groups"] == GROUPS, "FreeIPA groups changed")
    require(
        identity["proof_principals"]
        == {"allowed": "shell-operator", "denied": "shell-denied"},
        "FreeIPA proof principals changed",
    )
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
    managed_dns_records = document["managed_dns_records"]
    require(isinstance(managed_dns_records, list), "FreeIPA DNS records must be a list")
    for record in managed_dns_records:
        require(isinstance(record, dict), "FreeIPA DNS record must be an object")
        require(
            record.get("fqdn") == f"{record.get('name')}.{record.get('zone')}",
            f"FreeIPA DNS name does not match FQDN: {record.get('name')}",
        )
    require(
        managed_dns_records
        == [
            {
                "name": "delivery-01",
                "fqdn": "delivery-01.shell.internal",
                "zone": "shell.internal",
                "record_type": "A",
                "address": "10.77.0.211",
                "service_owner": "init",
            },
            {
                "name": "forgejo",
                "fqdn": "forgejo.shell.internal",
                "zone": "shell.internal",
                "record_type": "A",
                "address": "10.77.0.211",
                "service_owner": "make",
            },
            {
                "name": "registry",
                "fqdn": "registry.shell.internal",
                "zone": "shell.internal",
                "record_type": "A",
                "address": "10.77.0.221",
                "service_owner": "make",
            },
            {
                "name": "releases",
                "fqdn": "releases.shell.internal",
                "zone": "shell.internal",
                "record_type": "A",
                "address": "10.77.0.222",
                "service_owner": "make",
            },
        ],
        "FreeIPA managed DNS records changed",
    )
    execution = document["execution"]
    require(
        isinstance(execution, dict)
        and set(execution) == {"owner", "playbook", "mode", "status"},
        "FreeIPA execution shape changed",
    )
    require(
        execution["owner"] == "init"
        and execution["mode"] == "fixed-controller"
        and execution["status"] == "source-defined",
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
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "secret_store": SOPS_AGE,
            "plaintext_values_tracked": False,
            "publication": "create-only",
        },
        "FreeIPA private custody changed",
    )
    require(
        document["secret_contract"]
        == {
            "format": "sops-age-json",
            "storage": SOPS_AGE,
            "handoff_root": ".local/sudo/identity",
            "handoff": ".local/sudo/identity/freeipa.sops.json",
            "age_key": ".local/sudo/identity/age-key.txt",
            "private_values_tracked": False,
            "constraints": {
                "directory_manager_password": {
                    "min_length": 20,
                    "max_length": 30,
                    "character_set": "ascii-alphanumeric",
                    "reason": "FreeIPA directory-server password compatibility",
                },
                "admin_password": {
                    "min_length": 20,
                    "max_length": 64,
                    "character_set": "ascii-alphanumeric",
                },
                "proof_operator_password": {
                    "min_length": 20,
                    "max_length": 64,
                    "character_set": "ascii-alphanumeric",
                },
                "proof_denied_password": {
                    "min_length": 20,
                    "max_length": 64,
                    "character_set": "ascii-alphanumeric",
                },
            },
            "required_keys": [
                "directory_manager_password",
                "admin_password",
                "proof_operator_password",
                "proof_denied_password",
            ],
        },
        "FreeIPA secret contract changed",
    )
    require(
        document["required_contracts"]
        == {
            "identity_configuration": {
                "owner": "sudo",
                "status": "source-defined",
                "required_fields": ["domain", "realm", "dns_forwarders"],
            },
            "identity_credentials": {
                "owner": "sudo",
                "status": "source-defined",
                "handoff_status": "generated-locally-after-approval",
                "contract": "sudo/secrets/freeipa-input-contract.json",
                "required_keys": [
                    "directory_manager_password",
                    "admin_password",
                    "proof_operator_password",
                    "proof_denied_password",
                ],
            },
            "operating_system": {
                "owner": "init",
                "decision_owner": "man",
                "decision": "man/docs/adr/006-use-almalinux-9-for-freeipa-identity-host.md",
                "status": "source-defined",
                "value": "almalinux-9",
            },
            "artifact_supply": {
                "owner": "tar",
                "status": "source-defined",
                "contract": "tar/manifests/freeipa-supply.json",
            },
        },
        "FreeIPA required contracts changed",
    )
    require_reference(
        document["required_contracts"]["operating_system"]["decision"],
        expected="man/docs/adr/006-use-almalinux-9-for-freeipa-identity-host.md",
        repository_root=repository_root,
        label="FreeIPA operating-system decision",
    )
    require_reference(
        document["required_contracts"]["artifact_supply"]["contract"],
        expected="tar/manifests/freeipa-supply.json",
        repository_root=repository_root,
        label="FreeIPA artifact supply",
    )
    require(
        document["runtime"]
        == {
            "implementation": "native-packages",
            "packages": ["ipa-server", "ipa-server-dns"],
            "completion_marker": "/var/lib/shell/freeipa-install-complete",
            "ports": {
                "tcp": [53, 80, 88, 389, 443, 464, 636],
                "udp": [53, 88, 464],
            },
        },
        "FreeIPA runtime contract changed",
    )


def validate_freeipa_input_contract(repository_root: Path) -> None:
    label = "FreeIPA input contract"
    path = repository_root / "sudo/secrets/freeipa-input-contract.json"
    document = read_json_object(path, label, repository_root=repository_root)
    require_common(
        document,
        label=label,
        contract_id="freeipa-input-contract",
        consumers=["init"],
        fields={"environment", "private_custody", "input", "repository_policy"},
    )
    require(document["environment"] == "environment-gcp", "FreeIPA input environment changed")
    require(
        document["private_custody"]
        == {
            "root": ".local/sudo/identity",
            "storage": SOPS_AGE,
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
            "publication": "create-only",
        },
        "FreeIPA input private custody changed",
    )
    require(
        document["input"]
        == {
            "path": ".local/sudo/identity/freeipa.sops.json",
            "age_key": ".local/sudo/identity/age-key.txt",
            "format": "sops-age-json",
            "required_keys": [
                "directory_manager_password",
                "admin_password",
                "proof_operator_password",
                "proof_denied_password",
            ],
            "constraints": {
                "directory_manager_password": {
                    "min_length": 20,
                    "max_length": 30,
                    "character_set": "ascii-alphanumeric",
                    "reason": "FreeIPA directory-server password compatibility",
                },
                "admin_password": {
                    "min_length": 20,
                    "max_length": 64,
                    "character_set": "ascii-alphanumeric",
                },
                "proof_operator_password": {
                    "min_length": 20,
                    "max_length": 64,
                    "character_set": "ascii-alphanumeric",
                },
                "proof_denied_password": {
                    "min_length": 20,
                    "max_length": 64,
                    "character_set": "ascii-alphanumeric",
                },
            },
        },
        "FreeIPA input contract changed",
    )
    require(
        document["repository_policy"]
        == {"contract_tracked": True, "private_values_tracked": False},
        "FreeIPA input repository policy changed",
    )


def validate_keycloak(document: dict[str, Any], repository_root: Path) -> None:
    label = "Keycloak profile"
    require_common(
        document,
        label=label,
        contract_id="keycloak-profile",
        consumers=["init", "make"],
        fields={
            "environment",
            "identity",
            "service",
            "trust",
            "group_role_mapping",
            "required_contracts",
        },
    )
    require(document["environment"] == "environment-gcp", "Keycloak environment changed")
    require(
        document["identity"]
        == {
            "authority": "freeipa",
            "host_profile": "sudo/access/freeipa-host-profile.json",
            "domain": "shell.internal",
            "realm": "SHELL.INTERNAL",
            "base_dn": "dc=shell,dc=internal",
            "bind_principal": "keycloak-bind",
            "bind_dn": "uid=keycloak-bind,cn=users,cn=accounts,dc=shell,dc=internal",
            "groups": GROUPS,
        },
        "Keycloak identity policy changed",
    )
    require_reference(
        document["identity"]["host_profile"],
        expected="sudo/access/freeipa-host-profile.json",
        repository_root=repository_root,
        label="Keycloak FreeIPA host profile",
    )
    require(
        document["service"]
        == {
            "realm": "shell",
            "hostname": "keycloak.shell-identity.svc.cluster.local",
            "transport": "https",
            "port": 443,
            "target_port": 8443,
            "external_endpoint": False,
            "namespace": "shell-identity",
            "name": "keycloak",
        },
        "Keycloak service boundary changed",
    )
    require(
        document["trust"]
        == {
            "freeipa_ca_handoff": ".local/sudo/keycloak/freeipa-ca.crt",
            "storage": "private-local-file",
            "file_mode": "0600",
            "repository_tracked": False,
        },
        "Keycloak trust handoff changed",
    )
    require(
        document["group_role_mapping"]
        == {
            "platform-admins": "platform-admin",
            "platform-operators": "platform-operator",
            "auditors": "auditor",
        },
        "Keycloak group mapping changed",
    )
    require(
        document["required_contracts"]
        == {
            "input": {
                "owner": "sudo",
                "status": "source-defined",
                "contract": "sudo/secrets/keycloak-input-contract.json",
            },
            "supply": {
                "owner": "tar",
                "status": "source-defined",
                "contract": "tar/manifests/keycloak-supply.json",
            },
            "workload": {
                "owner": "make",
                "status": "source-defined",
                "contract": "make/contracts/keycloak-login-requirements.json",
            },
        },
        "Keycloak required contracts changed",
    )
    require_reference(
        document["required_contracts"]["input"]["contract"],
        expected="sudo/secrets/keycloak-input-contract.json",
        repository_root=repository_root,
        label="Keycloak input contract",
    )
    require_reference(
        document["required_contracts"]["supply"]["contract"],
        expected="tar/manifests/keycloak-supply.json",
        repository_root=repository_root,
        label="Keycloak supply contract",
    )
    require_reference(
        document["required_contracts"]["workload"]["contract"],
        expected="make/contracts/keycloak-login-requirements.json",
        repository_root=repository_root,
        label="Keycloak workload contract",
    )


def validate_keycloak_input_contract(repository_root: Path) -> None:
    label = "Keycloak input contract"
    path = repository_root / "sudo/secrets/keycloak-input-contract.json"
    document = read_json_object(path, label, repository_root=repository_root)
    require_common(
        document,
        label=label,
        contract_id="keycloak-input-contract",
        consumers=["init", "make"],
        fields={"environment", "private_custody", "input", "trust", "repository_policy"},
    )
    require(document["environment"] == "environment-gcp", "Keycloak input environment changed")
    require(
        document["private_custody"]
        == {
            "root": ".local/sudo/keycloak",
            "storage": SOPS_AGE,
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
            "publication": "create-only",
        },
        "Keycloak input private custody changed",
    )
    require(
        document["input"]
        == {
            "path": ".local/sudo/keycloak/keycloak.sops.json",
            "age_key": ".local/sudo/keycloak/age-key.txt",
            "format": "sops-age-json",
            "required_keys": [
                "database_username",
                "database_password",
                "bootstrap_admin_username",
                "bootstrap_admin_password",
                "ldap_bind_password",
            ],
            "fixed_values": {
                "database_username": "keycloak",
                "bootstrap_admin_username": "sso-bootstrap",
            },
            "secret_keys": [
                "database_password",
                "bootstrap_admin_password",
                "ldap_bind_password",
            ],
            "secret_constraints": {
                "min_length": 32,
                "max_length": 64,
                "character_set": "ascii-alphanumeric",
            },
        },
        "Keycloak input shape changed",
    )
    require(
        document["trust"]
        == {
            "freeipa_ca_path": ".local/sudo/keycloak/freeipa-ca.crt",
            "file_mode": "0600",
            "source": "authorized INIT identity CA handoff",
            "repository_tracked": False,
        },
        "Keycloak input trust handoff changed",
    )
    require(
        document["repository_policy"]
        == {"contract_tracked": True, "private_values_tracked": False},
        "Keycloak input repository policy changed",
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
            "service",
            "execution",
            "private_input",
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
            "fqdn": "delivery-01.shell.internal",
            "ip_address": "10.77.0.211",
            "operating_system": "debian-13",
            "intended_roles": ["forgejo", "rootless-runner"],
        },
        "delivery host identity changed",
    )
    trust = document["trust"]
    require(
        isinstance(trust, dict)
        and set(trust)
        == {"domain", "dns_server", "identity_host_profile", "identity_model"},
        "delivery trust shape changed",
    )
    require(trust["domain"] == "shell.internal", "delivery trust domain changed")
    require(trust["dns_server"] == "10.77.0.210", "delivery DNS server changed")
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
    require(
        document["service"]
        == {
            "owner": "make",
            "name": "forgejo",
            "fqdn": "forgejo.shell.internal",
            "port": 443,
            "transport": "https",
            "tls_input": "sudo/secrets/delivery-input-contract.json",
            "certificate_dns_sans": ["forgejo.shell.internal"],
        },
        "delivery service contract changed",
    )
    require_reference(
        document["service"]["tls_input"],
        expected="sudo/secrets/delivery-input-contract.json",
        repository_root=repository_root,
        label="delivery credential contract",
    )
    require(
        document["private_input"]
        == {
            "owner": "sudo",
            "contract": "sudo/secrets/delivery-input-contract.json",
            "contract_tracked": True,
            "private_values_tracked": False,
        },
        "delivery private input changed",
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
            "workload_configuration": {
                "owner": "make",
                "status": "source-defined",
                "contract": "make/contracts/service-node-handoff-requirements.json",
                "handoff_status": "not-defined",
            },
            "service_endpoints": {
                "owner": "make",
                "status": "source-defined",
                "contract": "make/contracts/service-node-handoff-requirements.json",
                "handoff_status": "not-defined",
            },
            "delivery_credentials": {
                "owner": "sudo",
                "status": "source-defined",
                "contract": "sudo/secrets/delivery-input-contract.json",
                "handoff_status": "not-defined",
            },
            "artifact_supply": {
                "owner": "tar",
                "status": "source-defined",
                "contract": "tar/manifests/delivery-supply.json",
                "handoff_status": "not-staged",
            },
        },
        "delivery required contracts changed",
    )
    require_reference(
        document["required_contracts"]["workload_configuration"]["contract"],
        expected="make/contracts/service-node-handoff-requirements.json",
        repository_root=repository_root,
        label="delivery MAKE handoff contract",
    )
    require_reference(
        document["required_contracts"]["artifact_supply"]["contract"],
        expected="tar/manifests/delivery-supply.json",
        repository_root=repository_root,
        label="delivery TAR supply contract",
    )


def validate_delivery_input_contract(
    repository_root: Path,
) -> None:
    label = "delivery input contract"
    path = repository_root / "sudo/secrets/delivery-input-contract.json"
    document = read_json_object(path, label, repository_root=repository_root)
    require_common(
        document,
        label=label,
        contract_id="delivery-input-contract",
        consumers=["make"],
        fields={"private_custody", "private_inputs", "classes", "repository_policy"},
    )
    require(
        document["private_custody"]
        == {
            "root": ".local/sudo/delivery",
            "storage": SOPS_AGE,
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
        },
        "delivery private custody changed",
    )
    require(
        document["private_inputs"]
        == {
            "bootstrap": {
                "path": ".local/sudo/delivery/bootstrap.sops.json",
                "storage": SOPS_AGE,
                "ignored": True,
            },
            "forgejo_public_tls": {
                "path": ".local/sudo/delivery/forgejo-public-tls.sops.json",
                "storage": SOPS_AGE,
                "ignored": True,
            },
            "forgejo_runner": {
                "path": ".local/sudo/delivery/forgejo-runner.sops.json",
                "storage": SOPS_AGE,
                "ignored": True,
                "file_mode": "0600",
            },
            "forgejo_repository": {
                "path": ".local/sudo/delivery/forgejo-repository.sops.json",
                "storage": SOPS_AGE,
                "ignored": True,
                "file_mode": "0600",
            },
            "age_key": {
                "path": ".local/sudo/delivery/age-key.txt",
                "storage": PLAINTEXT_AGE_IDENTITY,
                "consumer": "SOPS_AGE_KEY_FILE",
                "ignored": True,
                "file_mode": "0600",
            },
            "runtime": {
                "path": ".local/sudo/delivery/runtime",
                "storage": SERVICE_GENERATED_PRIVATE_STATE,
                "producer": "forgejo-after-bootstrap",
                "ignored": True,
                "directory_mode": "0700",
            },
        },
        "delivery private input boundary changed",
    )
    require(
        document["classes"]
        == {
            "forgejo_bootstrap": {
                "issuer": "sudo",
                "storage": SOPS_AGE,
                "deployment_target": "delivery-01",
                "required_keys": [
                    "admin_username",
                    "admin_password",
                    "security_secret_key",
                    "internal_token",
                    "jwt_secret",
                ],
                "input_phase": "pre-service",
            },
            "forgejo_public_tls": {
                "issuer": "sudo",
                "storage": SOPS_AGE,
                "deployment_target": "delivery-01",
                "dns_sans": ["forgejo.shell.internal"],
                "required_keys": ["certificate", "private_key", "root_ca"],
                "input_phase": "pre-service",
            },
            "forgejo_runner": {
                "issuer": "forgejo-after-bootstrap",
                "storage": SOPS_AGE,
                "deployment_target": "delivery-01",
                "required_keys": ["url", "uuid", "token"],
                "one_time_bootstrap": True,
                "input_phase": "post-service",
            },
            "forgejo_repository": {
                "issuer": "forgejo-after-bootstrap",
                "storage": SOPS_AGE,
                "deployment_target": "delivery-node-only",
                "transport": "https",
                "repository_url": "https://forgejo.shell.internal/shell/make.git",
                "required_keys": ["url", "username", "api_token"],
                "one_time_bootstrap": True,
                "rotation": "explicit-approved",
                "input_phase": "post-service",
            },
        },
        "delivery input classes changed",
    )
    require(
        document["repository_policy"]
        == {"contract_tracked": True, "private_values_tracked": False},
        "delivery repository policy changed",
    )


def validate_kubernetes(document: dict[str, Any], repository_root: Path) -> None:
    label = "Kubernetes ecosystem profile"
    require_common(
        document,
        label=label,
        contract_id="kubernetes-ecosystem-profile",
        consumers=["make"],
        fields={"cluster_scope", "identity", "admission_trust", "required_contracts"},
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
            "authentication_integration": {
                "owner": "make",
                "status": "source-defined",
                "contract": "sudo/access/keycloak-profile.json",
            },
            "workload_authorization": {
                "owner": "make",
                "policy_owner": "sudo",
                "status": "not-defined",
            },
            "service_endpoints": {
                "owner": "make",
                "status": "source-defined",
                "contract": "sudo/access/keycloak-profile.json",
            },
            "cluster_trust": {
                "owner": "make",
                "status": "source-defined",
                "contract": "make/contracts/cluster-trust-requirements.json",
                "handoff_status": "not-defined",
            },
        },
        "Kubernetes required contracts changed",
    )
    require(
        document["admission_trust"]
        == {
            "owner": "sudo",
            "status": "source-defined",
            "contract": "sudo/secrets/cosign-trust-input-contract.json",
        },
        "Kubernetes admission trust changed",
    )
    require_reference(
        document["admission_trust"]["contract"],
        expected="sudo/secrets/cosign-trust-input-contract.json",
        repository_root=repository_root,
        label="Kubernetes admission trust contract",
    )
    require_reference(
        document["required_contracts"]["cluster_trust"]["contract"],
        expected="make/contracts/cluster-trust-requirements.json",
        repository_root=repository_root,
        label="Kubernetes cluster-trust contract",
    )
    for name in ("authentication_integration", "service_endpoints"):
        require_reference(
            document["required_contracts"][name]["contract"],
            expected="sudo/access/keycloak-profile.json",
            repository_root=repository_root,
            label=f"Kubernetes {name} contract",
        )


def validate_kubernetes_input_contract(repository_root: Path) -> None:
    label = "Kubernetes ecosystem input contract"
    path = repository_root / "sudo/secrets/kubernetes-ecosystem-input-contract.json"
    document = read_json_object(path, label, repository_root=repository_root)
    require_common(
        document,
        label=label,
        contract_id="kubernetes-ecosystem-input-contract",
        consumers=["make"],
        fields={"private_custody", "public_trust", "clusters"},
    )
    require(
        document["private_custody"]
        == {
            "root": ".local/sudo/kubernetes",
            "storage": "sops-age",
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
        },
        "Kubernetes private custody changed",
    )
    public_trust = document["public_trust"]
    require(
        isinstance(public_trust, dict)
        and public_trust
        == {
            "root_certificate": "sudo/pki/shell-offline-root.crt.pem",
            "tracked": True,
            "issuer": "shell-offline-root",
        },
        "Kubernetes public trust changed",
    )
    root_certificate = repository_root / public_trust["root_certificate"]
    root_path = resolve_repository_file(
        root_certificate,
        repository_root=repository_root,
        label="Kubernetes public root certificate",
    )
    try:
        root_contents = root_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise AccessContractError(
            "Kubernetes public root certificate is unreadable"
        ) from error
    require(
        root_contents.startswith("-----BEGIN CERTIFICATE-----")
        and root_contents.rstrip().endswith("-----END CERTIFICATE-----")
        and "PRIVATE KEY" not in root_contents,
        "Kubernetes public root certificate is not public PEM data",
    )
    require(
        document["clusters"]
        == {
            "gcp": {
                "handoff": ".local/sudo/kubernetes/gcp/cluster-intermediate.sops.json",
                "deployment_target": "gcp",
                "storage": "sops-age",
                "required_keys": ["certificate", "private_key", "root_ca"],
                "input_phase": "pre-issuer",
            },
            "proxmox": {
                "handoff": ".local/sudo/kubernetes/proxmox/cluster-intermediate.sops.json",
                "deployment_target": "proxmox",
                "storage": "sops-age",
                "required_keys": ["certificate", "private_key", "root_ca"],
                "input_phase": "pre-issuer",
            },
        },
        "Kubernetes cluster trust handoffs changed",
    )


def validate_cosign_trust_input_contract(repository_root: Path) -> None:
    label = "Cosign trust input contract"
    path = repository_root / "sudo/secrets/cosign-trust-input-contract.json"
    document = read_json_object(path, label, repository_root=repository_root)
    require_common(
        document,
        label=label,
        contract_id="cosign-trust-input-contract",
        consumers=["make"],
        fields={
            "environment",
            "private_custody",
            "input",
            "public_trust",
            "repository_policy",
        },
    )
    require(document["environment"] == "environment-gcp", "Cosign input environment changed")
    require(
        document["private_custody"]
        == {
            "root": ".local/sudo/kubernetes/cosign",
            "storage": SOPS_AGE,
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
            "publication": "create-only",
        },
        "Cosign private custody changed",
    )
    require(
        document["input"]
        == {
            "path": ".local/sudo/kubernetes/cosign/cosign.sops.json",
            "public_handoff": ".local/sudo/kubernetes/cosign/cosign-public.sops.json",
            "age_key": ".local/sudo/kubernetes/cosign/age-key.txt",
            "cosign_binary": ".local/tar/kubernetes/tools/cosign",
            "format": "sops-age-json",
            "required_keys": ["private_key", "password", "public_key"],
            "public_required_keys": ["public_key"],
            "private_key_format": "encrypted-sigstore-private-key-pem",
            "public_key_format": "public-key-pem",
            "password": {
                "min_length": 32,
                "max_length": 64,
                "character_set": "ascii-alphanumeric",
            },
        },
        "Cosign input shape changed",
    )
    require(
        document["public_trust"]
        == {
            "namespace": "shell-trust",
            "secret_name": "cosign-public-keys",
            "key": "cosign.pub",
            "handoff_status": "not-defined",
        },
        "Cosign public trust handoff changed",
    )
    require(
        document["repository_policy"]
        == {"contract_tracked": True, "private_values_tracked": False},
        "Cosign input repository policy changed",
    )


def validate_velero_gcs_input_contract(repository_root: Path) -> None:
    label = "Velero GCS input contract"
    path = repository_root / "sudo/secrets/velero-gcs-input-contract.json"
    document = read_json_object(path, label, repository_root=repository_root)
    require_common(
        document,
        label=label,
        contract_id="velero-gcs-input-contract",
        consumers=["make"],
        fields={
            "environment",
            "private_custody",
            "input",
            "bucket",
            "repository_policy",
        },
    )
    require(document["environment"] == "environment-gcp", "Velero GCS environment changed")
    require(
        document["private_custody"]
        == {
            "root": ".local/init/gcs-backup",
            "storage": "init-generated-service-account-key",
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
            "publication": "create-only",
        },
        "Velero GCS private custody changed",
    )
    require(
        document["input"]
        == {
            "path": ".local/init/gcs-backup/credentials.json",
            "format": "google-service-account-json",
            "producer": "init/opentofu/gcs-backup",
            "service_account_id": "velero-backup",
            "required_keys": [
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
            ],
            "private_key_format": "pkcs8-pem",
            "rotation": "explicit-approved",
        },
        "Velero GCS input shape changed",
    )
    require(
        document["bucket"]
        == {
            "name_source": "init/opentofu/gcs-backup bucket_name input",
            "location": "europe-west4",
            "role": "roles/storage.objectAdmin",
            "public_access_prevention": "enforced",
            "uniform_bucket_level_access": True,
        },
        "Velero GCS bucket policy changed",
    )
    require(
        document["repository_policy"]
        == {"contract_tracked": True, "private_values_tracked": False},
        "Velero GCS repository policy changed",
    )


def validate_k3s_server_token_contract(repository_root: Path) -> None:
    """Run the SUDO-owned server-token validator as part of the aggregate gate."""

    script = resolve_repository_file(
        repository_root / "sudo/scripts/generate_k3s_server_tokens.py",
        repository_root=repository_root,
        label="K3s server-token validator",
    )
    contract = resolve_repository_file(
        repository_root / "sudo/secrets/k3s-server-token-contract.json",
        repository_root=repository_root,
        label="K3s server-token contract",
    )
    spec = importlib.util.spec_from_file_location(
        "sudo_k3s_server_token_validator", script
    )
    if spec is None or spec.loader is None:
        raise AccessContractError("cannot load K3s server-token validator")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        module.validate_contract(contract)
    except (OSError, UnicodeError, ValueError) as error:
        raise AccessContractError("K3s server-token contract is invalid") from error


def validate_stateful_input_contracts(repository_root: Path) -> None:
    """Run the SUDO-owned registry and OpenBao contract validator."""

    script = resolve_repository_file(
        repository_root / "sudo/scripts/validate_stateful_inputs.py",
        repository_root=repository_root,
        label="stateful-input validator",
    )
    spec = importlib.util.spec_from_file_location(
        "sudo_stateful_input_validator", script
    )
    if spec is None or spec.loader is None:
        raise AccessContractError("cannot load stateful-input validator")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        module.validate_release_feed(
            repository_root / "sudo/secrets/release-feed-input-contract.json"
        )
        module.validate_openbao(
            repository_root / "sudo/secrets/openbao-bootstrap-contract.json"
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise AccessContractError("stateful-input contracts are invalid") from error


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
    validate_operator(documents["operator"])
    validate_freeipa(documents["freeipa"], repository_root)
    validate_freeipa_input_contract(repository_root)
    validate_keycloak(documents["keycloak"], repository_root)
    validate_keycloak_input_contract(repository_root)
    validate_delivery(documents["delivery"], repository_root)
    validate_delivery_input_contract(repository_root)
    validate_kubernetes(documents["kubernetes"], repository_root)
    validate_kubernetes_input_contract(repository_root)
    validate_cosign_trust_input_contract(repository_root)
    validate_velero_gcs_input_contract(repository_root)
    validate_k3s_server_token_contract(repository_root)
    validate_stateful_input_contracts(repository_root)
    return documents


def main() -> int:
    try:
        documents = validate_contracts(REPOSITORY_ROOT)
    except AccessContractError as error:
        print(f"access contract validation failed: {error}", file=sys.stderr)
        return 2
    print(f"validated {len(documents)} SUDO access profiles and 9 handoff contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
