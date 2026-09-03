#!/usr/bin/env python3
"""Validate the source-only Keycloak workload boundary."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast

import yaml

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))
TAR_SCRIPTS = SCRIPT_ROOT.parents[1] / "tar/scripts"
SUDO_SCRIPTS = SCRIPT_ROOT.parents[1] / "sudo/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
if str(SUDO_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SUDO_SCRIPTS))

import validate_access_contracts as access  # noqa: E402
import validate_keycloak_supply as supply  # noqa: E402


ROOT = SCRIPT_ROOT.parents[1]
PROFILE = ROOT / "sudo/access/keycloak-profile.json"
CONTRACT = ROOT / "make/contracts/keycloak-login-requirements.json"
PLATFORM = ROOT / "make/gitops/platform/keycloak"
APPLICATION = ROOT / "make/gitops/applications/children/keycloak.yaml"
MANIFEST_NAMES = (
    "namespace.yaml",
    "certificate.yaml",
    "root-ca.yaml",
    "realm.yaml",
    "service.yaml",
    "networkpolicy.yaml",
    "deployment.yaml",
    "postgresql.yaml",
)
IMAGE_PATTERN = re.compile(r"^.+@sha256:[0-9a-f]{64}$")


class KeycloakValidationError(ValueError):
    """Keycloak source validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KeycloakValidationError(message)


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, f"duplicate JSON key in {label}: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise KeycloakValidationError(f"{label} is invalid JSON") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(dict[str, Any], value)


def read_yaml(path: Path) -> list[dict[str, Any]]:
    require(path.is_file() and not path.is_symlink(), f"Keycloak source is missing: {path.name}")
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise KeycloakValidationError(f"Keycloak source is invalid YAML: {path.name}") from error
    result: list[dict[str, Any]] = []
    for document in documents:
        require(isinstance(document, dict), f"Keycloak document is not a mapping: {path.name}")
        result.append(cast(dict[str, Any], document))
    return result


def resource(resources: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    matches = [
        item
        for item in resources
        if item.get("kind") == kind and item.get("metadata", {}).get("name") == name
    ]
    require(len(matches) == 1, f"Keycloak source must contain one {kind}/{name}")
    return matches[0]


def containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in ("initContainers", "containers"):
        values = pod_spec.get(key, [])
        require(isinstance(values, list), f"Keycloak pod {key} is invalid")
        result.extend(cast(list[dict[str, Any]], values))
    return result


def validate_workload_contract() -> dict[str, Any]:
    document = read_json(CONTRACT, "Keycloak workload contract")
    require(
        set(document)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "producer_owners",
            "consumer_owners",
            "proof_status",
            "environment",
            "source_contracts",
            "workload",
            "excluded_fields",
        },
        "Keycloak workload contract shape changed",
    )
    require(document["schema_version"] == "1.0", "Keycloak workload schema changed")
    require(document["contract_version"] == "1.0.0", "Keycloak workload version changed")
    require(document["contract_id"] == "keycloak-login-requirements", "Keycloak workload ID changed")
    require(document["policy_owner"] == "make", "MAKE must own Keycloak workload requirements")
    require(document["producer_owners"] == ["sudo", "tar", "init"], "Keycloak workload producers changed")
    require(document["consumer_owners"] == ["make"], "Keycloak workload consumers changed")
    require(document["proof_status"] == "source-only", "Keycloak workload proof changed")
    require(document["environment"] == "environment-gcp", "Keycloak workload environment changed")
    require(
        document["source_contracts"]
        == {
            "identity": "sudo/access/keycloak-profile.json",
            "inputs": "sudo/secrets/keycloak-input-contract.json",
            "supply": "tar/manifests/keycloak-supply.json",
            "certificate": "make/cert-manager/cluster-issuer.json",
        },
        "Keycloak workload source contracts changed",
    )
    require(
        document["excluded_fields"]
        == [
            "external_service_address",
            "node_port",
            "load_balancer",
            "ingress",
            "plaintext_credentials",
            "kubeconfig_data",
        ],
        "Keycloak workload exclusions changed",
    )
    return document


def validate_realm(config_map: dict[str, Any], profile: dict[str, Any]) -> None:
    data_value = config_map.get("data")
    require(
        isinstance(data_value, dict) and set(data_value) == {"shell-realm.json"},
        "Keycloak realm ConfigMap changed",
    )
    data = cast(dict[str, Any], data_value)
    require(isinstance(data["shell-realm.json"], str), "Keycloak realm JSON is not text")
    try:
        realm = json.loads(data["shell-realm.json"])
    except (TypeError, json.JSONDecodeError) as error:
        raise KeycloakValidationError("Keycloak realm JSON is invalid") from error
    require(isinstance(realm, dict), "Keycloak realm must be an object")
    require(
        realm.get("realm") == "shell"
        and realm.get("enabled") is True
        and realm.get("registrationAllowed") is False
        and realm.get("resetPasswordAllowed") is False,
        "Keycloak realm policy changed",
    )
    roles = realm.get("roles", {}).get("realm", [])
    require(
        {item.get("name") for item in roles}
        == {"platform-admin", "platform-operator", "auditor"},
        "Keycloak realm roles changed",
    )
    groups = realm.get("groups", [])
    require(
        {
            item.get("name"): item.get("realmRoles")
            for item in groups
        }
        == {
            "platform-admins": ["platform-admin"],
            "platform-operators": ["platform-operator"],
            "auditors": ["auditor"],
        },
        "Keycloak realm groups changed",
    )
    components = realm.get("components")
    require(isinstance(components, dict), "Keycloak LDAP components are missing")
    providers = components.get("org.keycloak.storage.UserStorageProvider", [])
    require(isinstance(providers, list) and len(providers) == 1, "Keycloak LDAP provider count changed")
    provider = cast(dict[str, Any], providers[0])
    provider_config = cast(dict[str, Any], provider.get("config", {}))
    require(
        provider.get("id") == "00000000-0000-4000-8000-000000000001"
        and provider.get("providerId") == "ldap"
        and provider_config.get("connectionUrl") == ["ldaps://identity-01.shell.internal:636"]
        and provider_config.get("usersDn") == [profile["identity"]["base_dn"].replace("dc=shell,dc=internal", "cn=users,cn=accounts,dc=shell,dc=internal")]
        and provider_config.get("bindDn") == [profile["identity"]["bind_dn"]]
        and provider_config.get("bindCredential") == ["${KEYCLOAK_LDAP_BIND_PASSWORD}"]
        and provider_config.get("editMode") == ["READ_ONLY"]
        and provider_config.get("useTruststoreSpi") == ["always"],
        "Keycloak FreeIPA federation changed",
    )
    mappers = components.get("org.keycloak.storage.ldap.mappers.LDAPStorageMapper", [])
    require(isinstance(mappers, list) and len(mappers) == 1, "Keycloak LDAP group mapper count changed")
    mapper = cast(dict[str, Any], mappers[0])
    mapper_config = cast(dict[str, Any], mapper.get("config", {}))
    require(
        mapper.get("parentId") == "00000000-0000-4000-8000-000000000001"
        and mapper.get("providerId") == "group-ldap-mapper"
        and mapper_config.get("groups.dn") == ["cn=groups,cn=accounts,dc=shell,dc=internal"]
        and mapper_config.get("mode") == ["READ_ONLY"]
        and mapper_config.get("membership.attribute.type") == ["DN"],
        "Keycloak FreeIPA group mapping changed",
    )
    require("clients" not in realm, "Downstream OIDC clients are outside this slice")


def validate() -> dict[str, Any]:
    documents = access.validate_contracts(ROOT)
    profile = documents["keycloak"]
    supply_lock = supply.validate_public()
    contract = validate_workload_contract()
    for relative in MANIFEST_NAMES:
        require((PLATFORM / relative).is_file(), f"Keycloak manifest is missing: {relative}")
    require((PLATFORM / "kustomization.yaml").is_file(), "Keycloak kustomization is missing")
    application = read_yaml(APPLICATION)[0]
    require(
        application.get("kind") == "Application"
        and application.get("metadata", {}).get("name") == "shell-keycloak"
        and application.get("spec", {}).get("project") == "shell-platform-services"
        and application.get("spec", {}).get("destination", {}).get("namespace") == "shell-identity"
        and application.get("spec", {}).get("source", {}).get("path") == "gitops/platform/keycloak"
        and application.get("metadata", {}).get("annotations", {}).get("argocd.argoproj.io/sync-wave") == "10",
        "Keycloak Argo application changed",
    )
    resources: list[dict[str, Any]] = []
    for relative in MANIFEST_NAMES:
        resources.extend(read_yaml(PLATFORM / relative))
    namespace = resource(resources, "Namespace", "shell-identity")
    labels = namespace["metadata"]["labels"]
    require(
        labels.get("pod-security.kubernetes.io/enforce") == "restricted"
        and labels.get("pod-security.kubernetes.io/audit") == "restricted"
        and labels.get("pod-security.kubernetes.io/warn") == "restricted",
        "Keycloak namespace security labels changed",
    )
    certificate = resource(resources, "Certificate", "keycloak-public-tls")
    cert_spec = certificate["spec"]
    require(
        cert_spec.get("secretName") == "keycloak-public-tls"
        and set(cert_spec.get("dnsNames", []))
        == {
            "keycloak.shell-identity.svc",
            "keycloak.shell-identity.svc.cluster.local",
        }
        and cert_spec.get("issuerRef", {}).get("name") == "shell-cluster-intermediate",
        "Keycloak certificate contract changed",
    )
    service = resource(resources, "Service", "keycloak")
    service_spec = service["spec"]
    require(
        service_spec.get("type") == "ClusterIP"
        and service_spec.get("ports") == [{"name": "https", "port": 443, "targetPort": "https"}],
        "Keycloak service must remain cluster-local",
    )
    management = resource(resources, "Service", "keycloak-management")
    require(management["spec"].get("type") == "ClusterIP", "Keycloak management service must remain ClusterIP")
    statefulset = resource(resources, "StatefulSet", "keycloak-postgresql")
    stateful_spec = statefulset["spec"]
    require(
        stateful_spec.get("replicas") == 1
        and stateful_spec.get("serviceName") == "keycloak-postgresql"
        and stateful_spec.get("volumeClaimTemplates", [{}])[0].get("spec", {}).get("storageClassName") == "longhorn"
        and stateful_spec.get("volumeClaimTemplates", [{}])[0].get("spec", {}).get("resources", {}).get("requests", {}).get("storage") == "8Gi",
        "Keycloak PostgreSQL stateful boundary changed",
    )
    stateful_pod = stateful_spec["template"]["spec"]
    require(stateful_pod.get("automountServiceAccountToken") is False, "Keycloak PostgreSQL service token must stay disabled")
    deployment = resource(resources, "Deployment", "keycloak")
    pod = deployment["spec"]["template"]["spec"]
    require(pod.get("automountServiceAccountToken") is False, "Keycloak service token must stay disabled")
    expected_images = {
        supply_lock["images"]["keycloak"]["runtime"],
        supply_lock["images"]["postgresql"]["runtime"],
    }
    observed_images = {container.get("image") for container in containers(pod)}
    require(observed_images <= expected_images and observed_images == {supply_lock["images"]["keycloak"]["runtime"]}, "Keycloak image pin changed")
    require(
        all(isinstance(container.get("image"), str) and IMAGE_PATTERN.fullmatch(container["image"]) for container in containers(pod) + containers(stateful_pod))
        and all("latest" not in container["image"] for container in containers(pod) + containers(stateful_pod)),
        "Keycloak images must be immutable and versioned",
    )
    main = resource(resources, "Deployment", "keycloak")["spec"]["template"]["spec"]["containers"][0]
    require(
        "--import-realm" in main.get("args", [])
        and "--hostname=https://keycloak.shell-identity.svc.cluster.local" in main.get("args", [])
        and isinstance(main.get("readinessProbe"), dict)
        and isinstance(main.get("livenessProbe"), dict),
        "Keycloak runtime probes or realm import changed",
    )
    require(
        all(isinstance(container.get("resources"), dict) for container in containers(pod) + containers(stateful_pod))
        and all(container.get("securityContext", {}).get("allowPrivilegeEscalation") is False for container in containers(pod) + containers(stateful_pod)),
        "Keycloak containers must retain resource and privilege guards",
    )
    realm = resource(resources, "ConfigMap", "keycloak-realm")
    validate_realm(realm, profile)
    root_ca = resource(resources, "ConfigMap", "shell-freeipa-ca")
    require(root_ca.get("data") == {}, "Keycloak source must not carry FreeIPA CA data")
    policies = [item for item in resources if item.get("kind") == "NetworkPolicy"]
    require(any(item["metadata"]["name"] == "shell-identity-default-deny" for item in policies), "Keycloak default deny policy is missing")
    policy_source = (PLATFORM / "networkpolicy.yaml").read_text(encoding="utf-8")
    require("namespaceSelector: {}" not in policy_source, "Keycloak network policy must not allow every namespace")
    kustomization = (PLATFORM / "kustomization.yaml").read_text(encoding="utf-8")
    require("root-ca.yaml" not in kustomization, "private FreeIPA CA marker must not overwrite the injected ConfigMap")
    return contract


def main() -> int:
    try:
        validate()
    except (OSError, KeycloakValidationError, access.AccessContractError, supply.KeycloakSupplyError) as error:
        print(f"MAKE Keycloak validation failed: {error}", file=sys.stderr)
        return 2
    print("validated Keycloak login source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
