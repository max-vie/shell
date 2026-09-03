#!/usr/bin/env python3
"""Validate the source-only Cosign and Kyverno admission boundary."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast

import yaml

SCRIPT_ROOT = Path(__file__).resolve().parent
SUDO_SCRIPTS = SCRIPT_ROOT.parents[1] / "sudo/scripts"
TAR_SCRIPTS = SCRIPT_ROOT.parents[1] / "tar/scripts"
for path in (SUDO_SCRIPTS, TAR_SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import validate_access_contracts as access  # noqa: E402
import validate_harbor_robots  # noqa: E402
import validate_kubernetes_supply as supply  # noqa: E402


ROOT = SCRIPT_ROOT.parents[1]
CONTRACT = ROOT / "make/contracts/cosign-admission-requirements.json"
VALUES = ROOT / "make/gitops/values/kyverno.yaml"
APPLICATION = ROOT / "make/gitops/applications/children/kyverno.yaml"
PLATFORM = ROOT / "make/gitops/platform/kyverno"
ROOT_CERTIFICATE = ROOT / "sudo/pki/shell-offline-root.crt.pem"
IMAGE_TAG = re.compile(r"^v1\.18\.2@sha256:[0-9a-f]{64}$")


class CosignAdmissionError(ValueError):
    """Cosign and Kyverno source validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CosignAdmissionError(message)


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
        raise CosignAdmissionError(f"{label} is invalid JSON") from error
    require(isinstance(value, dict), f"{label} is not an object")
    return cast(dict[str, Any], value)


def read_yaml(path: Path) -> list[dict[str, Any]]:
    require(path.is_file() and not path.is_symlink(), f"Kyverno source is missing: {path.name}")
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise CosignAdmissionError(f"Kyverno source is invalid YAML: {path.name}") from error
    result: list[dict[str, Any]] = []
    for document in documents:
        require(isinstance(document, dict), f"Kyverno document is not a mapping: {path.name}")
        result.append(cast(dict[str, Any], document))
    return result


def resource(resources: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    matches = [
        item
        for item in resources
        if item.get("kind") == kind and item.get("metadata", {}).get("name") == name
    ]
    require(len(matches) == 1, f"Kyverno source must contain one {kind}/{name}")
    return matches[0]


def validate_contract() -> dict[str, Any]:
    document = read_json(CONTRACT, "Cosign admission contract")
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
            "trust",
            "policy",
            "gitops",
            "excluded_fields",
        },
        "Cosign admission contract shape changed",
    )
    require(document["schema_version"] == "1.0", "Cosign admission schema changed")
    require(document["contract_version"] == "1.0.0", "Cosign admission version changed")
    require(document["contract_id"] == "cosign-admission-requirements", "Cosign admission ID changed")
    require(document["policy_owner"] == "sudo", "SUDO must own Cosign trust policy")
    require(document["producer_owners"] == ["sudo", "tar"], "Cosign admission producers changed")
    require(document["consumer_owners"] == ["make"], "Cosign admission consumers changed")
    require(document["proof_status"] == "source-only", "Cosign admission proof changed")
    require(document["environment"] == "environment-gcp", "Cosign admission environment changed")
    require(
        document["source_contracts"]
        == {
            "trust": "sudo/secrets/cosign-trust-input-contract.json",
            "supply": "tar/manifests/kubernetes-ecosystem-supply.json",
            "harbor_robots": "make/contracts/harbor-robot-handoff.json",
            "argo": "make/gitops/applications/children/kyverno.yaml",
        },
        "Cosign admission source contracts changed",
    )
    require(
        document["trust"]
        == {
            "owner": "sudo",
            "namespace": "shell-trust",
            "secret_name": "cosign-public-keys",
            "key": "cosign.pub",
            "approval": "environment-gcp/make/cosign-trust",
        },
        "Cosign trust target changed",
    )
    require(
        document["policy"]
        == {
            "name": "shell-require-signed-images",
            "kind": "ClusterPolicy",
            "namespace_label": {
                "key": "shell.platform/policy",
                "value": "enforced",
            },
            "image_prefix": "registry.shell.internal/shell/",
            "required": True,
            "verify_digest": True,
            "mutate_digest": False,
            "failure_policy": "Fail",
            "validation_failure_action": "Enforce",
            "rekor_ignore_tlog": True,
            "ctlog_ignore_sct": True,
        },
        "Cosign admission policy changed",
    )
    require(
        document["gitops"]
        == {
            "application": "make/gitops/applications/children/kyverno.yaml",
            "values": "make/gitops/values/kyverno.yaml",
            "resources": "make/gitops/platform/kyverno",
            "policy": "make/gitops/platform/kyverno/policies.yaml",
            "trust_rbac": "make/gitops/platform/kyverno/trust-rbac.yaml",
        },
        "Cosign admission GitOps paths changed",
    )
    require(
        document["excluded_fields"]
        == [
            "private_key",
            "password",
            "plaintext_credentials",
            "kubeconfig_data",
            "live_admission_evidence",
        ],
        "Cosign admission exclusions changed",
    )
    return document


def validate_values(lock: dict[str, Any]) -> None:
    try:
        values = yaml.safe_load(VALUES.read_text(encoding="utf-8"))
        root_ca = ROOT_CERTIFICATE.read_text(encoding="ascii")
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise CosignAdmissionError("Kyverno values are not parseable") from error
    require(isinstance(values, dict), "Kyverno values are not a mapping")
    require(values["global"]["imagePullSecrets"] == [{"name": "shell-registry-pull"}], "Kyverno pull secret changed")
    require(values["existingImagePullSecrets"] == ["shell-registry-pull"], "Kyverno existing pull secret changed")
    require(values["global"]["caCertificates"]["data"] == root_ca, "Kyverno CA bundle does not match SUDO")
    require(values["crds"]["migration"]["enabled"] is False, "Kyverno CRD migration must stay disabled")
    require(values["webhooksCleanup"]["enabled"] is False, "Kyverno cleanup hook must stay disabled")
    expected = {
        "admissionController": {
            "initContainer": "reg.kyverno.io/kyverno/kyvernopre",
            "container": "reg.kyverno.io/kyverno/kyverno",
        },
        "backgroundController": {"image": "reg.kyverno.io/kyverno/background-controller"},
        "cleanupController": {"image": "reg.kyverno.io/kyverno/cleanup-controller"},
        "reportsController": {"image": "reg.kyverno.io/kyverno/reports-controller"},
    }
    for controller, images in expected.items():
        for key, repository in images.items():
            image = (
                values[controller][key]["image"]
                if controller == "admissionController"
                else values[controller]["image"]
            )
            require(
                image["registry"] + "/" + image["repository"] == repository
                and IMAGE_TAG.fullmatch(image["tag"]) is not None
                and image["tag"].endswith("@" + lock["images"][repository + ":v1.18.2"]["digest"]),
                f"Kyverno {controller} image pin changed",
            )
    test_image = values["test"]["image"]
    require(
        test_image["registry"] + "/" + test_image["repository"]
        == "ghcr.io/kyverno/readiness-checker"
        and IMAGE_TAG.fullmatch(test_image["tag"]) is not None
        and test_image["tag"].endswith(
            "@" + lock["images"]["ghcr.io/kyverno/readiness-checker:v1.18.2"]["digest"]
        ),
        "Kyverno readiness image pin changed",
    )
    serialized = VALUES.read_text(encoding="utf-8")
    require("latest" not in serialized.lower(), "Kyverno values contain a mutable tag")


def validate() -> dict[str, Any]:
    contract = validate_contract()
    documents = access.validate_contracts(ROOT)
    supply_lock = supply.validate_public()
    validate_harbor_robots.validate()
    validate_values(supply_lock)
    application = read_yaml(APPLICATION)[0]
    spec = application.get("spec", {})
    require(
        application.get("kind") == "Application"
        and application.get("metadata", {}).get("name") == "shell-kyverno"
        and application.get("metadata", {}).get("annotations", {}).get("argocd.argoproj.io/sync-wave") == "20"
        and len(spec.get("sources", [])) == 3
        and spec.get("destination", {}).get("namespace") == "kyverno",
        "Kyverno Argo application changed",
    )
    project = read_yaml(ROOT / "make/gitops/bootstrap/argocd/project.yaml")[0]
    cluster_whitelist = {
        (item.get("group"), item.get("kind"))
        for item in project.get("spec", {}).get("clusterResourceWhitelist", [])
    }
    require(
        {
            ("", "Namespace"),
            ("cert-manager.io", "Certificate"),
            ("apiextensions.k8s.io", "CustomResourceDefinition"),
            ("rbac.authorization.k8s.io", "ClusterRole"),
            ("rbac.authorization.k8s.io", "ClusterRoleBinding"),
            ("admissionregistration.k8s.io", "MutatingWebhookConfiguration"),
            ("admissionregistration.k8s.io", "ValidatingWebhookConfiguration"),
            ("kyverno.io", "ClusterPolicy"),
        }
        <= cluster_whitelist
        and ("*", "*") not in cluster_whitelist,
        "Argo cluster-resource allow-list changed",
    )
    resources: list[dict[str, Any]] = []
    for relative in ("namespace.yaml", "trust-rbac.yaml", "policies.yaml"):
        resources.extend(read_yaml(PLATFORM / relative))
    for namespace in ("kyverno", "shell-trust"):
        labels = resource(resources, "Namespace", namespace)["metadata"]["labels"]
        require(labels.get("pod-security.kubernetes.io/enforce") == "restricted", f"{namespace} security label changed")
    role = resource(resources, "Role", "kyverno-cosign-key-reader")
    require(
        role["metadata"]["namespace"] == "shell-trust"
        and role["rules"] == [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["cosign-public-keys"], "verbs": ["get"]}],
        "Kyverno trust RBAC is broader than the named public key",
    )
    binding = resource(resources, "RoleBinding", "kyverno-cosign-key-reader")
    require(
        binding["metadata"]["namespace"] == "shell-trust"
        and binding["subjects"] == [{"kind": "ServiceAccount", "name": "kyverno-admission-controller", "namespace": "kyverno"}],
        "Kyverno trust RoleBinding changed",
    )
    policy = resource(resources, "ClusterPolicy", "shell-require-signed-images")
    policy_spec = policy["spec"]
    rule = policy_spec["rules"][0]
    require(
        policy_spec.get("failurePolicy") == "Fail"
        and policy_spec.get("validationFailureAction") == "Enforce"
        and rule["match"]["any"][0]["resources"]["namespaceSelector"]["matchLabels"] == {"shell.platform/policy": "enforced"}
        and rule["verifyImages"][0]["required"] is True
        and rule["verifyImages"][0]["mutateDigest"] is False
        and rule["verifyImages"][0]["verifyDigest"] is True
        and rule["verifyImages"][0]["attestors"][0]["entries"][0]["keys"]["publicKeys"] == "k8s://shell-trust/cosign-public-keys"
        and rule["verifyImages"][0]["attestors"][0]["entries"][0]["keys"]["rekor"]["ignoreTlog"] is True
        and rule["verifyImages"][0]["attestors"][0]["entries"][0]["keys"]["ctlog"]["ignoreSCT"] is True,
        "Kyverno signed-image rule changed",
    )
    require("shell.platform/policy: enforced" in (PLATFORM / "policies.yaml").read_text(encoding="utf-8"), "Kyverno policy namespace selector is missing")
    require("private_key" not in str(resources) and "password" not in str(resources).lower(), "Kyverno source contains private material")
    require(documents["kubernetes"]["admission_trust"]["contract"] == "sudo/secrets/cosign-trust-input-contract.json", "SUDO admission trust handoff changed")
    return contract


def main() -> int:
    try:
        validate()
    except (
        OSError,
        CosignAdmissionError,
        access.AccessContractError,
        supply.SupplyError,
        validate_harbor_robots.HarborRobotError,
    ) as error:
        print(f"MAKE Cosign admission validation failed: {error}", file=sys.stderr)
        return 2
    print("validated Cosign and Kyverno admission source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
