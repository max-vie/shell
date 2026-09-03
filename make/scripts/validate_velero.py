#!/usr/bin/env python3
"""Validate the source-only Velero and GCS backup boundary."""

from __future__ import annotations

import json
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
import validate_kubernetes_supply as supply  # noqa: E402


ROOT = SCRIPT_ROOT.parents[1]
CONTRACT = ROOT / "make/contracts/velero-gcs-requirements.json"
VALUES = ROOT / "make/gitops/values/velero.yaml"
APPLICATION = ROOT / "make/gitops/applications/children/velero.yaml"
PLATFORM = ROOT / "make/gitops/platform/velero"


class VeleroValidationError(ValueError):
    """Velero source validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VeleroValidationError(message)


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
        raise VeleroValidationError(f"{label} is invalid JSON") from error
    require(isinstance(value, dict), f"{label} is not an object")
    return cast(dict[str, Any], value)


def read_yaml(path: Path) -> list[dict[str, Any]]:
    require(path.is_file() and not path.is_symlink(), f"Velero source is missing: {path.name}")
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise VeleroValidationError(f"Velero source is invalid YAML: {path.name}") from error
    result: list[dict[str, Any]] = []
    for document in documents:
        require(isinstance(document, dict), f"Velero document is not a mapping: {path.name}")
        result.append(cast(dict[str, Any], document))
    return result


def resource(resources: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    matches = [
        item
        for item in resources
        if item.get("kind") == kind and item.get("metadata", {}).get("name") == name
    ]
    require(len(matches) == 1, f"Velero source must contain one {kind}/{name}")
    return matches[0]


def validate_contract() -> dict[str, Any]:
    document = read_json(CONTRACT, "Velero GCS contract")
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
            "backup",
            "gcs",
            "snapshot",
            "excluded_fields",
        },
        "Velero GCS contract shape changed",
    )
    require(document["schema_version"] == "1.0", "Velero GCS schema changed")
    require(document["contract_version"] == "1.0.0", "Velero GCS version changed")
    require(document["contract_id"] == "velero-gcs-requirements", "Velero GCS ID changed")
    require(document["policy_owner"] == "make", "MAKE must own Velero requirements")
    require(document["producer_owners"] == ["sudo", "tar", "init"], "Velero GCS producers changed")
    require(document["consumer_owners"] == ["make", "watch"], "Velero GCS consumers changed")
    require(document["proof_status"] == "source-only", "Velero GCS proof changed")
    require(document["environment"] == "environment-gcp", "Velero GCS environment changed")
    require(
        document["source_contracts"]
        == {
            "credentials": "sudo/secrets/velero-gcs-input-contract.json",
            "supply": "tar/manifests/kubernetes-ecosystem-supply.json",
            "gcs_root": "init/opentofu/gcs-backup",
            "cluster_trust": "make/contracts/cluster-trust-requirements.json",
        },
        "Velero GCS source contracts changed",
    )
    require(
        document["backup"]
        == {
            "namespace": "velero",
            "release": "velero",
            "chart": "velero",
            "chart_version": "12.1.0",
            "provider": "gcp",
            "bucket_name": "replace-with-unique-shell-velero-bucket",
            "credential_secret": "velero-object-store",
            "credential_key": "cloud",
            "uploader": "kopia",
            "features": ["EnableCSI"],
            "default_snapshot_move_data": True,
            "default_volumes_to_fs_backup": False,
            "snapshots_enabled": False,
            "node_agent_enabled": True,
            "schedule": {
                "name": "release-feed-daily",
                "cron": "17 1 * * *",
                "namespace": "release-feed",
                "ttl": "720h",
            },
        },
        "Velero backup configuration changed",
    )
    require(
        document["gcs"]
        == {
            "region": "europe-west4",
            "uniform_bucket_level_access": True,
            "public_access_prevention": "enforced",
            "force_destroy": False,
            "versioning": True,
            "iam_role": "roles/storage.objectAdmin",
        },
        "Velero GCS policy changed",
    )
    require(
        document["snapshot"]
        == {
            "driver": "driver.longhorn.io",
            "class": "longhorn-snapshot",
            "type": "snap",
            "deletion_policy": "Delete",
            "controller_namespace": "kube-system",
        },
        "Velero snapshot policy changed",
    )
    require(
        document["excluded_fields"]
        == [
            "private_key",
            "service_account_json",
            "kubeconfig_data",
            "live_backup_evidence",
            "external_object_store",
        ],
        "Velero GCS exclusions changed",
    )
    return document


def validate_values(lock: dict[str, Any], contract: dict[str, Any]) -> None:
    try:
        values = yaml.safe_load(VALUES.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise VeleroValidationError("Velero values are not parseable") from error
    require(isinstance(values, dict), "Velero values are not a mapping")
    image = values["image"]
    require(
        image
        == {
            "repository": "docker.io/velero/velero",
            "tag": "v1.18.2",
            "digest": lock["images"]["docker.io/velero/velero:v1.18.2"]["digest"],
            "pullPolicy": "IfNotPresent",
            "imagePullSecrets": [],
        },
        "Velero image pin changed",
    )
    plugin = values["initContainers"]
    require(
        isinstance(plugin, list)
        and len(plugin) == 1
        and plugin[0]["name"] == "velero-plugin-for-gcp"
        and plugin[0]["image"]
        == "docker.io/velero/velero-plugin-for-gcp:v1.14.2@"
        + lock["images"]["docker.io/velero/velero-plugin-for-gcp:v1.14.2"]["digest"],
        "Velero GCP plugin pin changed",
    )
    require(values["credentials"] == {"useSecret": True, "existingSecret": "velero-object-store"}, "Velero credential Secret changed")
    backup_location = values["configuration"]["backupStorageLocation"]
    require(
        backup_location
        == [
            {
                "name": "default",
                "provider": "gcp",
                "bucket": contract["backup"]["bucket_name"],
                "default": True,
                "credential": {"name": "velero-object-store", "key": "cloud"},
                "annotations": {"argocd.argoproj.io/sync-options": "Replace=true"},
            }
        ],
        "Velero BackupStorageLocation changed",
    )
    require(values["configuration"]["volumeSnapshotLocation"] == [], "Velero must not use a cloud snapshot location")
    require(
        values["configuration"]["uploaderType"] == "kopia"
        and values["configuration"]["features"] == "EnableCSI"
        and values["configuration"]["defaultSnapshotMoveData"] is True
        and values["configuration"]["defaultVolumesToFsBackup"] is False
        and values["snapshotsEnabled"] is False
        and values["backupsEnabled"] is True
        and values["deployNodeAgent"] is True,
        "Velero backup mode changed",
    )
    require(
        values["schedules"]
        == {
            "release-feed-daily": {
                "schedule": "17 1 * * *",
                "template": {
                    "ttl": "720h",
                    "includedNamespaces": ["release-feed"],
                    "snapshotVolumes": True,
                    "defaultVolumesToFsBackup": False,
                },
            }
        },
        "Velero schedule changed",
    )
    source = VALUES.read_text(encoding="utf-8").lower()
    require("rustfs" not in source and "aws" not in source and "latest" not in source, "Velero values contain a retired or mutable path")
    require(values["upgradeCRDs"] is False and values["cleanUpCRDs"] is False, "Velero CRD jobs must remain disabled")


def validate() -> dict[str, Any]:
    contract = validate_contract()
    access.validate_contracts(ROOT)
    supply_lock = supply.validate_public()
    validate_values(supply_lock, contract)
    application = read_yaml(APPLICATION)[0]
    spec = application.get("spec", {})
    require(
        application.get("kind") == "Application"
        and application.get("metadata", {}).get("name") == "shell-velero"
        and application.get("metadata", {}).get("annotations", {}).get("argocd.argoproj.io/sync-wave") == "40"
        and len(spec.get("sources", [])) == 3
        and spec.get("destination", {}).get("namespace") == "velero",
        "Velero Argo application changed",
    )
    resources: list[dict[str, Any]] = []
    for relative in (
        "namespace.yaml",
        "networkpolicy.yaml",
        "snapshot-crds.yaml",
        "snapshot-controller.yaml",
    ):
        resources.extend(read_yaml(PLATFORM / relative))
    namespace = resource(resources, "Namespace", "velero")
    require(namespace["metadata"]["labels"].get("shell.platform/policy") == "audit", "Velero namespace policy label changed")
    require(namespace["metadata"]["labels"].get("pod-security.kubernetes.io/enforce") == "restricted", "Velero namespace security label changed")
    default_deny = resource(resources, "NetworkPolicy", "velero-default-deny")
    require(default_deny["spec"].get("policyTypes") == ["Ingress", "Egress"], "Velero default deny policy changed")
    cilium = resource(resources, "CiliumNetworkPolicy", "velero-gcs-egress")
    rendered = str(cilium)
    require("storage.googleapis.com" in rendered and "oauth2.googleapis.com" in rendered and "kube-apiserver" in rendered, "Velero GCS egress policy is incomplete")
    crd_names = {
        item["metadata"]["name"]
        for item in resources
        if item.get("kind") == "CustomResourceDefinition"
    }
    require(
        crd_names
        == {
            "volumesnapshotclasses.snapshot.storage.k8s.io",
            "volumesnapshots.snapshot.storage.k8s.io",
            "volumesnapshotcontents.snapshot.storage.k8s.io",
        },
        "Velero snapshot CRD set changed",
    )
    snapshot = resource(resources, "Deployment", "snapshot-controller")
    snapshot_container = snapshot["spec"]["template"]["spec"]["containers"][0]
    require(
        snapshot["spec"]["replicas"] == 2
        and snapshot_container["image"]
        == "registry.k8s.io/sig-storage/snapshot-controller:v8.6.0@"
        + supply_lock["images"]["registry.k8s.io/sig-storage/snapshot-controller:v8.6.0"]["digest"],
        "snapshot-controller image or replica count changed",
    )
    require(snapshot_container["securityContext"]["allowPrivilegeEscalation"] is False, "snapshot-controller privilege guard changed")
    snapshot_class = resource(resources, "VolumeSnapshotClass", "longhorn-snapshot")
    require(
        snapshot_class["driver"] == "driver.longhorn.io"
        and snapshot_class["deletionPolicy"] == "Delete"
        and snapshot_class["parameters"] == {"type": "snap"},
        "Longhorn snapshot class changed",
    )
    source = "\n".join((PLATFORM / name).read_text(encoding="utf-8") for name in ("networkpolicy.yaml", "snapshot-crds.yaml", "snapshot-controller.yaml"))
    require("private_key" not in source and "service_account_json" not in source and "latest" not in source, "Velero manifests contain private or mutable data")
    kustomization = (PLATFORM / "kustomization.yaml").read_text(encoding="utf-8")
    require(all(name in kustomization for name in ("namespace.yaml", "networkpolicy.yaml", "snapshot-crds.yaml", "snapshot-controller.yaml")), "Velero kustomization is incomplete")
    return contract


def main() -> int:
    try:
        validate()
    except (
        OSError,
        VeleroValidationError,
        access.AccessContractError,
        supply.SupplyError,
    ) as error:
        print(f"MAKE Velero validation failed: {error}", file=sys.stderr)
        return 2
    print("validated Velero GCS source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
