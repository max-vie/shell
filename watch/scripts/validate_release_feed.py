#!/usr/bin/env python3
"""Validate WATCH's release-feed policy and source references."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

import yaml


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "watch/contracts/release-feed-requirements.json"
RULE = ROOT / "watch/monitoring/release-feed.rules.yaml"
MANIFEST_ROOT = ROOT / "make/apps/release-feed/k8s/base"
MAKE_CONTRACT = ROOT / "make/contracts/release-feed-secret-contract.json"


class ReleaseFeedWatchError(ValueError):
    """WATCH release-feed validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseFeedWatchError(message)


def read_json(path: Path) -> dict[str, Any]:
    require(
        path.is_file() and not path.is_symlink(),
        "release-feed WATCH contract is missing",
    )

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseFeedWatchError("release-feed WATCH contract is invalid") from error
    require(isinstance(document, dict), "release-feed WATCH contract is not an object")
    return cast(dict[str, Any], document)


def validate(path: Path = CONTRACT) -> dict[str, Any]:
    document = read_json(path)
    require(
        set(document)
        == {
            "description",
            "schema_version",
            "contract_version",
            "contract_id",
            "policy_owner",
            "consumer_owners",
            "proof_status",
            "environment",
            "cluster",
            "service",
            "workload",
            "evidence",
            "failure_policy",
        }
        and isinstance(document["description"], str),
        "release-feed WATCH shape changed",
    )
    require(document["schema_version"] == "1.0", "release-feed WATCH schema changed")
    require(
        document["contract_version"] == "1.0.0", "release-feed WATCH version changed"
    )
    require(
        document["contract_id"] == "release-feed-requirements",
        "release-feed WATCH ID changed",
    )
    require(document["policy_owner"] == "watch", "WATCH must own release-feed policy")
    require(
        document["consumer_owners"] == ["make", "watch"],
        "release-feed WATCH consumers changed",
    )
    require(
        document["proof_status"] == "source-only", "release-feed WATCH proof changed"
    )
    require(
        document["environment"] == "environment-gcp",
        "release-feed WATCH environment changed",
    )
    require(
        document["cluster"]
        == {
            "name": "gcp",
            "inventory_group": "gcp_k3s_servers",
            "first_server": "gcp-k3s-01",
            "first_server_address": "10.77.0.201",
        },
        "release-feed WATCH cluster changed",
    )
    require(
        document["service"]
        == {
            "namespace": "release-feed",
            "name": "release-feed",
            "address": "10.77.0.222",
            "port": 443,
            "health_path": "/healthz",
            "metrics_path": "/metrics",
            "tls_server_name": "releases.shell.internal",
        },
        "release-feed WATCH service changed",
    )
    require(
        document["workload"]
        == {
            "kind": "StatefulSet",
            "name": "release-feed",
            "replicas": 1,
            "storage_class": "longhorn",
            "storage_size": "1Gi",
            "retention": "retain",
            "max_records": 1000,
            "capacity_warning_remaining": 100,
        },
        "release-feed WATCH workload changed",
    )
    require(
        document["evidence"]
        == [
            "HTTPS service has the declared address",
            "StatefulSet has one ready replica",
            "retained Longhorn claim is bound",
            "health and metrics endpoints respond",
        ]
        and document["failure_policy"] == "read-only-diagnosis",
        "release-feed WATCH evidence boundary changed",
    )
    for name in (
        "statefulset.yaml",
        "service.yaml",
        "servicemonitor.yaml",
        "networkpolicy.yaml",
    ):
        path_value = MANIFEST_ROOT / name
        require(
            path_value.is_file() and not path_value.is_symlink(),
            f"release-feed manifest missing: {name}",
        )
    make_contract = read_json(MAKE_CONTRACT)
    require(
        make_contract["contract_id"] == "release-feed-secret-contract"
        and make_contract["application"]
        == {
            "max_records": 1000,
            "capacity_warning_remaining": 100,
            "capacity_exhausted_status": 507,
        }
        and make_contract["harbor"]["address"] == "10.77.0.221"
        and make_contract["openbao"]["path"] == "secret/data/release-feed"
        and make_contract["storage"]["retention"] == "retain",
        "release-feed MAKE contract changed",
    )
    try:
        resources = {
            name: list(
                yaml.safe_load_all((MANIFEST_ROOT / name).read_text(encoding="utf-8"))
            )
            for name in (
                "statefulset.yaml",
                "service.yaml",
                "servicemonitor.yaml",
                "networkpolicy.yaml",
            )
        }
        rule_documents = list(yaml.safe_load_all(RULE.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ReleaseFeedWatchError("release-feed resources are invalid YAML") from error
    service = resources["service.yaml"][0]
    monitor = resources["servicemonitor.yaml"][0]
    statefulset = resources["statefulset.yaml"][0]
    policies = resources["networkpolicy.yaml"]
    require(
        service["metadata"]["namespace"] == "release-feed"
        and service["spec"]["type"] == "LoadBalancer"
        and service["spec"]["loadBalancerIP"] == "10.77.0.222"
        and service["spec"]["selector"] == {"app.kubernetes.io/name": "release-feed"},
        "release-feed Service boundary changed",
    )
    endpoint = monitor["spec"]["endpoints"][0]
    require(
        monitor["metadata"]["labels"]["release"] == "shell-watch"
        and monitor["spec"]["selector"]["matchLabels"]
        == {"app.kubernetes.io/name": "release-feed"}
        and endpoint["port"] == "https"
        and endpoint["scheme"] == "https"
        and endpoint["path"] == "/metrics"
        and endpoint["tlsConfig"]["serverName"]
        == "release-feed.release-feed.svc.cluster.local",
        "release-feed ServiceMonitor boundary changed",
    )
    claim = statefulset["spec"]["volumeClaimTemplates"][0]["spec"]
    require(
        statefulset["spec"]["replicas"] == 1
        and statefulset["spec"]["persistentVolumeClaimRetentionPolicy"]
        == {"whenDeleted": "Retain", "whenScaled": "Retain"}
        and claim["storageClassName"] == "longhorn"
        and claim["resources"]["requests"]["storage"] == "1Gi",
        "release-feed StatefulSet boundary changed",
    )
    require(
        any(
            policy.get("metadata", {}).get("name") == "release-feed-default-deny"
            and policy.get("spec", {}).get("podSelector") == {}
            and set(policy.get("spec", {}).get("policyTypes", []))
            == {"Ingress", "Egress"}
            for policy in policies
            if isinstance(policy, dict)
        ),
        "release-feed default-deny policy is missing",
    )
    require(len(rule_documents) == 1, "release-feed rule document changed")
    rule = rule_documents[0]
    rules = rule["spec"]["groups"][0]["rules"]
    require(len(rules) == 2, "release-feed alert set changed")
    alert = rules[0]
    require(alert["alert"] == "ShellReleaseFeedUnavailable", "release-feed alert is missing")
    require(
        alert["expr"]
        == '(up{namespace="release-feed",service="release-feed"} == 0) or absent(up{namespace="release-feed",service="release-feed"})',
        "release-feed alert expression changed",
    )
    require(alert["for"] == "2m", "release-feed alert duration changed")
    capacity_alert = rules[1]
    require(
        capacity_alert["alert"] == "ShellReleaseFeedCapacityLow"
        and capacity_alert["expr"]
        == '(release_feed_capacity_remaining{namespace="release-feed",service="release-feed"} < 100) or absent(release_feed_capacity_remaining{namespace="release-feed",service="release-feed"})'
        and capacity_alert["for"] == "5m",
        "release-feed capacity alert changed",
    )
    return document


def main() -> int:
    try:
        validate()
    except (OSError, ReleaseFeedWatchError) as error:
        print(f"WATCH release-feed validation failed: {error}", file=sys.stderr)
        return 2
    print("validated WATCH release-feed policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
