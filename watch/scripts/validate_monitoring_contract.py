#!/usr/bin/env python3
"""Validate WATCH's source-only cluster monitoring contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPOSITORY_ROOT / "watch/contracts/cluster-monitoring-requirements.json"
INIT_LAUNCHER_PATH = REPOSITORY_ROOT / "init/scripts/run_k3s_runtime.py"
INIT_K3S_VARS_PATH = REPOSITORY_ROOT / "init/ansible/vars/k3s.yml"
TAR_SCRIPTS_ROOT = REPOSITORY_ROOT / "tar/scripts"
if str(TAR_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS_ROOT))
import validate_watch as watch_supply  # noqa: E402
import validate_watch_logs as watch_logs_supply  # noqa: E402


class MonitoringContractError(ValueError):
    """WATCH's public monitoring contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MonitoringContractError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing regular {label}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MonitoringContractError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


def validate_contract(
    path: Path = CONTRACT_PATH, repository_root: Path = REPOSITORY_ROOT
) -> dict[str, Any]:
    document = read_json(path, "WATCH monitoring contract")
    require(
        set(document)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "producer_owner",
            "consumer_owners",
            "proof_status",
            "environment",
            "cluster",
            "supply",
            "required_guest_tools",
            "deployment",
            "logs",
            "excluded_fields",
        },
        "WATCH monitoring contract shape changed",
    )
    require(document["schema_version"] == "1.0", "WATCH schema version changed")
    require(document["contract_version"] == "2.0.0", "WATCH contract version changed")
    require(
        document["contract_id"] == "cluster-monitoring-requirements",
        "WATCH contract ID changed",
    )
    require(document["policy_owner"] == "watch", "WATCH must own monitoring policy")
    require(
        document["producer_owner"] == "init", "INIT must produce the cluster handoff"
    )
    require(
        document["consumer_owners"] == ["make", "watch"],
        "WATCH consumer ownership changed",
    )
    require(document["proof_status"] == "source-only", "WATCH proof status changed")
    require(document["environment"] == "environment-gcp", "WATCH environment changed")

    cluster = document["cluster"]
    require(isinstance(cluster, dict), "WATCH cluster contract must be an object")
    require(
        cluster
        == {
            "name": "gcp",
            "inventory_group": "gcp_k3s_servers",
            "control_plane": "k3s",
            "nodes": ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"],
            "first_server": "gcp-k3s-01",
            "first_server_address": "10.77.0.201",
            "first_server_zone": "europe-west4-a",
            "project_id_source": "INIT private inventory gcp_project_id",
            "api_endpoint_source": "INIT private inventory shell_inventory_k3s_api_endpoint",
        },
        "WATCH cluster boundary changed",
    )
    supply = document["supply"]
    require(
        supply
        == {
            "contract": "tar/manifests/watch-supply.json",
            "chart": "kube-prometheus-stack",
            "chart_version": "88.5.2",
        },
        "WATCH supply boundary changed",
    )
    require(
        document["required_guest_tools"] == ["k3s", "helm"],
        "WATCH guest tool requirements changed",
    )
    deployment = document["deployment"]
    require(
        deployment
        == {
            "owner": "make",
            "values": "make/monitoring/values.yaml",
            "release": "shell-watch",
            "namespace": "monitoring",
            "exclusive_namespace": False,
            "runtime_pod_selector": "release=shell-watch",
            "service_selectors": {
                "prometheus": "app=kube-prometheus-stack-prometheus,release=shell-watch",
                "alertmanager": "app=kube-prometheus-stack-alertmanager,release=shell-watch",
            },
            "metrics_proof": ["node-exporter scrape target", "Watchdog alert"],
        },
        "WATCH deployment boundary changed",
    )
    require(
        document["excluded_fields"]
        == ["node_addresses", "pod_cidr", "service_cidr", "credentials"],
        "WATCH excluded fields changed",
    )
    logs = document["logs"]
    require(
        logs
        == {
            "supply": {
                "contract": "tar/manifests/watch-logs-supply.json",
                "charts": ["loki", "alloy"],
            },
            "values": {
                "loki": "make/monitoring/logs-values.yaml",
                "alloy": "make/monitoring/alloy-values.yaml",
            },
            "releases": {
                "loki": "shell-watch-loki",
                "alloy": "shell-watch-alloy",
            },
            "failure_policy": "compensating-rollback",
            "access_boundary": {
                "loki_authentication": "disabled",
                "network_policy": "Alloy to gateway to Loki only",
                "network_policy_source": "init/ansible/vars/k3s.yml shell_k3s_disable_network_policy=false",
                "alloy_service": False,
            },
            "namespace": "monitoring",
            "alloy_daemonset_selector": "app.kubernetes.io/instance=shell-watch-alloy",
            "loki_service_selector": "app.kubernetes.io/name=loki,app.kubernetes.io/instance=shell-watch-loki,app.kubernetes.io/component=gateway",
            "loki_service_port": 80,
            "logs_proof": [
                "Alloy ready on every contract node",
                "fresh Alloy logs queryable within 300 seconds",
            ],
        },
        "WATCH logs boundary changed",
    )

    launcher = (
        repository_root / INIT_LAUNCHER_PATH.relative_to(REPOSITORY_ROOT)
    ).read_text(encoding="utf-8")
    for fragment in (
        '"gcp_k3s_servers"',
        '"gcp-k3s-01"',
        '"gcp-k3s-02"',
        '"gcp-k3s-03"',
        '"10.77.0.201"',
    ):
        require(fragment in launcher, f"INIT K3s source is missing: {fragment}")
    k3s_vars = (
        repository_root / INIT_K3S_VARS_PATH.relative_to(REPOSITORY_ROOT)
    ).read_text(encoding="utf-8")
    require(
        "shell_k3s_disable_network_policy: false" in k3s_vars,
        "INIT K3s network policy controller is not enabled",
    )
    supply_path = repository_root / "tar/manifests/watch-supply.json"
    supply_lock = watch_supply.validate_public(supply_path)
    chart = supply_lock["charts"]["kube-prometheus-stack"]
    require(chart["version"] == supply["chart_version"], "WATCH chart pin changed")
    values_path = repository_root / deployment["values"]
    require(
        values_path.is_file() and not values_path.is_symlink(),
        "MAKE monitoring values are missing",
    )
    logs_supply_path = repository_root / logs["supply"]["contract"]
    watch_logs_supply.validate_public(logs_supply_path)
    for value_path in logs["values"].values():
        path_value = repository_root / value_path
        require(
            path_value.is_file() and not path_value.is_symlink(),
            f"MAKE logs values are missing: {value_path}",
        )
    return document


def main() -> int:
    try:
        validate_contract()
        print("validated WATCH monitoring contract")
        return 0
    except (
        MonitoringContractError,
        watch_supply.WatchSupplyError,
        watch_logs_supply.WatchLogsSupplyError,
        OSError,
    ) as error:
        print(f"WATCH monitoring validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
