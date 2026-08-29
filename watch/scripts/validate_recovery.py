#!/usr/bin/env python3
"""Validate the source-only Grafana recovery contract and evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ROOT.parent
WATCH_SCRIPTS_ROOT = ROOT / "scripts"
if str(WATCH_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(WATCH_SCRIPTS_ROOT))
import validate_monitoring_contract as monitoring_contract  # noqa: E402


CONTRACT_PATH = ROOT / "contracts/grafana-recovery-drill.json"
RULE_PATH = ROOT / "monitoring/grafana-recovery.rules.yaml"
EVIDENCE_ROOT = REPOSITORY_ROOT / ".local/watch/recovery"
OPERATION_ID_RE = re.compile(r"^grafana-[0-9]{8}-[0-9]{6}-[0-9a-f]{12}-[0-9a-f]{8}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class RecoveryValidationError(ValueError):
    """The recovery contract, rule, or evidence is unsafe or incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryValidationError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing regular {label}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryValidationError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(dict[str, Any], value)


def validate_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    document = read_json(path, "Grafana recovery contract")
    require(
        set(document)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "execution_owner",
            "observer_owner",
            "consumer_owners",
            "proof_status",
            "environment",
            "cluster",
            "approval",
            "target",
            "alert",
            "stability",
            "logs",
            "limits",
        },
        "Grafana recovery contract shape changed",
    )
    require(document["schema_version"] == "1.0", "recovery schema changed")
    require(
        document["contract_version"] == "1.0.0", "recovery contract version changed"
    )
    require(document["contract_id"] == "grafana-recovery-drill", "recovery ID changed")
    require(document["policy_owner"] == "watch", "WATCH must own recovery policy")
    require(document["execution_owner"] == "make", "MAKE must own recovery execution")
    require(
        document["observer_owner"] == "watch", "WATCH must own recovery observation"
    )
    require(document["consumer_owners"] == ["make", "watch"], "recovery owners changed")
    require(document["proof_status"] == "source-only", "recovery proof status changed")
    require(
        document["environment"] == "environment-gcp", "recovery environment changed"
    )
    require(
        document["approval"] == "environment-gcp/watch/grafana-unavailable",
        "recovery approval changed",
    )

    cluster = document["cluster"]
    require(
        cluster
        == {
            "name": "gcp",
            "control_plane": "k3s",
            "nodes": ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"],
            "first_server": "gcp-k3s-01",
        },
        "recovery cluster boundary changed",
    )
    target = document["target"]
    require(
        target
        == {
            "kind": "Deployment",
            "namespace": "monitoring",
            "name": "shell-watch-grafana",
            "service": "shell-watch-grafana",
            "healthy_replicas": 1,
            "annotation": "shell.internal/recovery-drill",
        },
        "recovery target boundary changed",
    )
    alert = document["alert"]
    require(isinstance(alert, dict), "recovery alert is missing")
    require(alert["name"] == "ShellWatchGrafanaUnavailable", "recovery alert changed")
    require(
        alert["query"]
        == 'kube_deployment_status_replicas_available{namespace="monitoring",deployment="shell-watch-grafana"} < 1',
        "recovery alert query changed",
    )
    require(alert["hold_seconds"] == 60, "recovery alert hold changed")
    require(alert["max_fire_seconds"] == 240, "recovery fire timeout changed")
    require(alert["max_resolve_seconds"] == 300, "recovery resolve timeout changed")
    require(
        alert["labels"]
        == {"owner": "watch", "drill": "grafana-unavailability", "severity": "warning"},
        "recovery alert labels changed",
    )
    stability = document["stability"]
    require(
        stability
        == {
            "samples": 20,
            "interval_seconds": 30,
            "max_memory_fraction": 0.8,
            "log_freshness_seconds": 300,
            "memory_limits_mib": {"prometheus": 1280, "grafana": 1024},
        },
        "recovery stability boundary changed",
    )
    require(
        document["logs"]
        == {
            "query": '{namespace="monitoring",pod=~"shell-watch-grafana.*"}',
            "max_entries": 20,
        },
        "recovery log boundary changed",
    )
    require(
        document["limits"] == {"max_outage_seconds": 300}, "recovery limits changed"
    )
    current = monitoring_contract.validate_contract()
    require(
        current["cluster"]["name"] == cluster["name"]
        and current["cluster"]["nodes"] == cluster["nodes"],
        "recovery and monitoring cluster contracts differ",
    )
    require(
        current["deployment"]["namespace"] == target["namespace"]
        and current["deployment"]["release"] + "-grafana" == target["name"],
        "recovery and monitoring Grafana targets differ",
    )
    return document


def validate_rule(path: Path = RULE_PATH) -> None:
    require(path.is_file() and not path.is_symlink(), "missing Grafana recovery rule")
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RecoveryValidationError("Grafana recovery rule cannot be read") from error
    for fragment in (
        "---",
        "apiVersion: monitoring.coreos.com/v1",
        "kind: PrometheusRule",
        "name: shell-watch-grafana-recovery",
        "namespace: monitoring",
        "release: shell-watch",
        "shell.platform/owner: watch",
        "alert: ShellWatchGrafanaUnavailable",
        'namespace="monitoring"',
        'deployment="shell-watch-grafana"',
        "for: 60s",
    ):
        require(fragment in source, f"Grafana recovery rule is missing: {fragment}")
    require("alert: Watchdog" not in source, "chart defaults must own Watchdog")
    alert = validate_contract()["alert"]
    require(
        re.sub(r"\s+", "", alert["query"]) in re.sub(r"\s+", "", source),
        "Grafana recovery rule query differs from the contract",
    )
    for key, value in alert["labels"].items():
        require(
            f"{key}: {value}" in source,
            f"Grafana recovery rule label differs from the contract: {key}",
        )
    require(
        source.count("alert: ShellWatchGrafanaUnavailable") == 1,
        "recovery rule must contain one Grafana alert",
    )
    for forbidden in (
        "shellprod.dev",
        "LokiRecovery",
        "loki-recovery",
        "password",
        "token",
    ):
        require(
            forbidden.lower() not in source.lower(),
            f"recovery rule contains forbidden scope: {forbidden}",
        )


def validate_operation_id(value: str) -> None:
    require(OPERATION_ID_RE.fullmatch(value) is not None, "operation ID is invalid")


def parse_timestamp(value: Any, label: str) -> datetime | None:
    if value is None:
        return None
    require(
        isinstance(value, str) and value.endswith("Z"),
        f"{label} timestamp is invalid",
    )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RecoveryValidationError(f"{label} timestamp is invalid") from error
    require(parsed.utcoffset() == timedelta(0), f"{label} timestamp is not UTC")
    return parsed.astimezone(timezone.utc)


def object_with_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is invalid")
    document = cast(dict[str, Any], value)
    require(set(document) == keys, f"{label} shape changed")
    return document


def validate_monitoring_snapshot(value: Any, label: str, *, healthy: bool) -> None:
    snapshot = object_with_keys(value, {"grafana", "prometheus"}, label)
    for role, item_value in snapshot.items():
        item = object_with_keys(
            item_value,
            {
                "pod",
                "ready",
                "restart_count",
                "oom_killed",
                "memory_limit_bytes",
            },
            f"{label} {role}",
        )
        require(
            isinstance(item["pod"], str) and bool(item["pod"]),
            f"{label} {role} pod is invalid",
        )
        require(type(item["ready"]) is bool, f"{label} {role} readiness is invalid")
        require(
            type(item["restart_count"]) is int and item["restart_count"] >= 0,
            f"{label} {role} restart count is invalid",
        )
        require(
            type(item["oom_killed"]) is bool,
            f"{label} {role} out-of-memory state is invalid",
        )
        require(
            type(item["memory_limit_bytes"]) is int
            and item["memory_limit_bytes"] > 0,
            f"{label} {role} memory limit is invalid",
        )
        if healthy:
            require(
                item["ready"] and not item["oom_killed"],
                f"{label} {role} is not healthy",
            )


def validate_baseline(value: Any, contract: dict[str, Any]) -> None:
    baseline = object_with_keys(
        value,
        {
            "replicas",
            "available_replicas",
            "endpoints",
            "ready_nodes",
            "monitoring",
            "alert",
        },
        "evidence baseline",
    )
    target_replicas = contract["target"]["healthy_replicas"]
    require(baseline["replicas"] == target_replicas, "baseline replicas changed")
    require(
        baseline["available_replicas"] == target_replicas,
        "baseline available replicas changed",
    )
    require(
        type(baseline["endpoints"]) is int and baseline["endpoints"] > 0,
        "baseline endpoints are invalid",
    )
    require(
        baseline["ready_nodes"] == len(contract["cluster"]["nodes"]),
        "baseline node count changed",
    )
    validate_monitoring_snapshot(
        baseline["monitoring"], "evidence baseline monitoring", healthy=True
    )
    monitoring = cast(dict[str, Any], baseline["monitoring"])
    for role, expected_mib in contract["stability"]["memory_limits_mib"].items():
        require(
            monitoring[role]["memory_limit_bytes"] == expected_mib * 1024 * 1024,
            f"baseline {role} memory limit differs from the contract",
        )
    alert = object_with_keys(
        baseline["alert"], {"loaded", "firing", "active"}, "baseline alert"
    )
    require(
        alert == {"loaded": True, "firing": False, "active": False},
        "baseline alert is not healthy",
    )


def validate_terminal(value: Any, contract: dict[str, Any], *, passing: bool) -> None:
    if not passing and value == {}:
        return
    terminal = object_with_keys(
        value,
        {
            "replicas",
            "available_replicas",
            "endpoints",
            "nodes",
            "monitoring",
            "annotation_absent",
        },
        "terminal observation",
    )
    nodes_value = terminal["nodes"]
    require(isinstance(nodes_value, list), "terminal nodes are invalid")
    nodes: list[dict[str, Any]] = []
    for item in nodes_value:
        node = object_with_keys(
            item, {"name", "ready", "memory_pressure"}, "terminal node"
        )
        require(isinstance(node["name"], str), "terminal node name is invalid")
        require(
            type(node["ready"]) is bool and type(node["memory_pressure"]) is bool,
            "terminal node state is invalid",
        )
        nodes.append(node)
    require(
        {node["name"] for node in nodes} == set(contract["cluster"]["nodes"]),
        "terminal node set changed",
    )
    validate_monitoring_snapshot(
        terminal["monitoring"], "terminal monitoring", healthy=passing
    )
    monitoring = cast(dict[str, Any], terminal["monitoring"])
    for role, expected_mib in contract["stability"]["memory_limits_mib"].items():
        require(
            monitoring[role]["memory_limit_bytes"] == expected_mib * 1024 * 1024,
            f"terminal {role} memory limit differs from the contract",
        )
    require(
        type(terminal["annotation_absent"]) is bool,
        "terminal annotation state is invalid",
    )
    if passing:
        target_replicas = contract["target"]["healthy_replicas"]
        require(terminal["replicas"] == target_replicas, "terminal replicas changed")
        require(
            terminal["available_replicas"] == target_replicas,
            "terminal available replicas changed",
        )
        require(
            type(terminal["endpoints"]) is int and terminal["endpoints"] > 0,
            "terminal endpoints are invalid",
        )
        require(
            all(node["ready"] and not node["memory_pressure"] for node in nodes),
            "terminal nodes are not healthy",
        )
        require(terminal["annotation_absent"], "terminal annotation remains")
