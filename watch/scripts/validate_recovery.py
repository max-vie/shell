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


def validate_evidence(document: dict[str, Any]) -> None:
    expected = {
        "schema_version",
        "contract_id",
        "contract_version",
        "environment",
        "operation_id",
        "implementation_revision",
        "target",
        "started_at",
        "fault_observed_at",
        "alert_fired_at",
        "restore_started_at",
        "recovered_at",
        "alert_resolved_at",
        "completed_at",
        "outage_duration_seconds",
        "alert_duration_seconds",
        "stability",
        "baseline",
        "observations",
        "logs",
        "cleanup",
        "result",
        "failure",
    }
    require(set(document) == expected, "recovery evidence shape changed")
    require(document["schema_version"] == "1.1", "evidence schema changed")
    require(
        document["contract_id"] == "grafana-recovery-drill", "evidence contract changed"
    )
    require(
        document["contract_version"] == "1.0.0", "evidence contract version changed"
    )
    require(
        document["environment"] == "environment-gcp", "evidence environment changed"
    )
    operation_id = document["operation_id"]
    require(isinstance(operation_id, str), "evidence operation ID is invalid")
    validate_operation_id(operation_id)
    revision = document["implementation_revision"]
    require(
        isinstance(revision, str) and bool(re.fullmatch(r"[0-9a-f]{40}", revision)),
        "evidence revision is invalid",
    )
    contract = validate_contract()
    require(document["target"] == contract["target"], "evidence target changed")

    result = document["result"]
    require(result in {"pass", "fail"}, "evidence result is invalid")
    passing = result == "pass"

    ordered = (
        "started_at",
        "fault_observed_at",
        "alert_fired_at",
        "restore_started_at",
        "recovered_at",
        "alert_resolved_at",
        "completed_at",
    )
    timestamps: dict[str, datetime | None] = {}
    previous: datetime | None = None
    for label in ordered:
        current = parse_timestamp(document[label], label)
        timestamps[label] = current
        if current is None:
            continue
        if previous is not None:
            require(current >= previous, "evidence timestamps are out of order")
        previous = current
    require(timestamps["started_at"] is not None, "evidence lacks a start timestamp")

    outage_duration = document["outage_duration_seconds"]
    alert_duration = document["alert_duration_seconds"]
    require(
        type(outage_duration) in {int, float} and outage_duration >= 0,
        "outage duration is invalid",
    )
    require(
        type(alert_duration) in {int, float} and alert_duration >= 0,
        "alert duration is invalid",
    )

    def derived_seconds(left: str, right: str) -> float:
        start = timestamps[left]
        end = timestamps[right]
        if start is None or end is None:
            return 0.0
        return (end - start).total_seconds()

    require(
        abs(outage_duration - derived_seconds("fault_observed_at", "recovered_at"))
        < 0.001,
        "outage duration differs from timestamps",
    )
    require(
        abs(alert_duration - derived_seconds("alert_fired_at", "alert_resolved_at"))
        < 0.001,
        "alert duration differs from timestamps",
    )
    logs = document["logs"]
    require(isinstance(logs, dict), "evidence logs are invalid")
    require(
        set(logs) == {"query", "entry_count", "sample_sha256"},
        "evidence logs contain unexpected fields",
    )
    require(logs["query"] == contract["logs"]["query"], "evidence log query changed")
    require(
        type(logs["entry_count"]) is int and logs["entry_count"] >= 0,
        "evidence log count is invalid",
    )
    require(
        logs["sample_sha256"] is None
        or (
            isinstance(logs["sample_sha256"], str)
            and bool(SHA256_RE.fullmatch(logs["sample_sha256"]))
        ),
        "evidence log sample hash is invalid",
    )
    require(
        logs["entry_count"] <= contract["logs"]["max_entries"],
        "evidence log count exceeded the contract",
    )

    stability = object_with_keys(
        document["stability"],
        {"started_at", "completed_at", "samples", "interval_seconds", "result"},
        "evidence stability",
    )
    stability_started = parse_timestamp(stability["started_at"], "stability start")
    stability_completed = parse_timestamp(
        stability["completed_at"], "stability completion"
    )
    require(
        stability_started is not None and stability_completed is not None,
        "stability timestamps are invalid",
    )
    stability_started = cast(datetime, stability_started)
    stability_completed = cast(datetime, stability_completed)
    require(
        stability_completed >= stability_started,
        "stability timestamps are invalid",
    )
    require(
        stability_completed <= cast(datetime, timestamps["started_at"]),
        "stability completed after the drill started",
    )
    require(
        stability["samples"] == contract["stability"]["samples"]
        and stability["interval_seconds"] == contract["stability"]["interval_seconds"]
        and stability["result"] == "pass",
        "stability evidence differs from the contract",
    )
    require(
        (stability_completed - stability_started).total_seconds()
        >= (stability["samples"] - 1) * stability["interval_seconds"],
        "stability evidence is shorter than the contract window",
    )

    validate_baseline(document["baseline"], contract)
    observations = object_with_keys(
        document["observations"], {"during", "after"}, "evidence observations"
    )
    during = object_with_keys(
        observations["during"], {"endpoints", "alert_fired"}, "during observation"
    )
    require(
        during["endpoints"] is None or type(during["endpoints"]) is int,
        "during endpoints are invalid",
    )
    require(type(during["alert_fired"]) is bool, "during alert state is invalid")
    validate_terminal(observations["after"], contract, passing=passing)

    cleanup = object_with_keys(
        document["cleanup"],
        {"annotation_absent", "guard_cancelled", "restore_attempted"},
        "evidence cleanup",
    )
    require(
        all(type(cleanup[key]) is bool for key in cleanup),
        "evidence cleanup flags are invalid",
    )
    require(
        document["failure"] is None or isinstance(document["failure"], str),
        "evidence failure is invalid",
    )
    if isinstance(document["failure"], str):
        require(
            len(document["failure"]) <= 2000 and "\n" not in document["failure"],
            "evidence failure detail is invalid",
        )
        require(
            not any(
                forbidden in document["failure"].lower()
                for forbidden in ("password", "token", "kubeconfig", "private key")
            ),
            "evidence failure contains forbidden detail",
        )
    if passing:
        require(
            all(document[label] is not None for label in ordered),
            "passing evidence lacks timestamps",
        )
        require(document["failure"] is None, "passing evidence contains a failure")
        require(
            during == {"endpoints": 0, "alert_fired": True},
            "passing outage observation is incomplete",
        )
        baseline = cast(dict[str, Any], document["baseline"])
        baseline_monitoring = cast(dict[str, Any], baseline["monitoring"])
        terminal = cast(dict[str, Any], observations["after"])
        terminal_monitoring = cast(dict[str, Any], terminal["monitoring"])
        require(
            terminal_monitoring["prometheus"]["pod"]
            == baseline_monitoring["prometheus"]["pod"]
            and terminal_monitoring["prometheus"]["restart_count"]
            == baseline_monitoring["prometheus"]["restart_count"],
            "passing Prometheus observation changed during the drill",
        )
        require(
            terminal_monitoring["grafana"]["restart_count"] == 0,
            "passing Grafana observation contains a restart",
        )
        require(
            cleanup
            == {
                "annotation_absent": True,
                "guard_cancelled": True,
                "restore_attempted": True,
            },
            "passing evidence cleanup is incomplete",
        )
        require(
            logs["entry_count"] > 0 and logs["sample_sha256"] is not None,
            "passing evidence lacks log proof",
        )
        fire_delay = derived_seconds("fault_observed_at", "alert_fired_at")
        resolve_delay = derived_seconds("recovered_at", "alert_resolved_at")
        require(
            0 <= fire_delay <= contract["alert"]["max_fire_seconds"],
            "passing alert fire timing is invalid",
        )
        require(
            resolve_delay <= contract["alert"]["max_resolve_seconds"],
            "passing alert resolve timing is invalid",
        )
        require(
            outage_duration <= contract["limits"]["max_outage_seconds"],
            "passing outage exceeded the contract limit",
        )
    else:
        require(
            document["started_at"] is not None,
            "failed evidence lacks a start timestamp",
        )
        require(
            document["completed_at"] is not None,
            "failed evidence lacks a completion timestamp",
        )
        require(
            isinstance(document["failure"], str) and bool(document["failure"].strip()),
            "failed evidence lacks a failure",
        )


def prepare_evidence_destination(path: Path) -> Path:
    destination = Path(os.path.abspath(path))
    require(
        not destination.exists() and not destination.is_symlink(),
        "evidence output already exists",
    )
    evidence_root = Path(os.path.abspath(EVIDENCE_ROOT)).resolve()
    if evidence_root in destination.parents:
        require(
            destination.parent == evidence_root,
            "evidence output must be a direct child of the evidence directory",
        )
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(parent.is_dir() and not parent.is_symlink(), "evidence directory is unsafe")
    require(
        stat.S_IMODE(parent.stat().st_mode) == 0o700,
        "evidence directory must be mode 0700",
    )
    if destination.parent == evidence_root:
        current = parent
        while current != REPOSITORY_ROOT:
            require(
                current.is_dir() and not current.is_symlink(),
                "evidence directory is unsafe",
            )
            require(
                stat.S_IMODE(current.stat().st_mode) == 0o700,
                "private evidence parent must be mode 0700",
            )
            current = current.parent
    return destination


def write_evidence(path: Path, document: dict[str, Any]) -> None:
    validate_evidence(document)
    destination = prepare_evidence_destination(path)
    parent = destination.parent
    descriptor: int | None = None
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=parent
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = None
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, destination, follow_symlinks=False)
        temporary_path.unlink()
        temporary_path = None
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise RecoveryValidationError("evidence output already exists") from error
    except OSError as error:
        raise RecoveryValidationError("evidence output could not be written") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def validate(evidence: Path | None = None) -> None:
    validate_contract()
    validate_rule()
    if evidence is not None:
        validate_evidence(read_json(evidence, "recovery evidence"))
    print("validated Grafana recovery contract, rule, and evidence shape")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        validate(args.evidence)
    except (RecoveryValidationError, OSError) as error:
        print(f"recovery validation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
