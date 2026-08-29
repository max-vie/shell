#!/usr/bin/env python3
"""Run the MAKE-owned Grafana recovery rule and guarded drill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shlex
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, cast


SCRIPT_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_ROOT.parents[1]
WATCH_SCRIPTS_ROOT = REPOSITORY_ROOT / "watch/scripts"
if str(WATCH_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(WATCH_SCRIPTS_ROOT))
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import k3s_transport as transport  # noqa: E402
import recovery_observer as observer  # noqa: E402
import validate_recovery as recovery_contract  # noqa: E402
import verify_logs  # noqa: E402
import verify_monitoring  # noqa: E402


APPROVAL = "environment-gcp/watch/grafana-unavailable"
FIELD_MANAGER = "shell-make-watch-recovery"
DEFAULT_OUTPUT_ROOT = REPOSITORY_ROOT / ".local/watch/recovery"


class RecoveryDrillError(RuntimeError):
    """The guarded recovery operation did not meet its terminal checks."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryDrillError(message)


def _contract() -> dict[str, Any]:
    document = recovery_contract.validate_contract()
    recovery_contract.validate_rule()
    return document


def _git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPOSITORY_ROOT), *args],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RecoveryDrillError("Git source check could not complete") from error
    if completed.returncode:
        raise RecoveryDrillError(f"git {' '.join(args)} failed")
    return completed.stdout.strip()


def require_clean_source() -> str:
    require(
        not _git("status", "--porcelain", "--untracked-files=all"),
        "recovery mutation requires a clean worktree",
    )
    head = _git("rev-parse", "HEAD")
    origin = _git("rev-parse", "origin/main")
    require(head == origin, "recovery mutation requires HEAD to match origin/main")
    require(len(head) == 40, "recovery source revision is invalid")
    return head


def resolve_connection(inventory_paths: list[Path]) -> transport.Connection:
    return transport.resolve_connection(inventory_paths)


def _kubectl(namespace: str) -> str:
    return observer.kubectl(namespace)


def _rule_text() -> str:
    try:
        return observer.RULE_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RecoveryDrillError("Grafana recovery rule cannot be read") from error


def apply_rule(
    connection: transport.Connection,
    *,
    dry_run: bool,
) -> None:
    mode = "--dry-run=server" if dry_run else "--server-side"
    command = (
        f"{_kubectl('monitoring')} apply {mode} --field-manager={FIELD_MANAGER} -f -"
    )
    transport.ssh(
        connection=connection,
        command=command,
        label="MAKE Grafana recovery rule preview"
        if dry_run
        else "MAKE Grafana recovery rule apply",
        input_text=_rule_text(),
        timeout_seconds=60,
    )


def rule_preview(inventory_paths: list[Path]) -> None:
    contract = _contract()
    connection = resolve_connection(inventory_paths)
    apply_rule(connection, dry_run=True)
    print(f"validated {contract['contract_id']} with server-side dry-run")


def rule_apply(approval: str, inventory_paths: list[Path]) -> None:
    contract = _contract()
    require(
        approval == contract["approval"] == APPROVAL,
        "recovery approval differs from the contract",
    )
    require_clean_source()
    connection = resolve_connection(inventory_paths)
    apply_rule(connection, dry_run=False)
    recovery = observer.RecoveryObserver(connection, contract)
    deadline = time.monotonic() + int(contract["alert"]["max_fire_seconds"])
    while time.monotonic() < deadline:
        state = recovery.alert_state()
        if state["loaded"]:
            require(
                not state["firing"] and not state["active"],
                "Grafana recovery alert is already active",
            )
            return
        time.sleep(5)
    raise RecoveryDrillError("Grafana recovery rule did not load")


def run_existing_verifiers(inventory_paths: list[Path]) -> None:
    verify_monitoring.verify(inventory_paths)
    verify_logs.verify(inventory_paths)


def run_preflight(inventory_paths: list[Path]) -> None:
    contract = _contract()
    connection = resolve_connection(inventory_paths)
    run_existing_verifiers(inventory_paths)
    result = observer.preflight(observer.RecoveryObserver(connection, contract))
    print(f"verified Grafana recovery preflight: {json.dumps(result, sort_keys=True)}")


def run_stability_soak(
    inventory_paths: list[Path], samples: int | None = None, interval: int | None = None
) -> dict[str, Any]:
    contract = _contract()
    stability = cast(dict[str, Any], contract["stability"])
    sample_count = stability["samples"] if samples is None else samples
    sample_interval = stability["interval_seconds"] if interval is None else interval
    require(
        type(sample_count) is int and sample_count > 0,
        "stability samples must be positive",
    )
    require(
        type(sample_interval) is int and sample_interval > 0,
        "stability interval must be positive",
    )
    connection = resolve_connection(inventory_paths)
    recovery = observer.RecoveryObserver(connection, contract)
    run_existing_verifiers(inventory_paths)
    baseline = observer.preflight(recovery)
    started_at = observer.utc_now()
    limits = cast(dict[str, int], stability["memory_limits_mib"])
    fraction = float(stability["max_memory_fraction"])
    for index in range(sample_count):
        snapshot = recovery.monitoring_snapshot()
        require(
            all(
                item["ready"]
                and not item["oom_killed"]
                and item["pod"] == baseline["monitoring"][role]["pod"]
                and item["restart_count"]
                == baseline["monitoring"][role]["restart_count"]
                for role, item in snapshot.items()
            ),
            "monitoring changed during stability soak",
        )
        require(
            all(
                item["memory_limit_bytes"] == limits[role] * 1024 * 1024
                for role, item in snapshot.items()
            ),
            "deployed monitoring memory limits differ from the recovery contract",
        )
        nodes = recovery.nodes()
        require(
            all(node["ready"] and not node["memory_pressure"] for node in nodes),
            "K3s node health changed during soak",
        )
        state = recovery.alert_state()
        require(
            state["loaded"] and not state["firing"] and not state["active"],
            "recovery alert changed during soak",
        )
        now = datetime.now(timezone.utc)
        start = (
            (now - timedelta(seconds=int(stability["log_freshness_seconds"])))
            .isoformat()
            .replace("+00:00", "Z")
        )
        if not recovery.loki_entries(start, now.isoformat().replace("+00:00", "Z")):
            raise RecoveryDrillError("Loki returned no fresh Grafana logs during soak")
        usage = recovery.memory_usage()
        for role, measurement in usage.items():
            require(
                measurement["pod"] == snapshot[role]["pod"],
                f"{role} memory sample changed pods",
            )
            require(
                measurement["bytes"] < snapshot[role]["memory_limit_bytes"] * fraction,
                f"{role} memory usage is above the soak limit",
            )
        print(f"stability soak sample {index + 1}/{sample_count}: monitoring healthy")
        if index + 1 < sample_count:
            time.sleep(sample_interval)
    completed_at = observer.utc_now()
    print(
        f"verified Grafana recovery stability soak from baseline {json.dumps(baseline, sort_keys=True)}"
    )
    return {
        "started_at": started_at,
        "completed_at": completed_at,
        "samples": sample_count,
        "interval_seconds": sample_interval,
        "result": "pass",
    }


def operation_id(revision: str, nonce: str | None = None) -> str:
    token = nonce or secrets.token_hex(4)
    require(
        len(token) == 8 and all(character in "0123456789abcdef" for character in token),
        "recovery operation nonce is invalid",
    )
    return (
        f"grafana-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        f"-{revision[:12]}-{token}"
    )


def evidence_path(value: Path | None, operation: str) -> Path:
    path = value or DEFAULT_OUTPUT_ROOT / f"{operation}.json"
    path = Path(os.path.abspath(path))
    root = DEFAULT_OUTPUT_ROOT.resolve()
    require(
        path.parent == root,
        "evidence output must be a direct child of .local/watch/recovery",
    )
    return path


def patch_command(
    document: dict[str, Any], operation: str, target: dict[str, Any]
) -> str:
    metadata = document.get("metadata")
    require(isinstance(metadata, dict), "Grafana deployment metadata is invalid")
    metadata = cast(dict[str, Any], metadata)
    resource_version = metadata.get("resourceVersion")
    require(
        isinstance(resource_version, str) and bool(resource_version),
        "Grafana deployment resource version is invalid",
    )
    annotations = metadata.get("annotations")
    operations: list[dict[str, Any]] = [
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": resource_version,
        },
        {"op": "test", "path": "/spec/replicas", "value": target["healthy_replicas"]},
    ]
    if isinstance(annotations, dict):
        key = observer.ANNOTATION.replace("~", "~0").replace("/", "~1")
        operations.append(
            {"op": "test", "path": "/metadata/annotations", "value": annotations}
        )
        operations.append(
            {"op": "add", "path": f"/metadata/annotations/{key}", "value": operation}
        )
    else:
        operations.append(
            {
                "op": "add",
                "path": "/metadata/annotations",
                "value": {observer.ANNOTATION: operation},
            }
        )
    operations.append({"op": "replace", "path": "/spec/replicas", "value": 0})
    payload = shlex.quote(json.dumps(operations, separators=(",", ":")))
    return (
        f"{_kubectl(target['namespace'])} patch deployment {shlex.quote(target['name'])} "
        f"--type=json -p {payload}"
    )


def restore_command(
    document: dict[str, Any], target: dict[str, Any], operation: str
) -> str:
    metadata = document.get("metadata")
    spec = document.get("spec")
    require(
        isinstance(metadata, dict) and isinstance(spec, dict),
        "Grafana deployment state is invalid",
    )
    metadata = cast(dict[str, Any], metadata)
    spec = cast(dict[str, Any], spec)
    annotations = metadata.get("annotations")
    resource_version = metadata.get("resourceVersion")
    replicas = spec.get("replicas")
    require(isinstance(annotations, dict), "Grafana annotations are invalid")
    annotations = cast(dict[str, Any], annotations)
    require(
        annotations.get(observer.ANNOTATION) == operation,
        "Grafana recovery annotation does not match the operation",
    )
    require(
        isinstance(resource_version, str) and bool(resource_version),
        "Grafana deployment resource version is invalid",
    )
    require(
        replicas in {0, target["healthy_replicas"]},
        "Grafana desired replicas changed during recovery",
    )
    key = observer.ANNOTATION.replace("~", "~0").replace("/", "~1")
    payload = shlex.quote(
        json.dumps(
            [
                {
                    "op": "test",
                    "path": "/metadata/resourceVersion",
                    "value": resource_version,
                },
                {
                    "op": "test",
                    "path": f"/metadata/annotations/{key}",
                    "value": operation,
                },
                {"op": "test", "path": "/spec/replicas", "value": replicas},
                {"op": "remove", "path": f"/metadata/annotations/{key}"},
                {
                    "op": "replace",
                    "path": "/spec/replicas",
                    "value": target["healthy_replicas"],
                },
            ],
            separators=(",", ":"),
        )
    )
    return (
        f"{_kubectl(target['namespace'])} patch deployment {shlex.quote(target['name'])} "
        f"--type=json -p {payload}"
    )


def guard_restore_command(target: dict[str, Any], operation: str) -> str:
    key = observer.ANNOTATION.replace("~", "~0").replace("/", "~1")
    payload = shlex.quote(
        json.dumps(
            [
                {
                    "op": "test",
                    "path": f"/metadata/annotations/{key}",
                    "value": operation,
                },
                {"op": "test", "path": "/spec/replicas", "value": 0},
                {"op": "remove", "path": f"/metadata/annotations/{key}"},
                {
                    "op": "replace",
                    "path": "/spec/replicas",
                    "value": target["healthy_replicas"],
                },
            ],
            separators=(",", ":"),
        )
    )
    return (
        f"{_kubectl(target['namespace'])} patch deployment {shlex.quote(target['name'])} "
        f"--type=json -p {payload}"
    )


def inject_fault(recovery: observer.RecoveryObserver, operation: str) -> None:
    document = recovery.deployment()
    target = recovery.target
    require(
        document.get("spec", {}).get("replicas") == target["healthy_replicas"],
        "Grafana desired replicas changed before injection",
    )
    metadata = document.get("metadata", {})
    annotations = metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
    require(isinstance(annotations, dict), "Grafana annotations are invalid")
    require(
        observer.ANNOTATION not in annotations,
        "Grafana already has a recovery annotation",
    )
    transport.ssh(
        connection=recovery.connection,
        command=patch_command(document, operation, target),
        label="MAKE inject Grafana outage",
    )
    updated = recovery.deployment()
    require(
        updated.get("spec", {}).get("replicas") == 0, "Grafana did not scale to zero"
    )
    updated_annotations = updated.get("metadata", {}).get("annotations", {})
    require(
        isinstance(updated_annotations, dict)
        and updated_annotations.get(observer.ANNOTATION) == operation,
        "Grafana operation annotation was not recorded",
    )


def restore_fault(recovery: observer.RecoveryObserver, operation: str) -> None:
    target = recovery.target
    document = recovery.deployment()
    transport.ssh(
        connection=recovery.connection,
        command=restore_command(document, target, operation),
        label="MAKE restore Grafana deployment",
    )
    updated = recovery.deployment()
    metadata = updated.get("metadata")
    spec = updated.get("spec")
    annotations = metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
    require(
        isinstance(spec, dict) and spec.get("replicas") == target["healthy_replicas"],
        "Grafana desired replicas were not restored",
    )
    require(
        isinstance(annotations, dict) and observer.ANNOTATION not in annotations,
        "Grafana recovery annotation remains after restoration",
    )


def start_restore_guard(recovery: observer.RecoveryObserver, operation: str) -> int:
    target = recovery.target
    max_outage = int(recovery.contract["limits"]["max_outage_seconds"])
    escaped_annotation = observer.ANNOTATION.replace(".", "\\.").replace("/", "\\/")
    read_annotation = (
        f"{_kubectl(target['namespace'])} get deployment {shlex.quote(target['name'])} "
        f"-o jsonpath='{{.metadata.annotations.{escaped_annotation}}}'"
    )
    body = (
        f"sleep {max_outage}; "
        "while :; do "
        f"if {guard_restore_command(target, operation)}; then "
        f"{_kubectl(target['namespace'])} rollout status deployment/"
        f"{shlex.quote(target['name'])} --timeout=240s; exit $?; fi; "
        f"current=$({read_annotation}) || {{ sleep 5; continue; }}; "
        f'test "$current" = {shlex.quote(operation)} || exit 0; '
        "sleep 5; done"
    )
    command = (
        f"nohup setsid sh -c {shlex.quote(body)} >/dev/null 2>&1 </dev/null & "
        'PID=$!; kill -0 "$PID" 2>/dev/null; '
        'ARGS=$(ps -p "$PID" -o args=); '
        f"printf '%s' \"$ARGS\" | grep -F -- {shlex.quote(operation)} >/dev/null; "
        "printf '%s\\n' \"$PID\""
    )
    output = transport.ssh(
        connection=recovery.connection,
        command=command,
        label="MAKE start Grafana restore guard",
    )
    values = [line.strip() for line in output.splitlines() if line.strip().isdigit()]
    if not values:
        raise RecoveryDrillError("Grafana restore guard did not return a process ID")
    return int(values[-1])
