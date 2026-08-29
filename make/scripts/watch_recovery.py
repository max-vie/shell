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


def stop_restore_guard(
    recovery: observer.RecoveryObserver, pid: int, operation: str
) -> bool:
    require(pid > 0, "Grafana restore guard process ID is invalid")
    command = (
        f"ARGS=$(ps -p {pid} -o args= 2>/dev/null) || exit 1; "
        f"printf '%s' \"$ARGS\" | grep -F -- {shlex.quote(operation)} >/dev/null || exit 1; "
        f"kill -TERM -- -{pid} 2>/dev/null || exit 1; "
        "for ATTEMPT in $(seq 1 20); do "
        f"kill -0 {pid} 2>/dev/null || {{ printf cancelled; exit 0; }}; "
        "sleep 0.1; done; exit 1"
    )
    try:
        output = transport.ssh(
            connection=recovery.connection,
            command=command,
            label="MAKE stop Grafana restore guard",
        )
        return output.strip().endswith("cancelled")
    except (transport.TransportError, OSError):
        return False


def wait_until(
    description: str, predicate: Callable[[], bool], timeout: int, interval: int = 5
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise RecoveryDrillError(f"timed out waiting for {description}")


def healthy(recovery: observer.RecoveryObserver) -> bool:
    document = recovery.deployment()
    return (
        document.get("spec", {}).get("replicas") == recovery.target["healthy_replicas"]
        and document.get("status", {}).get("availableReplicas")
        == recovery.target["healthy_replicas"]
        and recovery.endpoints() > 0
    )


def alert_firing(recovery: observer.RecoveryObserver) -> bool:
    state = recovery.alert_state()
    return state["loaded"] and state["firing"] and state["active"]


def alert_clear(recovery: observer.RecoveryObserver) -> bool:
    state = recovery.alert_state()
    return state["loaded"] and not state["firing"] and not state["active"]


def _error_text(error: BaseException) -> str:
    return str(error) or error.__class__.__name__


def append_failure(current: str | None, error: BaseException | str) -> str:
    detail = " ".join(
        (error if isinstance(error, str) else _error_text(error)).splitlines()
    )[:500]
    if any(
        forbidden in detail.lower()
        for forbidden in ("password", "token", "kubeconfig", "private key")
    ):
        detail = "recovery failure detail omitted by evidence policy"
    combined = f"{current}; {detail}" if current else detail
    return combined[:2000]


def seconds_between(start: str | None, end: str | None) -> float:
    if not start or not end:
        return 0.0
    left = datetime.fromisoformat(start.replace("Z", "+00:00"))
    right = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return (right - left).total_seconds()


def run_drill(approval: str, inventory_paths: list[Path], output: Path | None) -> None:
    contract = _contract()
    require(
        approval == contract["approval"] == APPROVAL,
        "recovery approval differs from the contract",
    )
    revision = require_clean_source()
    stability_result = run_stability_soak(inventory_paths)
    connection = resolve_connection(inventory_paths)
    recovery = observer.RecoveryObserver(connection, contract)
    run_existing_verifiers(inventory_paths)
    baseline = observer.preflight(recovery)
    require(
        require_clean_source() == revision,
        "recovery source changed during preflight",
    )
    operation = operation_id(revision)
    destination = evidence_path(output, operation)
    recovery_contract.prepare_evidence_destination(destination)
    print(
        f"Grafana recovery operation: {operation}; evidence: {destination}",
        flush=True,
    )

    started_at = observer.utc_now()
    during_endpoints: int | None = None
    fault_observed_at: str | None = None
    alert_fired_at: str | None = None
    restore_started_at: str | None = None
    recovered_at: str | None = None
    alert_resolved_at: str | None = None
    completed_at: str | None = None
    guard_pid: int | None = None
    guard_cancelled = False
    injected = False
    injection_started = False
    failure: str | None = None
    logs: list[dict[str, str]] = []
    post: dict[str, Any] = {}

    try:
        guard_pid = start_restore_guard(recovery, operation)
        injection_started = True
        inject_fault(recovery, operation)
        injected = True
        wait_until(
            "Grafana endpoints to disappear", lambda: recovery.endpoints() == 0, 60, 2
        )
        during_endpoints = 0
        fault_observed_at = observer.utc_now()
        wait_until(
            "Grafana recovery alert to fire",
            lambda: alert_firing(recovery),
            int(contract["alert"]["max_fire_seconds"]),
            5,
        )
        alert_fired_at = observer.utc_now()
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001
        failure = append_failure(failure, error)
        try:
            document = recovery.deployment()
            annotations = document.get("metadata", {}).get("annotations", {})
            injected = (
                isinstance(annotations, dict)
                and annotations.get(observer.ANNOTATION) == operation
            )
        except (Exception, KeyboardInterrupt) as readback_error:  # noqa: BLE001
            injected = injection_started
            failure = append_failure(
                failure,
                f"post-injection readback failed: {_error_text(readback_error)}",
            )
    finally:
        if injected or guard_pid is not None:
            restore_started_at = observer.utc_now()
            restore_succeeded = False
            try:
                if injected:
                    restore_fault(recovery, operation)
                    wait_until(
                        "Grafana deployment to become healthy",
                        lambda: healthy(recovery),
                        300,
                        5,
                    )
                    recovered_at = observer.utc_now()
                    restore_succeeded = True
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001
                failure = append_failure(failure, error)
            finally:
                if guard_pid is not None and (restore_succeeded or not injected):
                    guard_cancelled = stop_restore_guard(recovery, guard_pid, operation)

    if recovered_at is not None:
        try:
            wait_until(
                "Grafana recovery alert to resolve",
                lambda: alert_clear(recovery),
                int(contract["alert"]["max_resolve_seconds"]),
                5,
            )
            alert_resolved_at = observer.utc_now()
            logs = recovery.loki_entries(started_at, observer.utc_now())
            require(bool(logs), "Loki returned no Grafana log entries during the drill")
            run_existing_verifiers(inventory_paths)
        except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001
            failure = append_failure(failure, error)

    try:
        post = recovery.terminal_snapshot()
        require(
            post["replicas"] == contract["target"]["healthy_replicas"],
            "Grafana is not healthy after the drill",
        )
        require(
            post["available_replicas"] == contract["target"]["healthy_replicas"],
            "Grafana has no available replica after the drill",
        )
        require(post["endpoints"] > 0, "Grafana has no endpoint after the drill")
        require(post["annotation_absent"], "Grafana recovery annotation remains")
        require(
            all(
                node["ready"] and not node["memory_pressure"] for node in post["nodes"]
            ),
            "K3s node health failed after the drill",
        )
        require(
            all(
                item["ready"] and not item["oom_killed"]
                for item in post["monitoring"].values()
            ),
            "monitoring health failed after the drill",
        )
        require(
            post["monitoring"]["prometheus"]["pod"]
            == baseline["monitoring"]["prometheus"]["pod"]
            and post["monitoring"]["prometheus"]["restart_count"]
            == baseline["monitoring"]["prometheus"]["restart_count"],
            "Prometheus changed during the drill",
        )
        require(
            post["monitoring"]["grafana"]["restart_count"] == 0,
            "restored Grafana has restarted",
        )
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001
        failure = append_failure(failure, error)

    completed_at = completed_at or observer.utc_now()
    outage_duration = seconds_between(fault_observed_at, recovered_at)
    alert_duration = seconds_between(alert_fired_at, alert_resolved_at)
    if outage_duration > int(contract["limits"]["max_outage_seconds"]):
        failure = append_failure(failure, "recovery exceeded the outage limit")
    if guard_pid is not None and not guard_cancelled:
        failure = append_failure(failure, "restore guard was not cancelled")
    if recovered_at is None:
        failure = append_failure(failure, "Grafana recovery was not observed")
    if alert_resolved_at is None:
        failure = append_failure(failure, "Grafana recovery alert did not resolve")
    sample_hash = (
        hashlib.sha256(logs[0]["line"].encode("utf-8")).hexdigest() if logs else None
    )
    evidence = {
        "schema_version": "1.1",
        "contract_id": contract["contract_id"],
        "contract_version": contract["contract_version"],
        "environment": contract["environment"],
        "operation_id": operation,
        "implementation_revision": revision,
        "target": contract["target"],
        "started_at": started_at,
        "fault_observed_at": fault_observed_at,
        "alert_fired_at": alert_fired_at,
        "restore_started_at": restore_started_at,
        "recovered_at": recovered_at,
        "alert_resolved_at": alert_resolved_at,
        "completed_at": completed_at,
        "outage_duration_seconds": outage_duration,
        "alert_duration_seconds": alert_duration,
        "stability": stability_result,
        "baseline": baseline,
        "observations": {
            "during": {
                "endpoints": during_endpoints,
                "alert_fired": alert_fired_at is not None,
            },
            "after": post,
        },
        "logs": {
            "query": contract["logs"]["query"],
            "entry_count": len(logs),
            "sample_sha256": sample_hash,
        },
        "cleanup": {
            "annotation_absent": post.get("annotation_absent", False),
            "guard_cancelled": guard_cancelled,
            "restore_attempted": restore_started_at is not None,
        },
        "result": "pass" if failure is None else "fail",
        "failure": failure,
    }
    recovery_contract.write_evidence(destination, evidence)
    if evidence["result"] != "pass":
        raise RecoveryDrillError(
            f"Grafana recovery drill failed; evidence: {destination}: {failure}"
        )
    print(f"Grafana recovery drill passed; evidence: {destination}")


def restore(approval: str, inventory_paths: list[Path], operation: str) -> None:
    contract = _contract()
    require(
        approval == contract["approval"] == APPROVAL,
        "recovery approval differs from the contract",
    )
    recovery_contract.validate_operation_id(operation)
    connection = resolve_connection(inventory_paths)
    recovery = observer.RecoveryObserver(connection, contract)
    restore_fault(recovery, operation)
    wait_until(
        "Grafana deployment to become healthy", lambda: healthy(recovery), 300, 5
    )
    wait_until(
        "Grafana recovery alert to resolve", lambda: alert_clear(recovery), 300, 5
    )
    require(
        recovery.terminal_snapshot()["annotation_absent"],
        "Grafana recovery annotation remains after restore",
    )
    print("restored and verified Grafana recovery target")


def status(inventory_paths: list[Path]) -> None:
    contract = _contract()
    connection = resolve_connection(inventory_paths)
    recovery = observer.RecoveryObserver(connection, contract)
    document = recovery.deployment()
    metadata = document.get("metadata")
    annotations = metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
    require(isinstance(annotations, dict), "Grafana annotations are invalid")
    operation = annotations.get(observer.ANNOTATION)
    if operation is None:
        print("no Grafana recovery operation is active")
        return
    require(isinstance(operation, str), "Grafana recovery operation is invalid")
    recovery_contract.validate_operation_id(operation)
    print(f"active Grafana recovery operation: {operation}")


def _paths(values: list[str] | None) -> list[Path]:
    if values:
        return [Path(value) for value in values]
    return [
        REPOSITORY_ROOT / ".local/ansible/inventory.json",
        REPOSITORY_ROOT / ".local/ansible/connection-inventory.yml",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "rule-preview",
            "rule-apply",
            "status",
            "preflight",
            "stability-soak",
            "drill",
            "restore",
        ),
    )
    parser.add_argument("--approval", default="")
    parser.add_argument("--operation-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=int)
    parser.add_argument("--interval", type=int)
    parser.add_argument("--inventory", action="append", dest="inventory_paths")
    args = parser.parse_args()
    paths = _paths(args.inventory_paths)
    try:
        if args.action == "rule-preview":
            rule_preview(paths)
        elif args.action == "rule-apply":
            rule_apply(args.approval, paths)
        elif args.action == "status":
            status(paths)
        elif args.action == "preflight":
            run_preflight(paths)
        elif args.action == "stability-soak":
            run_stability_soak(paths, args.samples, args.interval)
        elif args.action == "drill":
            run_drill(args.approval, paths, args.output)
        else:
            require(
                args.operation_id is not None, "--operation-id is required for restore"
            )
            restore(args.approval, paths, args.operation_id)
    except (
        RecoveryDrillError,
        observer.RecoveryObservationError,
        recovery_contract.RecoveryValidationError,
        transport.TransportError,
        OSError,
        ValueError,
    ) as error:
        print(f"watch recovery failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
