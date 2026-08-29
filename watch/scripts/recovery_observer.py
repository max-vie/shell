#!/usr/bin/env python3
"""Read-only observations for the bounded Grafana recovery drill."""

from __future__ import annotations

import json
import re
import shlex
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ROOT.parent
MAKE_SCRIPTS_ROOT = REPOSITORY_ROOT / "make/scripts"
if str(MAKE_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(MAKE_SCRIPTS_ROOT))
import k3s_transport as transport  # noqa: E402
import verify_monitoring  # noqa: E402


RULE_PATH = ROOT / "monitoring/grafana-recovery.rules.yaml"
KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
ANNOTATION = "shell.internal/recovery-drill"
SERVICE_NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")


class RecoveryObservationError(RuntimeError):
    """A required recovery observation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryObservationError(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def kubectl(namespace: str = "monitoring") -> str:
    require(SERVICE_NAME_RE.fullmatch(namespace) is not None, "namespace is unsafe")
    return f"sudo -E KUBECONFIG={KUBECONFIG} k3s kubectl -n {shlex.quote(namespace)}"


def _json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise RecoveryObservationError(f"{label} is not valid JSON") from error


def _resource_items(raw: str, label: str) -> list[dict[str, Any]]:
    document = _json(raw, label)
    require(isinstance(document, dict), f"{label} is not an object")
    items = document.get("items")
    require(isinstance(items, list), f"{label} has no item list")
    result = [item for item in items if isinstance(item, dict)]
    require(len(result) == len(items), f"{label} contains an invalid item")
    return cast(list[dict[str, Any]], result)


def _conditions(resource: dict[str, Any]) -> dict[str, str]:
    status_value = resource.get("status")
    require(isinstance(status_value, dict), "resource status is invalid")
    status = cast(dict[str, Any], status_value)
    conditions = status.get("conditions")
    require(isinstance(conditions, list), "resource conditions are invalid")
    conditions = cast(list[Any], conditions)
    result: dict[str, str] = {}
    for condition in conditions:
        if isinstance(condition, dict):
            kind = condition.get("type")
            state = condition.get("status")
            if isinstance(kind, str) and isinstance(state, str):
                result[kind] = state
    return result


@dataclass
class RecoveryObserver:
    """Read-only view of the fixed current SHELL monitoring target."""

    connection: transport.Connection
    contract: dict[str, Any]

    @property
    def namespace(self) -> str:
        return cast(str, self.contract["target"]["namespace"])

    @property
    def target(self) -> dict[str, Any]:
        return cast(dict[str, Any], self.contract["target"])

    @property
    def monitoring_contract(self) -> dict[str, Any]:
        return verify_monitoring.contract.validate_contract()

    @property
    def deployment_selectors(self) -> dict[str, str]:
        return cast(
            dict[str, str],
            self.monitoring_contract["deployment"]["service_selectors"],
        )

    def service_pod_selector(self, role: str) -> str:
        require(role in {"grafana", "prometheus"}, "monitoring role is invalid")
        service = verify_monitoring.resolve_resource(
            self.connection,
            self.namespace,
            "service",
            self.deployment_selectors[role],
        )
        spec_value = service.get("spec")
        require(isinstance(spec_value, dict), f"{role} Service spec is invalid")
        spec = cast(dict[str, Any], spec_value)
        selector_value = spec.get("selector")
        require(
            isinstance(selector_value, dict) and bool(selector_value),
            f"{role} Service pod selector is invalid",
        )
        selector = cast(dict[Any, Any], selector_value)
        require(
            all(
                isinstance(key, str)
                and bool(key)
                and isinstance(value, str)
                and bool(value)
                for key, value in selector.items()
            ),
            f"{role} Service pod selector is invalid",
        )
        return ",".join(f"{key}={value}" for key, value in sorted(selector.items()))

    def role_pods(self, role: str) -> list[dict[str, Any]]:
        selector = self.service_pod_selector(role)
        output = transport.ssh(
            connection=self.connection,
            command=(
                f"{kubectl(self.namespace)} get pods -l {shlex.quote(selector)} -o json"
            ),
            label=f"WATCH {role} pod state",
        )
        items = _resource_items(output, f"{role} pods")
        require(len(items) == 1, f"{role} pod selection is ambiguous")
        return items

    def deployment(self) -> dict[str, Any]:
        target = self.target
        output = transport.ssh(
            connection=self.connection,
            command=(
                f"{kubectl(self.namespace)} get deployment "
                f"{shlex.quote(target['name'])} -o json"
            ),
            label="WATCH Grafana deployment state",
        )
        document = _json(output, "Grafana deployment")
        require(isinstance(document, dict), "Grafana deployment is invalid")
        return cast(dict[str, Any], document)

    def endpoints(self) -> int:
        target = self.target
        output = transport.ssh(
            connection=self.connection,
            command=(
                f"{kubectl(self.namespace)} get endpoints "
                f"{shlex.quote(target['service'])} -o json"
            ),
            label="WATCH Grafana endpoint state",
        )
        document = _json(output, "Grafana endpoints")
        require(isinstance(document, dict), "Grafana endpoints are invalid")
        subsets = document.get("subsets", [])
        require(isinstance(subsets, list), "Grafana endpoint subsets are invalid")
        count = 0
        for subset in subsets:
            if not isinstance(subset, dict):
                continue
            addresses = subset.get("addresses", [])
            if isinstance(addresses, list):
                count += len(
                    [address for address in addresses if isinstance(address, dict)]
                )
        return count

    def nodes(self) -> list[dict[str, Any]]:
        output = transport.ssh(
            connection=self.connection,
            command=f"{kubectl('default')} get nodes -o json",
            label="WATCH K3s node state",
        )
        items = _resource_items(output, "K3s nodes")
        expected = set(self.contract["cluster"]["nodes"])
        actual: set[Any] = set()
        for item in items:
            metadata = item.get("metadata")
            require(isinstance(metadata, dict), "K3s node metadata is invalid")
            metadata = cast(dict[str, Any], metadata)
            actual.add(metadata.get("name"))
        require(len(items) == len(expected), "K3s node count changed")
        require(actual == expected, "K3s node set changed")
        result: list[dict[str, Any]] = []
        for item in items:
            metadata_value = item.get("metadata")
            require(isinstance(metadata_value, dict), "K3s node metadata is invalid")
            metadata = cast(dict[str, Any], metadata_value)
            name = metadata.get("name")
            require(isinstance(name, str), "K3s node name is invalid")
            conditions = _conditions(item)
            result.append(
                {
                    "name": name,
                    "ready": conditions.get("Ready") == "True",
                    "memory_pressure": conditions.get("MemoryPressure") == "True",
                }
            )
        return sorted(result, key=lambda value: cast(str, value["name"]))

    def monitoring_snapshot(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for role in ("grafana", "prometheus"):
            item = self.role_pods(role)[0]
            metadata_value = item.get("metadata")
            spec_value = item.get("spec")
            status_value = item.get("status")
            require(isinstance(metadata_value, dict), f"{role} pod metadata is invalid")
            require(isinstance(spec_value, dict), f"{role} pod spec is invalid")
            require(isinstance(status_value, dict), f"{role} pod status is invalid")
            metadata = cast(dict[str, Any], metadata_value)
            spec = cast(dict[str, Any], spec_value)
            status = cast(dict[str, Any], status_value)
            name = metadata.get("name")
            require(isinstance(name, str) and bool(name), f"{role} pod name is invalid")
            containers = status.get("containerStatuses", [])
            require(
                isinstance(containers, list) and bool(containers),
                f"{role} container state is missing",
            )
            valid = [
                container for container in containers if isinstance(container, dict)
            ]
            require(len(valid) == len(containers), f"{role} container state is invalid")
            require(
                all(type(container.get("restartCount")) is int for container in valid),
                f"{role} restart state is invalid",
            )
            restart_count = sum(
                cast(int, container["restartCount"]) for container in valid
            )
            pod_containers = spec.get("containers")
            require(isinstance(pod_containers, list), f"{role} pod containers are invalid")
            pod_containers = cast(list[Any], pod_containers)
            role_containers = [
                container
                for container in pod_containers
                if isinstance(container, dict) and container.get("name") == role
            ]
            require(len(role_containers) == 1, f"{role} workload container is ambiguous")
            resources = role_containers[0].get("resources")
            limits = resources.get("limits") if isinstance(resources, dict) else None
            memory_limit = limits.get("memory") if isinstance(limits, dict) else None
            oom_killed = any(
                any(
                    isinstance(container.get(state_name), dict)
                    and isinstance(container[state_name].get("terminated"), dict)
                    and container[state_name]["terminated"].get("reason") == "OOMKilled"
                    for state_name in ("lastState", "state")
                )
                for container in valid
            )
            result[role] = {
                "pod": name,
                "ready": all(container.get("ready") is True for container in valid),
                "restart_count": restart_count,
                "oom_killed": oom_killed,
                "memory_limit_bytes": _memory_bytes(memory_limit),
            }
        return result

    def memory_usage(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for role in ("grafana", "prometheus"):
            selector = self.service_pod_selector(role)
            output = transport.ssh(
                connection=self.connection,
                command=(
                    f"{kubectl(self.namespace)} top pod -l {shlex.quote(selector)} "
                    "--no-headers"
                ),
                label=f"WATCH {role} memory usage",
            )
            rows = [line.split() for line in output.splitlines() if line.strip()]
            require(
                len(rows) == 1 and len(rows[0]) >= 3,
                f"{role} memory usage is ambiguous",
            )
            result[role] = {
                "pod": rows[0][0],
                "bytes": _memory_bytes(rows[0][2]),
            }
        return result

    def alert_state(self) -> dict[str, bool]:
        alert = self.contract["alert"]
        name = cast(str, alert["name"])
        prometheus_selector = self.deployment_selectors["prometheus"]
        alertmanager_selector = self.deployment_selectors["alertmanager"]
        rules_raw = verify_monitoring.query_service(
            self.connection,
            self.namespace,
            prometheus_selector,
            9090,
            "/api/v1/rules?type=alert",
        )
        rules = _json(rules_raw, "Prometheus rules")
        require(
            isinstance(rules, dict) and rules.get("status") == "success",
            "Prometheus rules query failed",
        )
        data = rules.get("data")
        groups = data.get("groups") if isinstance(data, dict) else None
        require(isinstance(groups, list), "Prometheus rules response is invalid")
        groups = cast(list[Any], groups)
        matches: list[dict[str, Any]] = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            rule_items = group.get("rules", [])
            if isinstance(rule_items, list):
                matches.extend(
                    cast(dict[str, Any], rule)
                    for rule in rule_items
                    if isinstance(rule, dict) and rule.get("name") == name
                )
        require(len(matches) == 1, "Grafana recovery rule is missing or duplicated")
        rule = matches[0]
        expected_labels = cast(dict[str, str], alert["labels"])
        loaded = (
            rule.get("health") == "ok"
            and rule.get("duration") == alert["hold_seconds"]
            and rule.get("labels") == expected_labels
            and isinstance(rule.get("query"), str)
            and re.sub(r"\s+", "", rule["query"]) == re.sub(r"\s+", "", alert["query"])
        )
        encoded = quote(f'ALERTS{{alertname="{name}",alertstate="firing"}}', safe="")
        firing_raw = verify_monitoring.query_service(
            self.connection,
            self.namespace,
            prometheus_selector,
            9090,
            f"/api/v1/query?query={encoded}",
        )
        firing_payload = _json(firing_raw, "Prometheus recovery alert")
        require(
            isinstance(firing_payload, dict)
            and firing_payload.get("status") == "success",
            "Prometheus recovery alert query failed",
        )
        firing_data = firing_payload.get("data")
        require(
            isinstance(firing_data, dict)
            and isinstance(firing_data.get("result"), list),
            "Prometheus recovery alert response is invalid",
        )
        firing = bool(firing_data["result"])
        active_raw = verify_monitoring.query_service(
            self.connection,
            self.namespace,
            alertmanager_selector,
            9093,
            "/api/v2/alerts?active=true",
        )
        active_payload = _json(active_raw, "Alertmanager alerts")
        require(
            isinstance(active_payload, list),
            "Alertmanager recovery alert response is invalid",
        )
        active = any(
            isinstance(item, dict)
            and isinstance(item.get("labels"), dict)
            and item["labels"].get("alertname") == name
            and all(
                item["labels"].get(key) == value
                for key, value in expected_labels.items()
            )
            for item in active_payload
        )
        return {"loaded": loaded, "firing": firing, "active": active}

    def loki_entries(self, start: str, end: str | None = None) -> list[dict[str, str]]:
        logs = self.contract["logs"]
        query = quote(cast(str, logs["query"]), safe="")
        path = f"/loki/api/v1/query_range?query={query}&limit={logs['max_entries']}&direction=backward"
        path += f"&start={quote(start, safe='')}"
        if end is not None:
            path += f"&end={quote(end, safe='')}"
        raw = verify_monitoring.query_service(
            self.connection,
            self.namespace,
            self.monitoring_contract["logs"]["loki_service_selector"],
            self.monitoring_contract["logs"]["loki_service_port"],
            path,
        )
        payload = _json(raw, "Loki recovery logs")
        data = payload.get("data") if isinstance(payload, dict) else None
        streams_value = data.get("result") if isinstance(data, dict) else None
        require(isinstance(streams_value, list), "Loki recovery response is invalid")
        streams = cast(list[Any], streams_value)
        result: list[dict[str, str]] = []
        for stream in streams:
            if not isinstance(stream, dict):
                continue
            labels = stream.get("stream", {})
            values = stream.get("values", [])
            if not isinstance(labels, dict) or not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, list) and len(value) >= 2:
                    result.append({"timestamp": str(value[0]), "line": str(value[1])})
        return result[: int(logs["max_entries"])]

    def terminal_snapshot(self) -> dict[str, Any]:
        deployment = self.deployment()
        metadata = deployment.get("metadata", {})
        annotations = (
            metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
        )
        status = deployment.get("status", {})
        spec = deployment.get("spec", {})
        require(isinstance(annotations, dict), "Grafana annotations are invalid")
        require(
            isinstance(status, dict) and isinstance(spec, dict),
            "Grafana deployment state is invalid",
        )
        return {
            "replicas": spec.get("replicas"),
            "available_replicas": status.get("availableReplicas", 0),
            "endpoints": self.endpoints(),
            "nodes": self.nodes(),
            "monitoring": self.monitoring_snapshot(),
            "annotation_absent": ANNOTATION not in annotations,
        }


def _memory_bytes(value: str | None) -> int:
    if not isinstance(value, str) or not value:
        raise RecoveryObservationError("memory value is missing")
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMG]i|[KMG]|)", value)
    if match is None:
        raise RecoveryObservationError(f"memory value is invalid: {value}")
    amount = float(match.group(1))
    unit = match.group(2)
    multiplier = {
        "": 1,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
    }[unit]
    return int(amount * multiplier)


def preflight(observer: RecoveryObserver) -> dict[str, Any]:
    target = observer.target
    deployment = observer.deployment()
    spec = deployment.get("spec", {})
    status = deployment.get("status", {})
    require(
        isinstance(spec, dict) and isinstance(status, dict),
        "Grafana deployment state is invalid",
    )
    require(
        spec.get("replicas") == target["healthy_replicas"],
        "Grafana desired replicas are not healthy",
    )
    require(
        status.get("availableReplicas") == target["healthy_replicas"],
        "Grafana available replicas are not healthy",
    )
    require(observer.endpoints() > 0, "Grafana has no Service endpoint")
    metadata = deployment.get("metadata")
    require(isinstance(metadata, dict), "Grafana deployment metadata is invalid")
    metadata = cast(dict[str, Any], metadata)
    annotations = metadata.get("annotations", {})
    require(isinstance(annotations, dict), "Grafana annotations are invalid")
    require(ANNOTATION not in annotations, "another recovery operation is active")
    nodes = observer.nodes()
    require(
        all(node["ready"] and not node["memory_pressure"] for node in nodes),
        "K3s node preflight failed",
    )
    monitoring = observer.monitoring_snapshot()
    require(
        all(item["ready"] and not item["oom_killed"] for item in monitoring.values()),
        "monitoring pod preflight failed",
    )
    state = observer.alert_state()
    require(state["loaded"], "Grafana recovery alert is not loaded")
    require(
        not state["firing"] and not state["active"],
        "Grafana recovery alert is already active",
    )
    return {
        "replicas": spec["replicas"],
        "available_replicas": status["availableReplicas"],
        "endpoints": observer.endpoints(),
        "ready_nodes": len(nodes),
        "monitoring": monitoring,
        "alert": state,
    }
