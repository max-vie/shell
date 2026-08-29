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
