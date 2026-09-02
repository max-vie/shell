#!/usr/bin/env python3
"""Read-only verification of the GCP platform add-ons."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
MAKE_SCRIPTS = ROOT / "make/scripts"
if str(MAKE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(MAKE_SCRIPTS))
import k3s_transport as transport  # noqa: E402
import validate_platform_addons as contract  # noqa: E402


class PlatformAddonsVerifyError(RuntimeError):
    """WATCH platform add-on verification failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlatformAddonsVerifyError(message)


def get_json(
    connection: transport.Connection,
    resource: str,
    *,
    namespace: str | None = None,
) -> dict[str, Any]:
    command = [
        "sudo",
        "-E",
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml",
        "k3s",
        "kubectl",
        "get",
        resource,
    ]
    if namespace is not None:
        command.extend(["--namespace", namespace])
    command.extend(["--output", "json"])
    output = transport.ssh(
        "set -eu; " + shlex.join(command),
        connection,
        label=f"WATCH platform add-on lookup {resource}",
        timeout_seconds=90,
    )
    try:
        value = json.loads(output)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PlatformAddonsVerifyError(f"{resource} response is invalid JSON") from error
    require(isinstance(value, dict), f"{resource} response is not an object")
    return cast(dict[str, Any], value)


def verify(connection: transport.Connection) -> dict[str, Any]:
    expected = contract.validate()
    nodes = get_json(connection, "nodes")
    node_items_value = nodes.get("items")
    require(isinstance(node_items_value, list), "K3s node response is incomplete")
    node_items = cast(list[Any], node_items_value)
    ready_nodes: list[str] = []
    for item in node_items:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata", {})
        status = item.get("status", {})
        name = metadata.get("name") if isinstance(metadata, dict) else None
        if not isinstance(name, str):
            continue
        conditions = status.get("conditions", []) if isinstance(status, dict) else []
        if any(
            isinstance(condition, dict)
            and condition.get("type") == "Ready"
            and condition.get("status") == "True"
            for condition in conditions
        ):
            ready_nodes.append(name)
    require(
        sorted(ready_nodes) == expected["cluster"]["nodes"],
        "GCP K3s Ready node set changed",
    )

    controller = get_json(
        connection,
        "deployment/metallb-controller",
        namespace="metallb-system",
    )
    controller_status = controller.get("status", {})
    require(
        controller_status.get("availableReplicas") == 1,
        "MetalLB controller is not available",
    )
    speaker = get_json(
        connection,
        "daemonset/metallb-speaker",
        namespace="metallb-system",
    )
    speaker_status = speaker.get("status", {})
    require(
        speaker_status.get("desiredNumberScheduled") == 3
        and speaker_status.get("numberReady") == 3,
        "MetalLB speakers are not ready on all nodes",
    )

    longhorn_nodes = get_json(
        connection,
        "nodes.longhorn.io",
        namespace="longhorn-system",
    )
    longhorn_items_value = longhorn_nodes.get("items")
    require(
        isinstance(longhorn_items_value, list) and len(longhorn_items_value) == 3,
        "Longhorn node count changed",
    )
    longhorn_items = cast(list[Any], longhorn_items_value)
    for item in longhorn_items:
        status = item.get("status", {}) if isinstance(item, dict) else {}
        disks = status.get("diskStatus", {}) if isinstance(status, dict) else {}
        require(
            isinstance(disks, dict) and bool(disks),
            "Longhorn disk status is missing",
        )
        for disk in disks.values():
            conditions = disk.get("conditions", []) if isinstance(disk, dict) else []
            states = {
                condition.get("type"): condition.get("status")
                for condition in conditions
                if isinstance(condition, dict)
            }
            require(
                states.get("Ready") == "True" and states.get("Schedulable") == "True",
                "Longhorn disk is not ready and schedulable",
            )

    storage_class = get_json(connection, "storageclass/longhorn")
    metadata = storage_class.get("metadata", {})
    annotations = metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
    require(
        annotations.get("storageclass.kubernetes.io/is-default-class") == "true",
        "Longhorn is not the default storage class",
    )
    local_path = get_json(connection, "storageclass/local-path")
    local_metadata = local_path.get("metadata", {})
    local_annotations = (
        local_metadata.get("annotations", {}) if isinstance(local_metadata, dict) else {}
    )
    require(
        local_annotations.get("storageclass.kubernetes.io/is-default-class") != "true",
        "local-path remains the default storage class",
    )
    pools = get_json(
        connection,
        "ipaddresspools.metallb.io",
        namespace="metallb-system",
    )
    require(not pools.get("items"), "MetalLB service address pools are configured")
    return {
        "contract_id": expected["contract_id"],
        "ready_nodes": ready_nodes,
        "metallb_controller": "available",
        "metallb_speakers": 3,
        "longhorn_nodes": len(longhorn_items),
        "default_storage_class": "longhorn",
        "service_address_pools": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        require(bool(args.inventory), "private INIT inventories are required")
        result = verify(transport.resolve_connection(args.inventory))
        print(json.dumps(result, sort_keys=True))
    except (
        OSError,
        PlatformAddonsVerifyError,
        contract.PlatformAddonsWatchError,
        transport.TransportError,
    ) as error:
        print(f"WATCH platform add-on verification failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
