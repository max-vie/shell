#!/usr/bin/env python3
"""Read-only verification for the WATCH Tempo and OTLP topology."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Any, cast


SCRIPT_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_ROOT.parents[1]
MAKE_SCRIPTS_ROOT = REPOSITORY_ROOT / "make/scripts"
if str(MAKE_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(MAKE_SCRIPTS_ROOT))
import k3s_transport as transport  # noqa: E402
import validate_tracing_contract as contract  # noqa: E402


GUEST_KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"


class TracingVerifyError(RuntimeError):
    """The WATCH tracing topology did not verify."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TracingVerifyError(message)


def kubectl(namespace: str) -> str:
    return (
        f"sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl -n "
        f"{shlex.quote(namespace)}"
    )


def get_resource(
    connection: transport.Connection,
    namespace: str,
    kind: str,
    name: str,
) -> dict[str, Any]:
    output = transport.ssh(
        connection=connection,
        command=f"{kubectl(namespace)} get {shlex.quote(kind)}/{shlex.quote(name)} -o json",
        label=f"WATCH tracing {kind}/{name} lookup",
    )
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise TracingVerifyError(f"{kind}/{name} lookup returned invalid JSON") from error
    require(isinstance(value, dict), f"{kind}/{name} lookup is invalid")
    return cast(dict[str, Any], value)


def verify_ready_workload(
    resource: dict[str, Any], kind: str, expected_replicas: int, name: str
) -> None:
    metadata = resource.get("metadata", {})
    status = resource.get("status", {})
    require(
        isinstance(metadata, dict) and isinstance(status, dict),
        f"WATCH {kind}/{name} status is invalid",
    )
    generation = metadata.get("generation")
    observed = status.get("observedGeneration")
    require(
        type(generation) is int and type(observed) is int and generation == observed,
        f"WATCH {kind}/{name} controller has not observed its generation",
    )
    if kind == "StatefulSet":
        ready = status.get("readyReplicas", 0)
        current = status.get("currentReplicas", 0)
        updated = status.get("updatedReplicas", 0)
    else:
        ready = status.get("readyReplicas", 0)
        current = status.get("availableReplicas", 0)
        updated = status.get("updatedReplicas", 0)
    require(
        all(type(value) is int and value == expected_replicas for value in (ready, current, updated)),
        f"WATCH {kind}/{name} is not ready",
    )


def verify_service(
    resource: dict[str, Any], name: str, expected_ports: set[int], service_type: str
) -> None:
    spec_value = resource.get("spec")
    require(isinstance(spec_value, dict), f"WATCH Service/{name} spec is invalid")
    spec = cast(dict[str, Any], spec_value)
    require(spec.get("type") == service_type, f"WATCH Service/{name} type changed")
    require(
        not any(key in spec for key in ("externalIPs", "loadBalancerIP", "loadBalancerSourceRanges")),
        f"WATCH Service/{name} has an external route",
    )
    ports_value = spec.get("ports")
    require(isinstance(ports_value, list), f"WATCH Service/{name} ports are invalid")
    ports = cast(list[Any], ports_value)
    actual = {port.get("port") for port in ports if isinstance(port, dict)}
    require(expected_ports <= actual, f"WATCH Service/{name} is missing a declared port")


def readiness(
    connection: transport.Connection, namespace: str, service: str, port: int
) -> None:
    command = (
        "set -eu; umask 077; STAGE=$(mktemp -d); PFPID=; "
        'trap \'test -z "$PFPID" || kill "$PFPID" 2>/dev/null || true; '
        'rm -rf -- "$STAGE"\' EXIT INT HUP TERM; '
        "PORT=$(python3 -c 'import socket; s=socket.socket(); "
        's.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()\'); '
        f'{kubectl(namespace)} port-forward svc/{shlex.quote(service)} "$PORT:{port}" '
        '--address=127.0.0.1 >"$STAGE/port-forward.log" 2>&1 & PFPID=$!; '
        "READY=; for ATTEMPT in $(seq 1 10); do "
        f'if curl --fail --silent --show-error --connect-timeout 1 --max-time 2 "http://127.0.0.1:$PORT/ready" >"$STAGE/ready"; '
        "then READY=1; break; fi; sleep 1; done; "
        'test "${READY:-}" = 1 || { cat "$STAGE/port-forward.log" >&2; exit 1; }; '
        'test -s "$STAGE/ready"'
    )
    transport.ssh(
        connection=connection,
        command=command,
        label="WATCH Tempo readiness",
        timeout_seconds=45,
    )


def verify(inventory_paths: list[Path]) -> None:
    document = contract.validate_contract()
    tempo = document["tempo"]
    collector = document["collector"]
    connection = transport.resolve_connection(inventory_paths)
    verify_ready_workload(
        get_resource(connection, tempo["namespace"], "statefulset", tempo["statefulset"]),
        "StatefulSet",
        tempo["replicas"],
        tempo["statefulset"],
    )
    verify_ready_workload(
        get_resource(connection, collector["namespace"], "deployment", collector["deployment"]),
        "Deployment",
        collector["replicas"],
        collector["deployment"],
    )
    verify_service(
        get_resource(connection, tempo["namespace"], "service", tempo["service"]),
        tempo["service"],
        {tempo["query_port"], *tempo["otlp_ports"].values()},
        tempo["service_type"],
    )
    verify_service(
        get_resource(connection, collector["namespace"], "service", collector["service"]),
        collector["service"],
        {*collector["otlp_ports"].values(), collector["metrics_port"]},
        collector["service_type"],
    )
    readiness(connection, tempo["namespace"], tempo["service"], tempo["query_port"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inventory", type=Path, action="append", dest="inventory_paths", default=None
    )
    args = parser.parse_args()
    inventory_paths = args.inventory_paths or [
        REPOSITORY_ROOT / ".local/ansible/inventory.json",
        REPOSITORY_ROOT / ".local/ansible/connection-inventory.yml",
    ]
    try:
        verify(inventory_paths)
        print("verified WATCH tracing topology and Tempo readiness")
        return 0
    except (
        TracingVerifyError,
        contract.TracingContractError,
        transport.TransportError,
        OSError,
        ValueError,
    ) as error:
        print(f"WATCH tracing verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
