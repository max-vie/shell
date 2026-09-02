#!/usr/bin/env python3
"""Read-only release-feed verification through the fixed GCP K3s server."""

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
import validate_release_feed as contract  # noqa: E402


class ReleaseFeedVerifyError(RuntimeError):
    """WATCH release-feed verification failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseFeedVerifyError(message)


def resource(connection: transport.Connection, kind: str, name: str) -> dict[str, Any]:
    output = transport.ssh(
        f"set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
        f"get {shlex.quote(kind)}/{shlex.quote(name)} --namespace release-feed --output json",
        connection,
        label=f"WATCH release-feed {kind} lookup",
        timeout_seconds=60,
    )
    try:
        value = json.loads(output)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseFeedVerifyError(f"{kind} response is invalid JSON") from error
    require(isinstance(value, dict), f"{kind} response is not an object")
    return cast(dict[str, Any], value)


def verify(connection: transport.Connection) -> dict[str, Any]:
    expected = contract.validate()
    service = resource(connection, "service", expected["service"]["name"])
    service_spec = service.get("spec")
    require(isinstance(service_spec, dict), "release-feed service spec is missing")
    service_spec = cast(dict[str, Any], service_spec)
    require(
        service_spec.get("type") == expected["service"]["type"]
        and service_spec.get("externalTrafficPolicy") == "Cluster",
        "release-feed service type does not match the declared NodePort boundary",
    )
    ports_value = service_spec.get("ports")
    require(isinstance(ports_value, list), "release-feed service ports are missing")
    ports = cast(list[Any], ports_value)
    https_ports = [
        item
        for item in ports
        if isinstance(item, dict) and item.get("name") == "https"
    ]
    require(
        len(https_ports) == 1
        and https_ports[0].get("nodePort") == expected["service"]["node_port"],
        "release-feed NodePort does not match the declared routing",
    )
    statefulset = resource(connection, "statefulset", expected["workload"]["name"])
    statefulset_spec = statefulset.get("spec")
    statefulset_status = statefulset.get("status")
    require(
        isinstance(statefulset_spec, dict), "release-feed StatefulSet spec is missing"
    )
    require(
        isinstance(statefulset_status, dict),
        "release-feed StatefulSet status is missing",
    )
    statefulset_spec = cast(dict[str, Any], statefulset_spec)
    statefulset_status = cast(dict[str, Any], statefulset_status)
    require(statefulset_spec.get("replicas") == 1, "release-feed replica count changed")
    require(
        statefulset_status.get("readyReplicas") == 1,
        "release-feed has no ready replica",
    )
    require(
        statefulset_status.get("currentReplicas") == 1
        and statefulset_status.get("updatedReplicas") == 1
        and statefulset_status.get("currentRevision")
        == statefulset_status.get("updateRevision"),
        "release-feed StatefulSet is not converged",
    )
    require(
        statefulset_spec.get("persistentVolumeClaimRetentionPolicy")
        == {"whenDeleted": "Retain", "whenScaled": "Retain"},
        "release-feed retention policy changed",
    )
    pvc = resource(connection, "pvc", "data-release-feed-0")
    pvc_spec = pvc.get("spec")
    pvc_status = pvc.get("status")
    require(
        isinstance(pvc_spec, dict) and isinstance(pvc_status, dict),
        "release-feed PVC is incomplete",
    )
    pvc_spec = cast(dict[str, Any], pvc_spec)
    pvc_status = cast(dict[str, Any], pvc_status)
    require(
        pvc_spec.get("storageClassName") == "longhorn",
        "release-feed PVC storage class changed",
    )
    require(pvc_status.get("phase") == "Bound", "release-feed PVC is not bound")
    require(
        isinstance(pvc_spec.get("resources"), dict)
        and pvc_spec["resources"].get("requests") == {"storage": "1Gi"},
        "release-feed PVC capacity changed",
    )
    server_name = expected["service"]["tls_server_name"]
    address = expected["service"]["address"]
    output = transport.ssh(
        "set -eu; umask 077; HEALTH=$(mktemp); "
        "trap 'rm -f -- \"$HEALTH\"' EXIT; "
        "curl --fail --silent --show-error --connect-timeout 2 --max-time 5 "
        "--cacert /usr/local/share/ca-certificates/shell-platform-ca.crt "
        f"--resolve {shlex.quote(server_name)}:443:{shlex.quote(address)} "
        f"https://{shlex.quote(server_name)}/healthz >\"$HEALTH\"; "
        "python3 -c 'import json,sys; d=json.load(sys.stdin); "
        "assert d.get(\"status\") == \"ok\" and d.get(\"service\") == \"release-feed\"' <\"$HEALTH\"; "
        "curl --fail --silent --show-error --connect-timeout 2 --max-time 5 "
        "--cacert /usr/local/share/ca-certificates/shell-platform-ca.crt "
        f"--resolve {shlex.quote(server_name)}:443:{shlex.quote(address)} "
        f"https://{shlex.quote(server_name)}/metrics | "
        "grep -q '^release_feed_capacity_remaining '; printf verified",
        connection,
        label="WATCH release-feed health and metrics",
        timeout_seconds=45,
    )
    return {
        "contract_id": expected["contract_id"],
        "service_address": expected["service"]["address"],
        "service_node_port": https_ports[0].get("nodePort"),
        "ready_replicas": statefulset_status.get("readyReplicas"),
        "pvc_phase": pvc_status.get("phase"),
        "health_metrics_probe": "passed",
        "command_output": output.strip(),
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
        ReleaseFeedVerifyError,
        transport.TransportError,
        ValueError,
    ) as error:
        print(f"WATCH release-feed verification failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
