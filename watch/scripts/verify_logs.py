#!/usr/bin/env python3
"""Read-only verification for the first WATCH logs slice."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any, cast

SCRIPT_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_ROOT.parents[1]
MAKE_SCRIPTS_ROOT = REPOSITORY_ROOT / "make/scripts"
if str(MAKE_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(MAKE_SCRIPTS_ROOT))
import k3s_transport as transport  # noqa: E402
import validate_monitoring_contract as contract  # noqa: E402
from verify_monitoring import query_service  # noqa: E402


FRESHNESS_SECONDS = 300


class WatchLogsVerifyError(RuntimeError):
    """The WATCH logs path did not verify."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchLogsVerifyError(message)


def verify_ingested_logs(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
) -> None:
    filter_code = (
        "import json,sys,time; "
        "data=json.load(sys.stdin); "
        "streams=data.get('data',{}).get('result',[]); "
        f"cutoff=time.time_ns()-{FRESHNESS_SECONDS}*1000000000; "
        "fresh=[value for stream in streams if isinstance(stream,dict) "
        "for value in stream.get('values',[]) if isinstance(value,list) "
        "and len(value) >= 2 and str(value[0]).isdigit() "
        "and int(value[0]) >= cutoff]; "
        "print('FRESH_LOG_ENTRIES=' + str(len(fresh))); "
        "sys.exit(0 if fresh else 1)"
    )
    stream_query = urllib.parse.quote(
        f'{{namespace="{namespace}",pod=~"shell-watch-alloy-.+"}}',
        safe="",
    )
    query = (
        f"/loki/api/v1/query_range?query={stream_query}"
        f"&since={FRESHNESS_SECONDS}s&direction=backward&limit=20"
    )
    output = query_service(
        connection,
        namespace,
        selector,
        service_port,
        query,
        filter_code,
    )
    require(
        "FRESH_LOG_ENTRIES=" in output and not output.strip().endswith("=0"),
        "Loki returned no fresh Alloy log entries",
    )


def verify_alloy_ready(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    expected_nodes: int,
) -> None:
    output = transport.ssh(
        connection=connection,
        command=(
            f"sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl -n "
            f"{namespace} get daemonset -l {selector} -o json"
        ),
        label="WATCH Alloy readiness",
    )
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        raise WatchLogsVerifyError(
            "Alloy readiness output is not valid JSON"
        ) from error
    items = document.get("items") if isinstance(document, dict) else None
    require(
        isinstance(items, list) and len(items) == 1,
        "Alloy selector must resolve one DaemonSet",
    )
    items = cast(list[Any], items)
    first = items[0]
    metadata = first.get("metadata", {}) if isinstance(first, dict) else {}
    status = first.get("status", {}) if isinstance(first, dict) else {}
    generation = metadata.get("generation") if isinstance(metadata, dict) else None
    observed = status.get("observedGeneration") if isinstance(status, dict) else None
    counters = (
        (
            status.get("desiredNumberScheduled"),
            status.get("currentNumberScheduled"),
            status.get("updatedNumberScheduled"),
            status.get("numberReady"),
            status.get("numberAvailable"),
        )
        if isinstance(status, dict)
        else ()
    )
    require(
        type(generation) is int
        and type(observed) is int
        and generation == observed
        and expected_nodes > 0
        and len(counters) == 5
        and all(type(value) is int for value in counters)
        and all(value == expected_nodes for value in counters),
        "Alloy DaemonSet is not ready",
    )


def verify(inventory_paths: list[Path]) -> None:
    document = contract.validate_contract()
    logs = document["logs"]
    connection = transport.resolve_connection(inventory_paths)
    verify_alloy_ready(
        connection,
        logs["namespace"],
        logs["alloy_daemonset_selector"],
        len(document["cluster"]["nodes"]),
    )
    verify_ingested_logs(
        connection,
        logs["namespace"],
        logs["loki_service_selector"],
        logs["loki_service_port"],
    )


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
        print("verified WATCH logs source and Loki query shape")
        return 0
    except (
        WatchLogsVerifyError,
        transport.TransportError,
        OSError,
        ValueError,
    ) as error:
        print(f"WATCH logs verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
