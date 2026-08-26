#!/usr/bin/env python3
"""Read-only verification for the first WATCH metrics slice."""

from __future__ import annotations

import argparse
import json
import re
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
import validate_monitoring_contract as contract  # noqa: E402


GUEST_KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
SERVICE_NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")


class WatchVerifyError(RuntimeError):
    """The WATCH metrics path did not verify."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchVerifyError(message)


def kubectl(namespace: str) -> str:
    return (
        f"sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl -n {shlex.quote(namespace)}"
    )


def resolve_service(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
) -> str:
    output = transport.ssh(
        connection=connection,
        command=(
            f"{kubectl(namespace)} get service -l {shlex.quote(selector)} -o json"
        ),
        label=f"WATCH service lookup {selector}",
    )
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        raise WatchVerifyError("WATCH service lookup returned invalid JSON") from error
    items_value = document.get("items") if isinstance(document, dict) else None
    require(isinstance(items_value, list), "WATCH service lookup has no items")
    items = cast(list[Any], items_value)
    require(len(items) == 1, f"WATCH selector must resolve one service: {selector}")
    service = items[0]
    require(isinstance(service, dict), "WATCH service is invalid")
    metadata = service.get("metadata")
    spec = service.get("spec")
    require(isinstance(metadata, dict), "WATCH service metadata is invalid")
    require(isinstance(spec, dict), "WATCH service spec is invalid")
    name = metadata.get("name")
    require(
        isinstance(name, str) and SERVICE_NAME_RE.fullmatch(name) is not None,
        "WATCH service name is unsafe",
    )
    ports = spec.get("ports")
    require(isinstance(ports, list), "WATCH service ports are invalid")
    require(
        any(
            isinstance(port, dict) and port.get("port") == service_port
            for port in ports
        ),
        f"WATCH service does not expose port {service_port}",
    )
    return name


def query_service(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
    path: str,
    filter_code: str,
) -> str:
    service = resolve_service(connection, namespace, selector, service_port)
    command = (
        "set -eu; umask 077; STAGE=$(mktemp -d); PFPID=; "
        'trap \'test -z "$PFPID" || kill "$PFPID" 2>/dev/null || true; '
        'rm -rf -- "$STAGE"\' EXIT INT HUP TERM; '
        "PORT=$(python3 -c 'import socket; s=socket.socket(); "
        's.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()\'); '
        f'{kubectl(namespace)} port-forward svc/{service} "$PORT:{service_port}" '
        '--address=127.0.0.1 >"$STAGE/port-forward.log" 2>&1 & PFPID=$!; '
        "READY=; for ATTEMPT in $(seq 1 20); do "
        f"if curl --fail --silent --show-error "
        f'"http://127.0.0.1:$PORT{path}" >"$STAGE/response.json"; '
        "then READY=1; break; fi; sleep 1; done; "
        'test "${READY:-}" = 1 || { cat "$STAGE/port-forward.log" >&2; exit 1; }; '
        f'python3 -c {shlex.quote(filter_code)} <"$STAGE/response.json"'
    )
    return transport.ssh(
        connection=connection,
        command=command,
        label=f"WATCH query {selector}",
        timeout_seconds=45,
    )


def verify_scrape_target(
    connection: transport.Connection, namespace: str, selector: str
) -> None:
    filter_code = (
        "import json,sys; "
        "data=json.load(sys.stdin)['data']['activeTargets']; "
        "up=[item for item in data if 'node-exporter' in item.get('scrapePool','') "
        "and item.get('health') == 'up']; "
        "print('NODE_EXPORTER_UP=' + str(len(up))); "
        "sys.exit(0 if up else 1)"
    )
    output = query_service(
        connection,
        namespace,
        selector,
        9090,
        "/api/v1/targets?state=active",
        filter_code,
    )
    require(
        "NODE_EXPORTER_UP=" in output and not output.strip().endswith("=0"),
        "node-exporter is not UP",
    )


def verify_watchdog(
    connection: transport.Connection, namespace: str, selector: str
) -> None:
    filter_code = (
        "import json,sys; "
        "data=json.load(sys.stdin); "
        "names=[item.get('labels',{}).get('alertname','') for item in data]; "
        "print('FIRING=' + ','.join(sorted(set(names)))); "
        "sys.exit(0 if 'Watchdog' in names else 1)"
    )
    output = query_service(
        connection,
        namespace,
        selector,
        9093,
        "/api/v2/alerts?active=true",
        filter_code,
    )
    require("Watchdog" in output, "Watchdog alert is not firing")


def verify(inventory_paths: list[Path]) -> None:
    document = contract.validate_contract()
    deployment = document["deployment"]
    selectors = deployment["service_selectors"]
    connection = transport.resolve_connection(inventory_paths)
    verify_scrape_target(connection, deployment["namespace"], selectors["prometheus"])
    verify_watchdog(connection, deployment["namespace"], selectors["alertmanager"])


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
        print("verified WATCH metrics source and live query shape")
        return 0
    except (WatchVerifyError, transport.TransportError, OSError, ValueError) as error:
        print(f"WATCH metrics verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
