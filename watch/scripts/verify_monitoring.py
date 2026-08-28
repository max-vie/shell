#!/usr/bin/env python3
"""Read-only verification for the WATCH metrics and Grafana slices."""

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
API_PATH_RE = re.compile(r"^/[A-Za-z0-9_./?=&%:-]+$")


class WatchVerifyError(RuntimeError):
    """The WATCH metrics or Grafana path did not verify."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchVerifyError(message)


def kubectl(namespace: str) -> str:
    return (
        f"sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl -n {shlex.quote(namespace)}"
    )


def resolve_resource(
    connection: transport.Connection,
    namespace: str,
    kind: str,
    selector: str,
) -> dict[str, Any]:
    output = transport.ssh(
        connection=connection,
        command=(
            f"{kubectl(namespace)} get {shlex.quote(kind)} -l "
            f"{shlex.quote(selector)} -o json"
        ),
        label=f"WATCH {kind} lookup {selector}",
    )
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        raise WatchVerifyError(f"WATCH {kind} lookup returned invalid JSON") from error
    items_value = document.get("items") if isinstance(document, dict) else None
    require(isinstance(items_value, list), f"WATCH {kind} lookup has no items")
    items = cast(list[Any], items_value)
    require(len(items) == 1, f"WATCH selector must resolve one {kind}: {selector}")
    resource = items[0]
    require(isinstance(resource, dict), f"WATCH {kind} is invalid")
    return cast(dict[str, Any], resource)


def resolve_service(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
) -> str:
    service = resolve_resource(connection, namespace, "service", selector)
    metadata_value = service.get("metadata")
    spec_value = service.get("spec")
    require(isinstance(metadata_value, dict), "WATCH service metadata is invalid")
    require(isinstance(spec_value, dict), "WATCH service spec is invalid")
    metadata = cast(dict[str, Any], metadata_value)
    spec = cast(dict[str, Any], spec_value)
    name = metadata.get("name")
    require(
        isinstance(name, str) and SERVICE_NAME_RE.fullmatch(name) is not None,
        "WATCH service name is unsafe",
    )
    ports_value = spec.get("ports")
    require(isinstance(ports_value, list), "WATCH service ports are invalid")
    ports = cast(list[Any], ports_value)
    require(
        any(
            isinstance(port, dict) and port.get("port") == service_port
            for port in ports
        ),
        f"WATCH service does not expose port {service_port}",
    )
    return cast(str, name)


def query_service(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
    path: str,
) -> str:
    require(API_PATH_RE.fullmatch(path) is not None, "WATCH API path is unsafe")
    service = resolve_service(connection, namespace, selector, service_port)
    command = (
        "set -eu; umask 077; STAGE=$(mktemp -d); PFPID=; "
        'trap \'test -z "$PFPID" || kill "$PFPID" 2>/dev/null || true; '
        'rm -rf -- "$STAGE"\' EXIT INT HUP TERM; '
        "PORT=$(python3 -c 'import socket; s=socket.socket(); "
        's.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()\'); '
        f'{kubectl(namespace)} port-forward svc/{service} "$PORT:{service_port}" '
        '--address=127.0.0.1 >"$STAGE/port-forward.log" 2>&1 & PFPID=$!; '
        "READY=; for ATTEMPT in $(seq 1 10); do "
        f"if curl --fail --silent --show-error --connect-timeout 1 --max-time 2 "
        f'"http://127.0.0.1:$PORT{path}" >"$STAGE/response.json"; '
        "then READY=1; break; fi; sleep 1; done; "
        'test "${READY:-}" = 1 || { cat "$STAGE/port-forward.log" >&2; exit 1; }; '
        'cat "$STAGE/response.json"'
    )
    return transport.ssh(
        connection=connection,
        command=command,
        label=f"WATCH query {selector}",
        timeout_seconds=45,
    )


def parse_json_response(source: str, label: str) -> Any:
    try:
        return json.loads(source)
    except json.JSONDecodeError as error:
        raise WatchVerifyError(f"{label} returned invalid JSON") from error


def verify_scrape_target(
    connection: transport.Connection, namespace: str, selector: str
) -> None:
    output = query_service(
        connection,
        namespace,
        selector,
        9090,
        "/api/v1/targets?state=active",
    )
    payload = parse_json_response(output, "Prometheus target query")
    require(isinstance(payload, dict), "Prometheus target response is invalid")
    data = payload.get("data")
    require(isinstance(data, dict), "Prometheus target data is invalid")
    targets = data.get("activeTargets")
    require(isinstance(targets, list), "Prometheus active targets are invalid")
    up = [
        item
        for item in targets
        if isinstance(item, dict)
        and "node-exporter" in str(item.get("scrapePool", ""))
        and item.get("health") == "up"
    ]
    require(bool(up), "node-exporter is not UP")


def verify_watchdog(
    connection: transport.Connection, namespace: str, selector: str
) -> None:
    output = query_service(
        connection,
        namespace,
        selector,
        9093,
        "/api/v2/alerts?active=true",
    )
    payload = parse_json_response(output, "Alertmanager alert query")
    require(isinstance(payload, list), "Alertmanager alert response is invalid")
    names = {
        labels.get("alertname")
        for item in payload
        if isinstance(item, dict)
        and isinstance((labels := item.get("labels")), dict)
    }
    require("Watchdog" in names, "Watchdog alert is not firing")


def verify_grafana_health(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
    health_path: str,
) -> None:
    output = query_service(
        connection,
        namespace,
        selector,
        service_port,
        health_path,
    )
    payload = parse_json_response(output, "Grafana health query")
    require(isinstance(payload, dict), "Grafana health response is invalid")
    require(payload.get("database") == "ok", "Grafana health is not ready")
    require(
        isinstance(payload.get("version"), str) and bool(payload["version"]),
        "Grafana version is missing",
    )


def verify_grafana_datasource(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
    uid: str,
    expected_type: str,
    expected_url: str,
) -> None:
    require(SERVICE_NAME_RE.fullmatch(uid) is not None, "Grafana datasource UID is unsafe")
    output = query_service(
        connection,
        namespace,
        selector,
        service_port,
        f"/api/datasources/uid/{uid}",
    )
    datasource = parse_json_response(output, f"Grafana datasource {uid}")
    require(isinstance(datasource, dict), "Grafana datasource response is invalid")
    require(datasource.get("uid") == uid, f"Grafana datasource UID changed: {uid}")
    require(
        datasource.get("type") == expected_type,
        f"Grafana datasource type changed: {uid}",
    )
    actual_url = datasource.get("url")
    require(
        isinstance(actual_url, str)
        and actual_url.rstrip("/") == expected_url.rstrip("/"),
        f"Grafana datasource URL changed: {uid}",
    )
    require(datasource.get("access") == "proxy", f"Grafana datasource is not proxied: {uid}")
    require(datasource.get("readOnly") is True, f"Grafana datasource is not provisioned: {uid}")


def verify_grafana_datasource_query(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
    uid: str,
    proof_path: str,
) -> None:
    output = query_service(
        connection,
        namespace,
        selector,
        service_port,
        f"/api/datasources/proxy/uid/{uid}{proof_path}",
    )
    payload = parse_json_response(output, f"Grafana datasource proof {uid}")
    require(isinstance(payload, dict), "Grafana datasource proof is invalid")
    require(payload.get("status") == "success", f"Grafana datasource query failed: {uid}")
    data = payload.get("data")
    require(isinstance(data, dict), f"Grafana datasource data is invalid: {uid}")
    if uid == "prometheus":
        result = data.get("result")
        require(isinstance(result, list) and bool(result), "Grafana Prometheus proof is empty")
        values: list[list[Any]] = []
        for item in result:
            if not isinstance(item, dict):
                continue
            value = item.get("value")
            if isinstance(value, list):
                values.append(value)
        require(
            any(len(value) >= 2 and str(value[-1]) == "1" for value in values),
            "Grafana Prometheus proof returned the wrong value",
        )


def verify_grafana_dashboard(
    connection: transport.Connection,
    namespace: str,
    selector: str,
    service_port: int,
    expected_uid: str,
    expected_title: str,
    expected_datasources: set[str],
) -> None:
    require(
        SERVICE_NAME_RE.fullmatch(expected_uid) is not None,
        "Grafana dashboard UID is unsafe",
    )
    output = query_service(
        connection,
        namespace,
        selector,
        service_port,
        "/apis/dashboard.grafana.app/v1/namespaces/default/dashboards/"
        f"{expected_uid}",
    )
    payload = parse_json_response(output, "Grafana dashboard query")
    require(isinstance(payload, dict), "Grafana dashboard response is invalid")
    metadata = payload.get("metadata")
    require(isinstance(metadata, dict), "Grafana dashboard metadata is invalid")
    require(
        metadata.get("name") == expected_uid,
        "Grafana dashboard API identity changed",
    )
    dashboard = payload.get("spec")
    require(isinstance(dashboard, dict), "Grafana dashboard is not provisioned")
    require(dashboard.get("uid") == expected_uid, "Grafana dashboard UID changed")
    require(
        dashboard.get("title") == expected_title,
        "Grafana dashboard title changed",
    )
    panels = dashboard.get("panels")
    if not isinstance(panels, list) or not panels:
        raise WatchVerifyError("Grafana dashboard has no panels")
    panel_datasources = {
        panel.get("datasource", {}).get("uid")
        for panel in panels
        if isinstance(panel, dict) and isinstance(panel.get("datasource"), dict)
    }
    require(
        expected_datasources <= panel_datasources,
        "Grafana dashboard datasource references changed",
    )


def verify(inventory_paths: list[Path]) -> None:
    document = contract.validate_contract()
    deployment = document["deployment"]
    selectors = deployment["service_selectors"]
    grafana = document["grafana"]
    connection = transport.resolve_connection(inventory_paths)
    verify_scrape_target(connection, deployment["namespace"], selectors["prometheus"])
    verify_watchdog(connection, deployment["namespace"], selectors["alertmanager"])
    verify_grafana_health(
        connection,
        deployment["namespace"],
        selectors["grafana"],
        grafana["service_port"],
        grafana["health_path"],
    )
    for uid, datasource in grafana["datasources"].items():
        verify_grafana_datasource(
            connection,
            deployment["namespace"],
            selectors["grafana"],
            grafana["service_port"],
            uid,
            datasource["type"],
            datasource["url"],
        )
        verify_grafana_datasource_query(
            connection,
            deployment["namespace"],
            selectors["grafana"],
            grafana["service_port"],
            uid,
            datasource["proof_path"],
        )
    verify_grafana_dashboard(
        connection,
        deployment["namespace"],
        selectors["grafana"],
        grafana["service_port"],
        grafana["dashboard_uid"],
        grafana["dashboard_title"],
        set(grafana["dashboard_datasources"]),
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
        print("verified WATCH metrics and Grafana live queries")
        return 0
    except (WatchVerifyError, transport.TransportError, OSError, ValueError) as error:
        print(f"WATCH metrics and Grafana verification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
