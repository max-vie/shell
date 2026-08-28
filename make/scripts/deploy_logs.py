#!/usr/bin/env python3
"""Deploy the pinned Loki and Alloy logs slice from MAKE."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

import k3s_transport as transport

SCRIPT_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_ROOT.parents[1]
WATCH_SCRIPTS_ROOT = REPOSITORY_ROOT / "watch/scripts"
TAR_SCRIPTS_ROOT = REPOSITORY_ROOT / "tar/scripts"
for script_root in (WATCH_SCRIPTS_ROOT, TAR_SCRIPTS_ROOT):
    if str(script_root) not in sys.path:
        sys.path.insert(0, str(script_root))
import validate_monitoring_contract as contract  # noqa: E402
import validate_monitoring_images as image_validator  # noqa: E402
import validate_watch_logs as supply  # noqa: E402

from deploy_monitoring import (  # noqa: E402
    cleanup_guest,
    create_guest_stage,
    preflight,
    remote,
)


MAKE_APPROVAL = "environment-gcp/make/logs"
IMAGE_VALIDATOR = SCRIPT_ROOT / "validate_monitoring_images.py"
SUPPLY_LOCK = REPOSITORY_ROOT / "tar/manifests/watch-logs-supply.json"
GUEST_HELM = "/usr/local/bin/helm"
GUEST_KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
IMAGE_PATHS = {
    "docker.io/grafana/loki:3.7.6": "loki.image",
    "docker.io/nginxinc/nginx-unprivileged:1.31-alpine": "gateway.image",
    "docker.io/grafana/alloy:v1.18.1": "image",
    "quay.io/prometheus-operator/prometheus-config-reloader:v0.91.0": "configReloader.image",
}
CHART_IMAGES = {
    "loki": {
        "docker.io/grafana/loki:3.7.6",
        "docker.io/nginxinc/nginx-unprivileged:1.31-alpine",
    },
    "alloy": {
        "docker.io/grafana/alloy:v1.18.1",
        "quay.io/prometheus-operator/prometheus-config-reloader:v0.91.0",
    },
}


class LogsDeployError(RuntimeError):
    """MAKE cannot safely deploy the WATCH logs policy."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LogsDeployError(message)


def validate_source() -> tuple[dict[str, Any], dict[str, Any]]:
    monitoring_contract = contract.validate_contract()
    logs_supply = supply.validate_public()
    require(
        IMAGE_VALIDATOR.is_file() and not IMAGE_VALIDATOR.is_symlink(),
        "MAKE image validator is missing",
    )
    return monitoring_contract, logs_supply


def split_image(image: str) -> tuple[str, str, str]:
    registry, separator, remainder = image.partition("/")
    repository, tag_separator, tag = remainder.rpartition(":")
    require(bool(separator and tag_separator), f"invalid locked logs image: {image}")
    return registry, repository, tag


def helm_image_arguments(
    logs_supply: dict[str, Any], image_names: set[str] | None = None
) -> list[str]:
    digests = logs_supply["runtime_image_digests"]
    require(set(digests) == set(IMAGE_PATHS), "TAR logs image set cannot be applied")
    selected = set(IMAGE_PATHS) if image_names is None else image_names
    if not selected or not selected <= set(IMAGE_PATHS):
        raise LogsDeployError("TAR chart image set is invalid")
    arguments: list[str] = []
    for image, prefix in IMAGE_PATHS.items():
        if image not in selected:
            continue
        registry, repository, tag = split_image(image)
        arguments.extend(
            [
                "--set-string",
                f"{prefix}.registry={registry}",
                "--set-string",
                f"{prefix}.repository={repository}",
                "--set-string",
                f"{prefix}.tag={tag}",
                "--set-string",
                f"{prefix}.digest={digests[image]}",
            ]
        )
    return arguments


def staged_chart_path(logs_supply: dict[str, Any], chart_name: str) -> Path:
    charts = cast(dict[str, dict[str, Any]], logs_supply["charts"])
    staging = cast(dict[str, Any], logs_supply["staging"])
    chart = charts[chart_name]
    artifact_directory = cast(str, staging["artifact_directory"])
    name = cast(str, chart["name"])
    version = cast(str, chart["version"])
    return (
        REPOSITORY_ROOT
        / ".local/tar"
        / artifact_directory
        / "charts"
        / f"{name}-{version}.tgz"
    )


def require_staged_chart(logs_supply: dict[str, Any], chart_name: str) -> Path:
    chart = logs_supply["charts"][chart_name]
    path = transport.require_regular_file(
        staged_chart_path(logs_supply, chart_name),
        f"staged WATCH {chart_name} chart",
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    require(digest == chart["sha256"], f"staged WATCH {chart_name} checksum changed")
    return path


def template_local(
    logs_contract: dict[str, Any],
    logs_supply: dict[str, Any],
) -> None:
    releases = logs_contract["logs"]["releases"]
    values = logs_contract["logs"]["values"]
    namespace = logs_contract["logs"]["namespace"]
    with tempfile.TemporaryDirectory(prefix="shell-watch-logs-render-") as temporary:
        temporary_root = Path(temporary)
        for chart_name in ("loki", "alloy"):
            chart = require_staged_chart(logs_supply, chart_name)
            command = [
                "helm",
                "template",
                releases[chart_name],
                str(chart),
                "--namespace",
                namespace,
                "--values",
                str(REPOSITORY_ROOT / values[chart_name]),
                *helm_image_arguments(logs_supply, CHART_IMAGES[chart_name]),
            ]
            rendered = transport.run(
                command,
                label=f"local {chart_name} chart render",
                timeout_seconds=180,
            )
            rendered_path = temporary_root / f"{chart_name}.yaml"
            rendered_path.write_text(rendered, encoding="utf-8")
            image_validator.validate_rendered(
                rendered_path,
                SUPPLY_LOCK,
                CHART_IMAGES[chart_name],
            )


def stage_artifacts(
    connection: transport.Connection,
    stage_dir: str,
    logs_contract: dict[str, Any],
    logs_supply: dict[str, Any],
) -> None:
    charts = logs_supply["charts"]
    values = logs_contract["logs"]["values"]
    artifacts = [
        (
            staged_chart_path(logs_supply, "loki"),
            "loki.tgz",
        ),
        (
            staged_chart_path(logs_supply, "alloy"),
            "alloy.tgz",
        ),
        (REPOSITORY_ROOT / values["loki"], "loki-values.yaml"),
        (REPOSITORY_ROOT / values["alloy"], "alloy-values.yaml"),
        (REPOSITORY_ROOT / "tar/manifests/watch-logs-supply.json", "supply.json"),
        (IMAGE_VALIDATOR, "validate-images.py"),
    ]
    for local, name in artifacts:
        transport.scp(local, f"{stage_dir}/{name}", connection)
    remote(
        connection,
        f"set -eu; chmod 0600 {shlex.quote(stage_dir)}/*; "
        f"sha256sum {shlex.quote(stage_dir + '/loki.tgz')} | grep -q "
        f"'^{charts['loki']['sha256']}  {stage_dir}/loki.tgz$'; "
        f"sha256sum {shlex.quote(stage_dir + '/alloy.tgz')} | grep -q "
        f"'^{charts['alloy']['sha256']}  {stage_dir}/alloy.tgz$'",
        label="MAKE logs staged artifact verification",
    )


def helm_command(
    action: list[str],
    release: str,
    chart_name: str,
    values_name: str,
    stage_dir: str,
    logs_supply: dict[str, Any],
) -> str:
    chart_path = f"{stage_dir}/{chart_name}.tgz"
    return shlex.join(
        [
            GUEST_HELM,
            *action,
            release,
            chart_path,
            "--namespace",
            "monitoring",
            "--values",
            f"{stage_dir}/{values_name}",
            *helm_image_arguments(logs_supply, CHART_IMAGES[chart_name]),
        ]
    )


def render_release(
    connection: transport.Connection,
    stage_dir: str,
    release: str,
    chart_name: str,
    values_name: str,
    logs_supply: dict[str, Any],
) -> None:
    command = helm_command(
        ["template"], release, chart_name, values_name, stage_dir, logs_supply
    )
    rendered = shlex.quote(f"{stage_dir}/{release}-rendered.yaml")
    validator = shlex.quote(f"{stage_dir}/validate-images.py")
    lock = shlex.quote(f"{stage_dir}/supply.json")
    remote(
        connection,
        f"set -eu; {command} > {rendered}; "
        f"python3 {validator} --lock {lock} --rendered {rendered} "
        + " ".join(
            f"--include-image {shlex.quote(image)}"
            for image in sorted(CHART_IMAGES[chart_name])
        ),
        label=f"MAKE logs rendered image validation {release}",
        timeout_seconds=180,
    )


def install_release(
    connection: transport.Connection,
    stage_dir: str,
    release: str,
    chart_name: str,
    values_name: str,
    logs_supply: dict[str, Any],
) -> None:
    command = helm_command(
        ["upgrade", "--install"],
        release,
        chart_name,
        values_name,
        stage_dir,
        logs_supply,
    )
    remote(
        connection,
        f"set -eu; sudo -E KUBECONFIG={GUEST_KUBECONFIG} {command} "
        "--create-namespace --wait --wait-for-jobs --atomic --timeout 10m "
        "--history-max 3",
        label=f"MAKE logs Helm deployment {release}",
        timeout_seconds=660,
    )


def release_revision(
    connection: transport.Connection,
    namespace: str,
    release: str,
) -> int | None:
    output = remote(
        connection,
        f"sudo -E KUBECONFIG={GUEST_KUBECONFIG} {GUEST_HELM} list "
        f"--namespace {shlex.quote(namespace)} --all "
        f"--filter {shlex.quote(f'^{release}$')} --output json",
        label=f"MAKE logs release snapshot {release}",
    )
    try:
        records = json.loads(output)
    except json.JSONDecodeError as error:
        raise LogsDeployError(f"Helm release snapshot is invalid: {release}") from error
    require(isinstance(records, list), f"Helm release snapshot is invalid: {release}")
    if not records:
        return None
    require(len(records) == 1, f"Helm release snapshot is ambiguous: {release}")
    record = records[0]
    require(isinstance(record, dict), f"Helm release snapshot is invalid: {release}")
    require(record.get("name") == release, f"Helm release snapshot changed: {release}")
    require(
        record.get("status") == "deployed", f"Helm release is not deployed: {release}"
    )
    revision = record.get("revision")
    require(
        (type(revision) is int and revision > 0)
        or (isinstance(revision, str) and revision.isdigit() and int(revision) > 0),
        f"Helm release revision is invalid: {release}",
    )
    return int(cast(int | str, revision))


def restore_release(
    connection: transport.Connection,
    namespace: str,
    release: str,
    revision: int | None,
) -> None:
    if revision is None:
        action = f"uninstall {shlex.quote(release)}"
    else:
        action = f"rollback {shlex.quote(release)} {revision}"
    remote(
        connection,
        f"set -eu; sudo -E KUBECONFIG={GUEST_KUBECONFIG} {GUEST_HELM} "
        f"{action} --namespace {shlex.quote(namespace)} --wait --timeout 10m",
        label=f"MAKE logs restore {release}",
        timeout_seconds=660,
    )


def cleanup_preserving_error(
    connection: transport.Connection,
    stage_dir: str,
) -> None:
    active_error = sys.exception()
    try:
        cleanup_guest(connection, stage_dir)
    except Exception as cleanup_error:
        if active_error is None:
            raise
        active_error.add_note(
            f"temporary artifact cleanup also failed: {cleanup_error}"
        )


def wait_ready(connection: transport.Connection, logs_contract: dict[str, Any]) -> None:
    namespace = logs_contract["logs"]["namespace"]
    releases = logs_contract["logs"]["releases"]
    command = (
        f"set -eu; K='sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl "
        f"-n {shlex.quote(namespace)}'; "
        f"for RELEASE in {shlex.quote(releases['loki'])} "
        f"{shlex.quote(releases['alloy'])}; do "
        "FOUND=; for ATTEMPT in $(seq 1 60); do "
        'FOUND=$($K get pod -l "app.kubernetes.io/instance=$RELEASE" -o name); '
        'test -n "$FOUND" && break; sleep 2; done; '
        'test -n "$FOUND"; '
        "$K wait --for=condition=Ready pod -l "
        '"app.kubernetes.io/instance=$RELEASE" --timeout=180s; done'
    )
    remote(connection, command, label="MAKE logs readiness", timeout_seconds=660)


def verify_runtime_images(
    connection: transport.Connection, stage_dir: str, logs_contract: dict[str, Any]
) -> None:
    namespace = shlex.quote(logs_contract["logs"]["namespace"])
    pods = shlex.quote(f"{stage_dir}/running-pods.json")
    validator = shlex.quote(f"{stage_dir}/validate-images.py")
    lock = shlex.quote(f"{stage_dir}/supply.json")
    releases = logs_contract["logs"]["releases"]
    selector = shlex.quote(
        f"app.kubernetes.io/instance in ({releases['loki']},{releases['alloy']})"
    )
    remote(
        connection,
        f"set -eu; sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl "
        f"-n {namespace} get pods -l {selector} -o json > {pods}; "
        f"python3 {validator} --lock {lock} --running-pods {pods}",
        label="MAKE logs running image validation",
        timeout_seconds=120,
    )


def deploy(
    inventory_paths: list[Path],
    *,
    approval: str | None = None,
    check_only: bool = False,
    template_only: bool = False,
) -> None:
    logs_contract, logs_supply = validate_source()
    if check_only:
        return
    if template_only:
        template_local(logs_contract, logs_supply)
        return
    require(approval == MAKE_APPROVAL, "exact MAKE logs approval is required")
    for chart_name in logs_supply["charts"]:
        require_staged_chart(logs_supply, chart_name)
    connection = transport.resolve_connection(inventory_paths)
    preflight(connection)
    stage_dir: str | None = None
    releases = logs_contract["logs"]["releases"]
    namespace = logs_contract["logs"]["namespace"]
    snapshots = {
        release: release_revision(connection, namespace, release)
        for release in (releases["loki"], releases["alloy"])
    }
    changed_releases: list[str] = []
    try:
        stage_dir = create_guest_stage(connection)
        stage_artifacts(connection, stage_dir, logs_contract, logs_supply)
        render_release(
            connection,
            stage_dir,
            logs_contract["logs"]["releases"]["loki"],
            "loki",
            "loki-values.yaml",
            logs_supply,
        )
        render_release(
            connection,
            stage_dir,
            logs_contract["logs"]["releases"]["alloy"],
            "alloy",
            "alloy-values.yaml",
            logs_supply,
        )
        install_release(
            connection,
            stage_dir,
            logs_contract["logs"]["releases"]["loki"],
            "loki",
            "loki-values.yaml",
            logs_supply,
        )
        changed_releases.append(releases["loki"])
        install_release(
            connection,
            stage_dir,
            logs_contract["logs"]["releases"]["alloy"],
            "alloy",
            "alloy-values.yaml",
            logs_supply,
        )
        changed_releases.append(releases["alloy"])
        wait_ready(connection, logs_contract)
        verify_runtime_images(connection, stage_dir, logs_contract)
    except Exception as error:
        for release in reversed(changed_releases):
            try:
                restore_release(
                    connection,
                    namespace,
                    release,
                    snapshots[release],
                )
            except Exception as restore_error:
                error.add_note(f"failed to restore {release}: {restore_error}")
        raise
    finally:
        if stage_dir is not None:
            cleanup_preserving_error(connection, stage_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-only", action="store_true")
    modes.add_argument("--template-only", action="store_true")
    parser.add_argument("--approval")
    parser.add_argument(
        "--inventory", type=Path, action="append", dest="inventory_paths", default=None
    )
    args = parser.parse_args()
    inventory_paths = args.inventory_paths or [
        REPOSITORY_ROOT / ".local/ansible/inventory.json",
        REPOSITORY_ROOT / ".local/ansible/connection-inventory.yml",
    ]
    try:
        deploy(
            inventory_paths,
            approval=args.approval,
            check_only=args.check_only,
            template_only=args.template_only,
        )
        if args.check_only:
            print("validated MAKE logs source")
        elif args.template_only:
            print("rendered MAKE logs charts")
        else:
            print("deployed MAKE logs")
        return 0
    except (LogsDeployError, transport.TransportError, OSError, ValueError) as error:
        print(f"MAKE logs deployment failed: {error}", file=sys.stderr)
        for note in getattr(error, "__notes__", ()):
            print(f"MAKE logs deployment detail: {note}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
