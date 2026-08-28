#!/usr/bin/env python3
"""Deploy the pinned WATCH metrics and Grafana slices from MAKE."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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
import validate_watch as supply  # noqa: E402


MAKE_APPROVAL = "environment-gcp/make/monitoring"
SUPPLY_LOCK = REPOSITORY_ROOT / "tar/manifests/watch-supply.json"
IMAGE_VALIDATOR = SCRIPT_ROOT / "validate_monitoring_images.py"
GUEST_HELM = "/usr/local/bin/helm"
GUEST_KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"


class MonitoringDeployError(RuntimeError):
    """MAKE cannot safely deploy the WATCH metrics policy."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MonitoringDeployError(message)


def validate_source() -> tuple[dict[str, Any], dict[str, Any]]:
    monitoring_contract = contract.validate_contract()
    supply_lock = supply.validate_public()
    values = REPOSITORY_ROOT / monitoring_contract["deployment"]["values"]
    require(
        values.is_file() and not values.is_symlink(),
        "MAKE monitoring values are missing",
    )
    require(
        IMAGE_VALIDATOR.is_file() and not IMAGE_VALIDATOR.is_symlink(),
        "MAKE monitoring image validator is missing",
    )
    return monitoring_contract, supply_lock


def require_staged_chart(supply_lock: dict[str, Any]) -> Path:
    chart = supply_lock["charts"]["kube-prometheus-stack"]
    staging = supply_lock["staging"]
    path = (
        REPOSITORY_ROOT
        / ".local/tar"
        / staging["artifact_directory"]
        / "charts"
        / f"{chart['name']}-{chart['version']}.tgz"
    )
    staged = transport.require_regular_file(path, "staged monitoring chart")
    digest = hashlib.sha256(staged.read_bytes()).hexdigest()
    require(digest == chart["sha256"], "staged monitoring chart checksum changed")
    return staged


def split_image(image: str) -> tuple[str, str, str]:
    registry, separator, remainder = image.partition("/")
    repository, tag_separator, tag = remainder.rpartition(":")
    require(bool(separator and tag_separator), f"invalid locked image: {image}")
    return registry, repository, tag


def helm_image_arguments(supply_lock: dict[str, Any]) -> list[str]:
    digests = supply_lock["runtime_image_digests"]
    paths = {
        "quay.io/prometheus/prometheus:v3.14.0-distroless": (
            "prometheus.prometheusSpec.image",
            "hex",
        ),
        "quay.io/prometheus/alertmanager:v0.34.0": (
            "alertmanager.alertmanagerSpec.image",
            "hex",
        ),
        "quay.io/prometheus-operator/prometheus-operator:v0.93.1": (
            "prometheusOperator.image",
            "hex",
        ),
        "quay.io/prometheus-operator/prometheus-config-reloader:v0.93.1": (
            "prometheusOperator.prometheusConfigReloader.image",
            "hex",
        ),
        "quay.io/prometheus/node-exporter:v1.12.1-distroless": (
            "prometheus-node-exporter.image",
            "node-exporter",
        ),
        "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.20.0": (
            "kube-state-metrics.image",
            "full",
        ),
        "docker.io/grafana/grafana:13.2.0": ("grafana.image", "hex"),
        "ghcr.io/jkroepke/kube-webhook-certgen:1.8.5": (
            "prometheusOperator.admissionWebhooks.patch.image",
            "hex",
        ),
    }
    require(set(digests) == set(paths), "TAR monitoring image set cannot be applied")
    arguments: list[str] = []
    for image, (prefix, digest_style) in paths.items():
        registry, repository, tag = split_image(image)
        if digest_style == "node-exporter":
            require(tag.endswith("-distroless"), "node-exporter pin is not distroless")
            tag = tag.removesuffix("-distroless")
            arguments.extend(["--set", f"{prefix}.distroless=true"])
        digest = digests[image]
        if digest_style == "hex":
            digest = digest.removeprefix("sha256:")
        digest_field = "digest" if digest_style == "node-exporter" else "sha"
        arguments.extend(
            [
                "--set-string",
                f"{prefix}.registry={registry}",
                "--set-string",
                f"{prefix}.repository={repository}",
                "--set-string",
                f"{prefix}.tag={tag}",
                "--set-string",
                f"{prefix}.{digest_field}={digest}",
            ]
        )
    return arguments


def remote(
    connection: transport.Connection,
    command: str,
    *,
    label: str,
    timeout_seconds: int = 60,
) -> str:
    return transport.ssh(
        command,
        connection,
        label=label,
        timeout_seconds=timeout_seconds,
    )


def preflight(connection: transport.Connection) -> None:
    remote(
        connection,
        f"set -eu; test -x {GUEST_HELM}; "
        f"sudo -E KUBECONFIG={GUEST_KUBECONFIG} "
        "k3s kubectl get --raw=/readyz | grep -qx ok",
        label="MAKE monitoring K3s and Helm preflight",
    )


def create_guest_stage(connection: transport.Connection) -> str:
    output = remote(
        connection,
        "set -eu; umask 077; mktemp -d",
        label="MAKE monitoring temporary staging directory",
    ).strip()
    parts = output.split("/")
    require(
        (len(parts) == 3 and parts[1] == "tmp" and parts[2].startswith("tmp."))
        or (
            len(parts) == 4
            and parts[1] == "var"
            and parts[2] == "tmp"
            and parts[3].startswith("tmp.")
        ),
        "MAKE monitoring staging directory is unsafe",
    )
    return output


def cleanup_guest(connection: transport.Connection, stage_dir: str) -> None:
    remote(
        connection,
        f"rm -rf -- {shlex.quote(stage_dir)}",
        label="MAKE monitoring temporary artifact cleanup",
    )


def stage_artifacts(
    connection: transport.Connection,
    chart: Path,
    values: Path,
    stage_dir: str,
    chart_sha256: str,
) -> None:
    artifacts = {
        chart: "chart.tgz",
        values: "values.yaml",
        SUPPLY_LOCK: "supply.json",
        IMAGE_VALIDATOR: "validate-images.py",
    }
    for local, name in artifacts.items():
        transport.scp(local, f"{stage_dir}/{name}", connection)
    guest_chart = shlex.quote(f"{stage_dir}/chart.tgz")
    remote(
        connection,
        f"set -eu; chmod 0600 {shlex.quote(stage_dir)}/*; "
        f"sha256sum {guest_chart} | grep -q '^{chart_sha256}  {guest_chart}$'",
        label="MAKE monitoring staged artifact verification",
    )


def helm_command(
    executable: str,
    action: list[str],
    chart_path: str,
    values_path: str,
    monitoring_contract: dict[str, Any],
    supply_lock: dict[str, Any],
) -> str:
    deployment = monitoring_contract["deployment"]
    command = [
        executable,
        *action,
        deployment["release"],
        chart_path,
        "--namespace",
        deployment["namespace"],
        "--values",
        values_path,
        *helm_image_arguments(supply_lock),
    ]
    return shlex.join(command)


def rendered_resource(source: str, kind: str, name: str) -> str:
    matches = [
        document
        for document in re.split(r"(?m)^---\s*$", source)
        if re.search(rf"(?m)^kind: {re.escape(kind)}\s*$", document)
        and re.search(rf"(?m)^  name: {re.escape(name)}\s*$", document)
    ]
    require(
        len(matches) == 1,
        f"rendered monitoring resource must resolve once: {kind}/{name}",
    )
    return matches[0]


def validate_rendered_resources(
    source: str, monitoring_contract: dict[str, Any]
) -> None:
    release = monitoring_contract["deployment"]["release"]
    grafana_name = f"{release}-grafana"
    grafana = rendered_resource(source, "Deployment", grafana_name)
    for fragment in (
        "release: shell-watch",
        "automountServiceAccountToken: false",
        "runAsNonRoot: true",
        "allowPrivilegeEscalation: false",
        "type: RuntimeDefault",
        'mountPath: "/etc/grafana/provisioning/datasources/datasources.yaml"',
        'mountPath: "/var/lib/grafana/dashboards/default"',
        'name: "GF_SECURITY_DISABLE_INITIAL_ADMIN_CREATION"',
        'value: "true"',
    ):
        require(fragment in grafana, f"rendered Grafana deployment is missing: {fragment}")

    service = rendered_resource(source, "Service", grafana_name)
    require("type: ClusterIP" in service, "rendered Grafana service is not ClusterIP")
    require("port: 80" in service, "rendered Grafana service port changed")

    configuration = rendered_resource(source, "ConfigMap", grafana_name)
    for fragment in (
        "[auth.anonymous]",
        "org_role = Viewer",
        "[auth.basic]",
        "enabled = false",
        "uid: prometheus",
        "url: http://shell-watch-kube-prometheu-prometheus.monitoring:9090/",
        "uid: loki",
        "url: http://shell-watch-loki-gateway.monitoring.svc.cluster.local",
    ):
        require(fragment in configuration, f"rendered Grafana config is missing: {fragment}")

    dashboard = rendered_resource(
        source, "ConfigMap", "shell-watch-grafana-dashboards"
    )
    for fragment in (
        '"uid": "shell-watch-overview"',
        '"title": "SHELL Watch Overview"',
        '"uid": "prometheus"',
        '"uid": "loki"',
    ):
        require(fragment in dashboard, f"rendered Grafana dashboard is missing: {fragment}")

    policy = rendered_resource(
        source, "NetworkPolicy", "shell-watch-grafana-ingress"
    )
    for fragment in (
        "app.kubernetes.io/name: grafana",
        "app.kubernetes.io/instance: shell-watch",
        "policyTypes:",
        "- Ingress",
        "ingress: []",
    ):
        require(fragment in policy, f"rendered Grafana NetworkPolicy is missing: {fragment}")

    grafana_monitors = [
        document
        for document in re.split(r"(?m)^---\s*$", source)
        if re.search(r"(?m)^kind: ServiceMonitor\s*$", document)
        and re.search(rf"(?m)^  name: {re.escape(grafana_name)}\s*$", document)
    ]
    require(not grafana_monitors, "rendered Grafana ServiceMonitor must stay disabled")

    for kind, name in (
        ("Prometheus", "shell-watch-kube-prometheu-prometheus"),
        ("Alertmanager", "shell-watch-kube-prometheu-alertmanager"),
    ):
        workload = rendered_resource(source, kind, name)
        require(
            "podMetadata:" in workload and "release: shell-watch" in workload,
            f"rendered {kind} runtime label changed",
        )


def template_local(
    monitoring_contract: dict[str, Any], supply_lock: dict[str, Any]
) -> None:
    chart = require_staged_chart(supply_lock)
    values = REPOSITORY_ROOT / monitoring_contract["deployment"]["values"]
    command = shlex.split(
        helm_command(
            "helm",
            ["template"],
            str(chart),
            str(values),
            monitoring_contract,
            supply_lock,
        )
    )
    rendered = transport.run(
        command,
        label="local monitoring chart render",
        timeout_seconds=180,
    )
    with tempfile.TemporaryDirectory(prefix="shell-watch-monitoring-render-") as temp:
        rendered_path = Path(temp) / "monitoring.yaml"
        rendered_path.write_text(rendered, encoding="utf-8")
        image_validator.validate_rendered(rendered_path, SUPPLY_LOCK)
    validate_rendered_resources(rendered, monitoring_contract)


def render_release(
    connection: transport.Connection,
    stage_dir: str,
    monitoring_contract: dict[str, Any],
    supply_lock: dict[str, Any],
) -> None:
    command = helm_command(
        GUEST_HELM,
        ["template"],
        f"{stage_dir}/chart.tgz",
        f"{stage_dir}/values.yaml",
        monitoring_contract,
        supply_lock,
    )
    rendered = shlex.quote(f"{stage_dir}/rendered.yaml")
    validator = shlex.quote(f"{stage_dir}/validate-images.py")
    lock = shlex.quote(f"{stage_dir}/supply.json")
    source = remote(
        connection,
        f"set -eu; {command} > {rendered}; "
        f"python3 {validator} --lock {lock} --rendered {rendered}; "
        f"cat {rendered}",
        label="MAKE monitoring rendered image validation",
        timeout_seconds=180,
    )
    validate_rendered_resources(source, monitoring_contract)


def install_release(
    connection: transport.Connection,
    stage_dir: str,
    monitoring_contract: dict[str, Any],
    supply_lock: dict[str, Any],
) -> None:
    command = helm_command(
        GUEST_HELM,
        ["upgrade", "--install"],
        f"{stage_dir}/chart.tgz",
        f"{stage_dir}/values.yaml",
        monitoring_contract,
        supply_lock,
    )
    remote(
        connection,
        f"set -eu; sudo -E KUBECONFIG={GUEST_KUBECONFIG} {command} "
        "--create-namespace --wait --wait-for-jobs --atomic --timeout 10m "
        "--history-max 3",
        label="MAKE monitoring Helm deployment",
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
        label=f"MAKE monitoring release snapshot {release}",
    )
    try:
        records = json.loads(output)
    except json.JSONDecodeError as error:
        raise MonitoringDeployError("monitoring Helm release snapshot is invalid") from error
    require(isinstance(records, list), "monitoring Helm release snapshot is invalid")
    if not records:
        return None
    require(len(records) == 1, "monitoring Helm release snapshot is ambiguous")
    record = records[0]
    require(isinstance(record, dict), "monitoring Helm release snapshot is invalid")
    require(record.get("name") == release, "monitoring Helm release snapshot changed")
    require(
        record.get("status") == "deployed",
        "monitoring Helm release is not deployed",
    )
    revision = record.get("revision")
    require(
        (type(revision) is int and revision > 0)
        or (isinstance(revision, str) and revision.isdigit() and int(revision) > 0),
        "monitoring Helm release revision is invalid",
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
        label=f"MAKE monitoring restore {release}",
        timeout_seconds=660,
    )


def reconcile_install_failure(
    connection: transport.Connection,
    namespace: str,
    release: str,
    snapshot: int | None,
    install_error: Exception,
) -> None:
    try:
        observed = release_revision(connection, namespace, release)
    except Exception as reconciliation_error:
        install_error.add_note(
            f"failed to reconcile {release}: {reconciliation_error}"
        )
        return
    if observed == snapshot:
        return
    try:
        restore_release(connection, namespace, release, snapshot)
    except Exception as restore_error:
        install_error.add_note(f"failed to restore {release}: {restore_error}")


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


def wait_ready(
    connection: transport.Connection, monitoring_contract: dict[str, Any]
) -> None:
    namespace = monitoring_contract["deployment"]["namespace"]
    selector = monitoring_contract["deployment"]["runtime_pod_selector"]
    command = (
        f"set -eu; K='sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl "
        f"-n {shlex.quote(namespace)}'; "
        "FIELD_SELECTOR='status.phase!=Succeeded,status.phase!=Failed'; "
        "FOUND=; for ATTEMPT in $(seq 1 60); do "
        f"FOUND=$($K get pod -l {shlex.quote(selector)} "
        '--field-selector "$FIELD_SELECTOR" -o name); '
        'test -n "$FOUND" && break; sleep 2; done; '
        'test -n "$FOUND"; '
        f"$K wait --for=condition=Ready pod -l {shlex.quote(selector)} "
        '--field-selector "$FIELD_SELECTOR" '
        "--timeout=180s"
    )
    remote(
        connection,
        command,
        label="MAKE monitoring readiness",
        timeout_seconds=360,
    )


def verify_runtime_images(
    connection: transport.Connection,
    stage_dir: str,
    monitoring_contract: dict[str, Any],
) -> None:
    namespace = monitoring_contract["deployment"]["namespace"]
    selector = monitoring_contract["deployment"]["runtime_pod_selector"]
    pods = shlex.quote(f"{stage_dir}/running-pods.json")
    validator = shlex.quote(f"{stage_dir}/validate-images.py")
    lock = shlex.quote(f"{stage_dir}/supply.json")
    remote(
        connection,
        f"set -eu; sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl "
        f"-n {shlex.quote(namespace)} get pods -l {shlex.quote(selector)} "
        f"-o json > {pods}; "
        f"python3 {validator} --lock {lock} --running-pods {pods}",
        label="MAKE monitoring running image validation",
        timeout_seconds=120,
    )


def deploy(
    inventory_paths: list[Path],
    *,
    approval: str | None = None,
    check_only: bool = False,
    template_only: bool = False,
) -> None:
    monitoring_contract, supply_lock = validate_source()
    if check_only:
        return
    if template_only:
        template_local(monitoring_contract, supply_lock)
        return
    require(approval == MAKE_APPROVAL, "exact MAKE monitoring approval is required")
    chart = require_staged_chart(supply_lock)
    values = REPOSITORY_ROOT / monitoring_contract["deployment"]["values"]
    chart_sha256 = supply_lock["charts"]["kube-prometheus-stack"]["sha256"]
    connection = transport.resolve_connection(inventory_paths)
    preflight(connection)
    stage_dir: str | None = None
    namespace = monitoring_contract["deployment"]["namespace"]
    release = monitoring_contract["deployment"]["release"]
    snapshot = release_revision(connection, namespace, release)
    changed_release = False
    try:
        stage_dir = create_guest_stage(connection)
        stage_artifacts(connection, chart, values, stage_dir, chart_sha256)
        render_release(connection, stage_dir, monitoring_contract, supply_lock)
        try:
            install_release(connection, stage_dir, monitoring_contract, supply_lock)
        except Exception as install_error:
            reconcile_install_failure(
                connection,
                namespace,
                release,
                snapshot,
                install_error,
            )
            raise
        changed_release = True
        wait_ready(connection, monitoring_contract)
        verify_runtime_images(connection, stage_dir, monitoring_contract)
    except Exception as error:
        if changed_release:
            try:
                restore_release(connection, namespace, release, snapshot)
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
            print("validated MAKE monitoring source")
        elif args.template_only:
            print("rendered MAKE monitoring chart")
        else:
            print("deployed MAKE monitoring")
        return 0
    except (
        MonitoringDeployError,
        transport.TransportError,
        OSError,
        ValueError,
    ) as error:
        print(f"MAKE monitoring deployment failed: {error}", file=sys.stderr)
        for note in getattr(error, "__notes__", ()):
            print(f"MAKE monitoring deployment detail: {note}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
