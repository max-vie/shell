#!/usr/bin/env python3
"""Deploy the pinned first WATCH metrics slice from MAKE."""

from __future__ import annotations

import argparse
import hashlib
import shlex
import sys
from pathlib import Path
from typing import Any

import k3s_transport as transport


SCRIPT_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_ROOT.parents[1]
WATCH_SCRIPTS_ROOT = REPOSITORY_ROOT / "watch/scripts"
TAR_SCRIPTS_ROOT = REPOSITORY_ROOT / "tar/scripts"
for script_root in (WATCH_SCRIPTS_ROOT, TAR_SCRIPTS_ROOT):
    if str(script_root) not in sys.path:
        sys.path.insert(0, str(script_root))
import validate_monitoring_contract as contract  # noqa: E402
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
    stage_dir: str,
    monitoring_contract: dict[str, Any],
    supply_lock: dict[str, Any],
) -> str:
    deployment = monitoring_contract["deployment"]
    command = [
        executable,
        *action,
        deployment["release"],
        f"{stage_dir}/chart.tgz",
        "--namespace",
        deployment["namespace"],
        "--values",
        f"{stage_dir}/values.yaml",
        *helm_image_arguments(supply_lock),
    ]
    return shlex.join(command)


def render_release(
    connection: transport.Connection,
    stage_dir: str,
    monitoring_contract: dict[str, Any],
    supply_lock: dict[str, Any],
) -> None:
    command = helm_command(
        GUEST_HELM,
        ["template"],
        stage_dir,
        monitoring_contract,
        supply_lock,
    )
    rendered = shlex.quote(f"{stage_dir}/rendered.yaml")
    validator = shlex.quote(f"{stage_dir}/validate-images.py")
    lock = shlex.quote(f"{stage_dir}/supply.json")
    remote(
        connection,
        f"set -eu; {command} > {rendered}; "
        f"python3 {validator} --lock {lock} --rendered {rendered}",
        label="MAKE monitoring rendered image validation",
        timeout_seconds=180,
    )


def install_release(
    connection: transport.Connection,
    stage_dir: str,
    monitoring_contract: dict[str, Any],
    supply_lock: dict[str, Any],
) -> None:
    command = helm_command(
        GUEST_HELM,
        ["upgrade", "--install"],
        stage_dir,
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


def wait_ready(
    connection: transport.Connection, monitoring_contract: dict[str, Any]
) -> None:
    namespace = monitoring_contract["deployment"]["namespace"]
    command = (
        f"set -eu; K='sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl "
        f"-n {namespace}'; "
        "for SELECTOR in app.kubernetes.io/name=prometheus "
        "app.kubernetes.io/name=alertmanager; do "
        "FOUND=; for ATTEMPT in $(seq 1 60); do "
        'FOUND=$($K get pod -l "$SELECTOR" -o name); '
        'test -n "$FOUND" && break; sleep 2; done; '
        'test -n "$FOUND"; '
        '$K wait --for=condition=Ready pod -l "$SELECTOR" --timeout=180s; '
        "done"
    )
    remote(
        connection,
        command,
        label="MAKE monitoring readiness",
        timeout_seconds=660,
    )


def verify_runtime_images(
    connection: transport.Connection,
    stage_dir: str,
    monitoring_contract: dict[str, Any],
) -> None:
    namespace = monitoring_contract["deployment"]["namespace"]
    pods = shlex.quote(f"{stage_dir}/running-pods.json")
    validator = shlex.quote(f"{stage_dir}/validate-images.py")
    lock = shlex.quote(f"{stage_dir}/supply.json")
    remote(
        connection,
        f"set -eu; sudo -E KUBECONFIG={GUEST_KUBECONFIG} k3s kubectl "
        f"-n {shlex.quote(namespace)} get pods -o json > {pods}; "
        f"python3 {validator} --lock {lock} --running-pods {pods}",
        label="MAKE monitoring running image validation",
        timeout_seconds=120,
    )


def deploy(
    inventory_paths: list[Path],
    *,
    approval: str | None = None,
    check_only: bool = False,
) -> None:
    monitoring_contract, supply_lock = validate_source()
    if check_only:
        return
    require(approval == MAKE_APPROVAL, "exact MAKE monitoring approval is required")
    chart = require_staged_chart(supply_lock)
    values = REPOSITORY_ROOT / monitoring_contract["deployment"]["values"]
    chart_sha256 = supply_lock["charts"]["kube-prometheus-stack"]["sha256"]
    connection = transport.resolve_connection(inventory_paths)
    preflight(connection)
    stage_dir: str | None = None
    try:
        stage_dir = create_guest_stage(connection)
        stage_artifacts(connection, chart, values, stage_dir, chart_sha256)
        render_release(connection, stage_dir, monitoring_contract, supply_lock)
        install_release(connection, stage_dir, monitoring_contract, supply_lock)
        wait_ready(connection, monitoring_contract)
        verify_runtime_images(connection, stage_dir, monitoring_contract)
    finally:
        if stage_dir is not None:
            cleanup_guest(connection, stage_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
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
        deploy(inventory_paths, approval=args.approval, check_only=args.check_only)
        message = (
            "validated MAKE monitoring source"
            if args.check_only
            else "deployed MAKE monitoring"
        )
        print(message)
        return 0
    except (
        MonitoringDeployError,
        transport.TransportError,
        OSError,
        ValueError,
    ) as error:
        print(f"MAKE monitoring deployment failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
