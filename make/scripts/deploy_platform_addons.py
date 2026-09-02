#!/usr/bin/env python3
"""Deploy the pinned GCP platform add-ons from MAKE."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

import k3s_transport as transport


ROOT = Path(__file__).resolve().parents[2]
TAR_SCRIPTS = ROOT / "tar/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
import validate_platform_supply as platform_supply  # noqa: E402


SUPPLY = ROOT / "tar/manifests/platform-addons-supply.json"
LOCAL_ROOT = ROOT / ".local/tar/platform-addons"
GUEST_HELM = "/usr/local/bin/helm"
GUEST_KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
REMOTE_TMP = "/tmp"
APPROVAL = "environment-gcp/make/platform-addons"
RELEASES = {
    "metallb": {"namespace": "metallb-system"},
    "longhorn": {"namespace": "longhorn-system"},
}
METALLB_IMAGES = {
    "quay.io/metallb/controller:v0.15.2",
    "quay.io/metallb/speaker:v0.15.2",
}
LONGHORN_IMAGES = {
    "longhornio/longhorn-manager:v1.10.1",
    "longhornio/longhorn-ui:v1.10.1",
    "longhornio/longhorn-engine:v1.10.1",
    "longhornio/longhorn-instance-manager:v1.10.1",
    "longhornio/longhorn-share-manager:v1.10.1",
    "longhornio/backing-image-manager:v1.10.1",
    "longhornio/support-bundle-kit:v0.0.71",
    "longhornio/csi-attacher:v4.10.0-20251030",
    "longhornio/csi-provisioner:v5.3.0-20251030",
    "longhornio/csi-node-driver-registrar:v2.15.0-20251030",
    "longhornio/csi-resizer:v1.14.0-20251030",
    "longhornio/csi-snapshotter:v8.4.0-20251030",
    "longhornio/livenessprobe:v2.17.0-20251030",
}


class PlatformAddonsError(RuntimeError):
    """MAKE refused an unsafe platform add-on operation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlatformAddonsError(message)


def validate_source() -> dict[str, Any]:
    lock = platform_supply.validate_platform()
    service = lock["service_routing"]["services"]
    require(
        service["harbor"]["node_port"] == 30443
        and service["release_feed"]["node_port"] == 30444,
        "platform service NodePorts changed",
    )
    service_manifest = (
        ROOT / "make/apps/release-feed/k8s/base/service.yaml"
    ).read_text(encoding="utf-8")
    require(
        "type: NodePort" in service_manifest
        and "externalTrafficPolicy: Cluster" in service_manifest
        and "nodePort: 30444" in service_manifest,
        "release-feed NodePort consumer is incomplete",
    )
    harbor_values = json.loads(
        (ROOT / "tar/manifests/harbor-values.json").read_text(encoding="utf-8")
    )
    require(
        harbor_values["expose"]["type"] == "nodePort"
        and harbor_values["expose"]["nodePort"]["ports"]["https"]["nodePort"]
        == 30443,
        "Harbor NodePort consumer is incomplete",
    )
    return lock


def staged_chart(lock: dict[str, Any], name: str) -> Path:
    chart = cast(dict[str, Any], lock["charts"][name])
    path = LOCAL_ROOT / "charts" / f"{chart['name']}-{chart['version']}.tgz"
    try:
        path = transport.require_regular_file(path, f"staged {name} chart")
    except transport.TransportError as error:
        raise PlatformAddonsError(str(error)) from error
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, f"staged {name} chart mode changed")
    require(path.stat().st_size <= chart["max_bytes"], f"staged {name} chart is too large")
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == chart["sha256"],
        f"staged {name} chart checksum changed",
    )
    return path


def image_tag(lock: dict[str, Any], image: str) -> str:
    _, separator, version = image.rpartition(":")
    require(bool(separator), f"invalid platform image lock: {image}")
    return f"{version}@{lock['runtime_image_digests'][image]}"


def values(lock: dict[str, Any], name: str) -> dict[str, Any]:
    images = lock["runtime_image_digests"]
    if name == "metallb":
        require(set(images) >= METALLB_IMAGES, "MetalLB image lock is incomplete")
        return {
            "controller": {
                "image": {"tag": image_tag(lock, "quay.io/metallb/controller:v0.15.2")}
            },
            "speaker": {
                "frr": {"enabled": False},
                "image": {"tag": image_tag(lock, "quay.io/metallb/speaker:v0.15.2")},
            },
        }
    require(name == "longhorn", "unknown platform add-on")
    require(set(images) >= LONGHORN_IMAGES, "Longhorn image lock is incomplete")
    tags = {
        "engine": "longhornio/longhorn-engine:v1.10.1",
        "manager": "longhornio/longhorn-manager:v1.10.1",
        "ui": "longhornio/longhorn-ui:v1.10.1",
        "instanceManager": "longhornio/longhorn-instance-manager:v1.10.1",
        "shareManager": "longhornio/longhorn-share-manager:v1.10.1",
        "backingImageManager": "longhornio/backing-image-manager:v1.10.1",
        "supportBundleKit": "longhornio/support-bundle-kit:v0.0.71",
    }
    csi_tags = {
        "attacher": "longhornio/csi-attacher:v4.10.0-20251030",
        "provisioner": "longhornio/csi-provisioner:v5.3.0-20251030",
        "nodeDriverRegistrar": "longhornio/csi-node-driver-registrar:v2.15.0-20251030",
        "resizer": "longhornio/csi-resizer:v1.14.0-20251030",
        "snapshotter": "longhornio/csi-snapshotter:v8.4.0-20251030",
        "livenessProbe": "longhornio/livenessprobe:v2.17.0-20251030",
    }
    return {
        "defaultSettings": {
            "defaultDataPath": "/var/lib/longhorn",
            "defaultReplicaCount": "3",
        },
        "image": {
            "longhorn": {
                key: {"tag": image_tag(lock, image)} for key, image in tags.items()
            },
            "csi": {
                key: {"tag": image_tag(lock, image)}
                for key, image in csi_tags.items()
            },
        },
    }


def values_file(directory: Path, lock: dict[str, Any], name: str) -> Path:
    path = directory / f"{name}-values.json"
    path.write_text(json.dumps(values(lock, name), indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def validate_rendered(rendered: str, lock: dict[str, Any], name: str) -> None:
    expected = METALLB_IMAGES if name == "metallb" else LONGHORN_IMAGES
    for image in expected:
        require(
            lock["runtime_image_digests"][image] in rendered,
            f"rendered {name} output is missing the locked digest for {image}",
        )
    image_lines = re.findall(r"(?m)^[ \t]*image:[ \t]*[\"']?([^\"'\s]+)", rendered)
    require(bool(image_lines), f"rendered {name} output contains no images")
    require(
        all("@sha256:" in image for image in image_lines),
        f"rendered {name} output contains an unpinned image",
    )


def template_local(lock: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory(prefix="shell-platform-addons-render-") as directory:
        root = Path(directory)
        for name, metadata in RELEASES.items():
            chart = staged_chart(lock, name)
            rendered = transport.run(
                [
                    "helm",
                    "template",
                    name,
                    str(chart),
                    "--namespace",
                    metadata["namespace"],
                    "--values",
                    str(values_file(root, lock, name)),
                ],
                label=f"local {name} chart render",
                timeout_seconds=180,
            )
            validate_rendered(rendered, lock, name)


def remote(
    connection: transport.Connection,
    command: str,
    *,
    label: str,
    timeout_seconds: int = 120,
) -> str:
    return transport.ssh(
        command,
        connection,
        label=label,
        timeout_seconds=timeout_seconds,
    )


def create_guest_stage(connection: transport.Connection) -> str:
    output = remote(
        connection,
        "set -eu; umask 077; mktemp -d /tmp/shell-platform-addons.XXXXXX",
        label="platform add-on remote staging",
    ).strip()
    require(
        re.fullmatch(r"/tmp/shell-platform-addons\.[A-Za-z0-9]+", output) is not None,
        "platform add-on staging directory is unsafe",
    )
    return output


def stage_artifacts(
    connection: transport.Connection,
    stage_dir: str,
    lock: dict[str, Any],
    local_values: dict[str, Path],
) -> None:
    artifacts: list[tuple[Path, str]] = [(SUPPLY, "supply.json")]
    for name in RELEASES:
        chart = staged_chart(lock, name)
        artifacts.extend(
            [
                (chart, f"{name}.tgz"),
                (local_values[name], f"{name}-values.json"),
            ]
        )
    for local, name in artifacts:
        transport.scp(local, f"{stage_dir}/{name}", connection)
    checks = [
        f"test -f {shlex.quote(stage_dir)}/{name}"
        for name in ("supply.json", "metallb.tgz", "metallb-values.json", "longhorn.tgz", "longhorn-values.json")
    ]
    for name in RELEASES:
        chart = lock["charts"][name]
        checks.append(
            f"sha256sum {shlex.quote(stage_dir)}/{name}.tgz | grep -q '^{chart['sha256']}  '")
    remote(
        connection,
        "set -eu; chmod 0600 "
        + shlex.quote(stage_dir)
        + "/*; "
        + "; ".join(checks),
        label="platform add-on staged artifact verification",
    )


def helm_command(
    action: list[str],
    name: str,
    stage_dir: str,
) -> str:
    metadata = RELEASES[name]
    return shlex.join(
        [
            GUEST_HELM,
            *action,
            name,
            f"{stage_dir}/{name}.tgz",
            "--namespace",
            metadata["namespace"],
            "--create-namespace",
            "--values",
            f"{stage_dir}/{name}-values.json",
            "--wait",
            "--timeout",
            "15m",
        ]
    )


def preflight(connection: transport.Connection) -> None:
    remote(
        connection,
        f"set -eu; test -x {GUEST_HELM}; sudo -E KUBECONFIG={GUEST_KUBECONFIG} "
        "k3s kubectl get --raw=/readyz | grep -qx ok",
        label="platform add-on K3s and Helm preflight",
    )


def install(connection: transport.Connection, stage_dir: str, name: str) -> None:
    remote(
        connection,
        "set -eu; sudo -E KUBECONFIG="
        + GUEST_KUBECONFIG
        + " "
        + helm_command(["upgrade", "--install"], name, stage_dir),
        label=f"install {name} platform add-on",
        timeout_seconds=1200,
    )


def wait_for_metallb(connection: transport.Connection) -> None:
    remote(
        connection,
        "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
        "rollout status deployment/metallb-controller --namespace metallb-system --timeout=180s",
        label="MetalLB controller readiness",
        timeout_seconds=240,
    )


def cleanup_guest(connection: transport.Connection, stage_dir: str) -> None:
    active_error = sys.exception()
    try:
        remote(
            connection,
            f"rm -rf -- {shlex.quote(stage_dir)}",
            label="platform add-on remote cleanup",
        )
    except Exception as cleanup_error:
        if active_error is None:
            raise
        active_error.add_note(f"platform add-on cleanup also failed: {cleanup_error}")


def apply(connection: transport.Connection, lock: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory(prefix="shell-platform-addons-") as directory:
        root = Path(directory)
        local_values = {
            name: values_file(root, lock, name) for name in RELEASES
        }
        stage_dir = create_guest_stage(connection)
        try:
            stage_artifacts(connection, stage_dir, lock, local_values)
            preflight(connection)
            # MetalLB's webhook is independent of Longhorn and must be ready
            # before any later consumer applies service-related resources.
            install(connection, stage_dir, "metallb")
            wait_for_metallb(connection)
            install(connection, stage_dir, "longhorn")
        finally:
            cleanup_guest(connection, stage_dir)


def verify(connection: transport.Connection) -> str:
    command = (
        "set -eu; K='sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl'; "
        "test \"$($K get nodes --no-headers | awk '$2 == \"Ready\" {count++} END {print count + 0}')\" = 3; "
        "$K -n metallb-system get deployment/metallb-controller daemonset/metallb-speaker; "
        "$K -n longhorn-system get nodes.longhorn.io -o wide; "
        "$K get storageclass/longhorn -o name; "
        "test \"$($K get storageclass/longhorn -o jsonpath='{.metadata.annotations.storageclass\\.kubernetes\\.io/is-default-class}')\" = true; "
        "if $K get storageclass/local-path -o jsonpath='{.metadata.annotations.storageclass\\.kubernetes\\.io/is-default-class}' 2>/dev/null | grep -qx true; then exit 1; fi; "
        "if $K -n metallb-system get ipaddresspool -o name 2>/dev/null | grep -q .; then exit 1; fi; "
        "printf verified"
    )
    return remote(
        connection,
        command,
        label="platform add-on read-only verification",
        timeout_seconds=180,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "template", "apply", "verify"))
    parser.add_argument("--approval", default="")
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        lock = validate_source()
        if args.action == "check":
            print("validated platform add-on source")
            return 0
        if args.action == "template":
            template_local(lock)
            print("rendered platform add-on charts")
            return 0
        if args.action == "apply":
            require(args.approval == APPROVAL, f"approval must be {APPROVAL}")
            require(bool(args.inventory), "private INIT inventories are required")
            for name in RELEASES:
                staged_chart(lock, name)
            connection = transport.resolve_connection(args.inventory)
            apply(connection, lock)
            return 0
        require(bool(args.inventory), "private INIT inventories are required")
        connection = transport.resolve_connection(args.inventory)
        print(verify(connection), end="")
    except (
        OSError,
        PlatformAddonsError,
        platform_supply.PlatformSupplyError,
        transport.TransportError,
    ) as error:
        print(f"MAKE platform add-on operation refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
