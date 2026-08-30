#!/usr/bin/env python3
"""Guarded Argo CD bootstrap controller owned by MAKE."""

from __future__ import annotations

import argparse
import hashlib
import re
import shlex
import sys
import tempfile
from pathlib import Path

TAR_SCRIPTS = Path(__file__).resolve().parents[2] / "tar/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
import k3s_transport as transport  # noqa: E402
import validate_platform_supply as platform_supply  # noqa: E402
import validate_argocd as validator  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
# Remote mktemp results are regex-validated before use.
REMOTE_TMP = "/tmp"  # nosec B108
CHART = ROOT / ".local/tar/platform-addons/charts/argo-cd-10.1.4.tgz"
VALUES = ROOT / "make/gitops/bootstrap/argocd/values.yaml"
APPLY_FILES = (
    ROOT / "make/gitops/bootstrap/argocd/repository-ca.yaml",
    ROOT / "make/gitops/bootstrap/argocd/project.yaml",
    ROOT / "make/gitops/bootstrap/argocd/certificate.yaml",
)
ROOT_APPLICATION = ROOT / "make/gitops/bootstrap/argocd/root-application.yaml"
APPROVAL = "environment-gcp/make/argocd"
ROOT_APPROVAL = "environment-gcp/make/argocd-root"


class ArgoDeployError(RuntimeError):
    """Argo CD deployment was refused."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArgoDeployError(message)


def remote(connection: transport.Connection, command: str, *, label: str) -> str:
    return transport.ssh(
        command,
        connection,
        label=label,
        timeout_seconds=120,
    )


def deploy(connection: transport.Connection) -> None:
    lock = platform_supply.validate_services()
    chart = lock["charts"]["argo-cd"]
    require(
        CHART.is_file() and not CHART.is_symlink(), "staged Argo CD chart is missing"
    )
    require(
        hashlib.sha256(CHART.read_bytes()).hexdigest() == chart["sha256"],
        "staged Argo CD chart checksum changed",
    )
    with tempfile.TemporaryDirectory(prefix="shell-argocd-") as directory:
        local = Path(directory)
        values = local / VALUES.name
        values.write_bytes(VALUES.read_bytes())
        remote_dir = remote(
            connection,
            f"set -eu; umask 077; mktemp -d {REMOTE_TMP}/shell-argocd.XXXXXX",
            label="Argo CD remote staging",
        ).strip()
        require(
            re.fullmatch(
                rf"{re.escape(REMOTE_TMP)}/shell-argocd\.[A-Za-z0-9]+", remote_dir
            )
            is not None,
            "Argo CD remote staging path is unsafe",
        )
        try:
            transport.scp(values, f"{remote_dir}/{VALUES.name}", connection)
            transport.scp(CHART, f"{remote_dir}/argo-cd-10.1.4.tgz", connection)
            remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml "
                f"/usr/local/bin/helm upgrade --install argocd {shlex.quote(remote_dir)}/argo-cd-10.1.4.tgz "
                f"--namespace argocd --create-namespace --values {shlex.quote(remote_dir)}/{VALUES.name} "
                "--atomic --wait --timeout 10m",
                label="Argo CD Helm bootstrap",
            )
            for path in APPLY_FILES:
                transport.scp(path, f"{remote_dir}/{path.name}", connection)
                remote(
                    connection,
                    "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                    f"apply --server-side --field-manager=make-argocd --filename {shlex.quote(remote_dir)}/{path.name}",
                    label=f"apply Argo CD {path.name}",
                )
        finally:
            remote(
                connection,
                f"set -eu; sudo rm -rf -- {shlex.quote(remote_dir)}",
                label="Argo CD remote cleanup",
            )


def apply_root(connection: transport.Connection) -> None:
    require(
        ROOT_APPLICATION.is_file() and not ROOT_APPLICATION.is_symlink(),
        "Argo CD root application is missing",
    )
    remote(
        connection,
        "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
        "get secret shell-make-repository shell-harbor-charts "
        "--namespace argocd --output name",
        label="Argo CD repository handoff preflight",
    )
    with tempfile.TemporaryDirectory(prefix="shell-argocd-root-"):
        remote_dir = remote(
            connection,
            f"set -eu; umask 077; mktemp -d {REMOTE_TMP}/shell-argocd-root.XXXXXX",
            label="Argo CD root remote staging",
        ).strip()
        require(
            re.fullmatch(
                rf"{re.escape(REMOTE_TMP)}/shell-argocd-root\.[A-Za-z0-9]+",
                remote_dir,
            )
            is not None,
            "Argo CD root staging path is unsafe",
        )
        try:
            transport.scp(
                ROOT_APPLICATION,
                f"{remote_dir}/{ROOT_APPLICATION.name}",
                connection,
            )
            remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                f"apply --server-side --field-manager=make-argocd --filename "
                f"{shlex.quote(remote_dir)}/{ROOT_APPLICATION.name}",
                label="Argo CD root application",
            )
        finally:
            remote(
                connection,
                f"set -eu; sudo rm -rf -- {shlex.quote(remote_dir)}",
                label="Argo CD root remote cleanup",
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "apply", "root-apply", "verify"))
    parser.add_argument("--approval")
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        validator.validate()
        platform_supply.validate_services()
        if args.action == "check":
            print("validated Argo CD source")
            return 0
        if args.action in {"apply", "root-apply"}:
            raise ArgoDeployError(
                "Argo CD apply is blocked until runtime images and the GitOps source revision are pinned"
            )
        require(args.inventory, "private INIT inventories are required")
        connection = transport.resolve_connection(args.inventory)
        if args.action == "verify":
            output = remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                "get application shell-platform-root --namespace argocd --output wide",
                label="Argo CD verification",
            )
            print(output, end="")
    except (
        OSError,
        ArgoDeployError,
        transport.TransportError,
        validator.ArgoValidationError,
    ) as error:
        print(f"MAKE Argo CD operation refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
