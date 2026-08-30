#!/usr/bin/env python3
"""Guarded Harbor bootstrap controller owned by MAKE."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any

TAR_SCRIPTS = Path(__file__).resolve().parents[2] / "tar/scripts"

if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
import k3s_transport as transport  # noqa: E402
import sops_helpers  # noqa: E402
import validate_platform_supply as platform_supply  # noqa: E402
import validate_harbor_robots  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
# Remote mktemp results are regex-validated before use.
REMOTE_TMP = "/tmp"  # nosec B108
CHART = ROOT / ".local/tar/platform-addons/charts/harbor-1.19.2.tgz"
VALUES = ROOT / "tar/manifests/harbor-values.json"
CERTIFICATE = ROOT / "make/harbor/certificate.yaml"
ROOT_CA = ROOT / "make/harbor/root-ca.yaml"
ROOT_CERTIFICATE = ROOT / "sudo/pki/shell-offline-root.crt.pem"
HARBOR_INPUT = ROOT / ".local/sudo/release-feed/input-set/harbor.sops.json"
AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
APPROVAL = "environment-gcp/make/harbor"
NAMESPACE = "shell-artifacts"


class HarborDeployError(RuntimeError):
    """Harbor deployment was refused."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HarborDeployError(message)


def validate_source() -> None:
    platform_supply.validate_harbor()
    validate_harbor_robots.validate()
    require(VALUES.is_file() and not VALUES.is_symlink(), "Harbor values are missing")
    require(
        CERTIFICATE.is_file() and not CERTIFICATE.is_symlink(),
        "Harbor certificate is missing",
    )
    require(
        ROOT_CA.is_file() and not ROOT_CA.is_symlink(),
        "Harbor root CA is missing",
    )
    require(
        ROOT_CERTIFICATE.is_file() and not ROOT_CERTIFICATE.is_symlink(),
        "SUDO root certificate is missing",
    )
    require(
        "".join(ROOT_CERTIFICATE.read_text(encoding="ascii").split())
        in "".join(ROOT_CA.read_text(encoding="ascii").split()),
        "Harbor root CA does not match SUDO trust",
    )
    values = json.loads(VALUES.read_text(encoding="utf-8"))
    require(
        values["expose"]["loadBalancer"]["IP"] == "10.77.0.221",
        "Harbor address changed",
    )
    require(values["trivy"]["enabled"] is True, "Harbor full profile must enable Trivy")
    require(
        values["persistence"]["enabled"] is True,
        "Harbor persistence must remain enabled",
    )


def secret_manifests(values: dict[str, Any]) -> str:
    required = (
        "admin_password",
        "core_key",
        "core_xsrf_key",
        "jobservice_secret",
        "registry_http_secret",
        "database_password",
        "registry_username",
        "registry_password",
    )
    require(
        all(isinstance(values.get(key), str) and values[key] for key in required),
        "Harbor input keys are incomplete",
    )

    def secret(
        name: str,
        data: dict[str, str],
        *,
        helm_managed: bool = True,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {"shell.platform/owner": "sudo"},
        }
        if helm_managed:
            metadata["labels"]["app.kubernetes.io/managed-by"] = "Helm"
            metadata["annotations"] = {
                "meta.helm.sh/release-name": "harbor",
                "meta.helm.sh/release-namespace": NAMESPACE,
            }
        return {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": metadata,
            "type": "Opaque",
            "stringData": data,
        }

    documents = [
        secret(
            "harbor-admin",
            {"HARBOR_ADMIN_PASSWORD": values["admin_password"]},
        ),
        secret("harbor-core-key", {"secretKey": values["core_key"]}),
        secret(
            "harbor-core",
            {
                "secret": values["core_key"],
                "POSTGRESQL_PASSWORD": values["database_password"],
            },
        ),
        secret("harbor-core-xsrf", {"CSRF_KEY": values["core_xsrf_key"]}),
        secret(
            "harbor-jobservice",
            {"JOBSERVICE_SECRET": values["jobservice_secret"]},
        ),
        secret(
            "harbor-registry",
            {
                "REGISTRY_HTTP_SECRET": values["registry_http_secret"],
                "REGISTRY_REDIS_PASSWORD": values["core_key"],
            },
        ),
        secret(
            "harbor-registry-credentials",
            {
                "REGISTRY_PASSWD": values["registry_password"],
                "REGISTRY_HTPASSWD": registry_htpasswd(
                    values["registry_username"], values["registry_password"]
                ),
            },
        ),
        secret(
            "harbor-database",
            {"POSTGRES_PASSWORD": values["database_password"]},
        ),
        secret(
            "harbor-exporter",
            {"HARBOR_DATABASE_PASSWORD": values["database_password"]},
        ),
    ]
    return "\n---\n".join(json.dumps(document) for document in documents) + "\n"


def registry_htpasswd(username: str, password: str) -> str:
    require(
        isinstance(username, str)
        and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username) is not None,
        "Harbor registry username is invalid",
    )
    try:
        result = subprocess.run(  # nosec B603
            ["htpasswd", "-niBC", "5", username],
            input=password + "\n",
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarborDeployError(
            "Harbor registry credential generation failed"
        ) from error
    require(result.returncode == 0, "Harbor registry credential generation failed")
    return result.stdout.strip()


def token_tls_material() -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="shell-harbor-token-") as directory:
        root = Path(directory)
        key = root / "tls.key"
        certificate = root / "tls.crt"
        for command, label in (
            (
                [
                    "openssl",
                    "genrsa",
                    "-traditional",
                    "-out",
                    str(key),
                    "2048",
                ],
                "Harbor token key generation",
            ),
            (
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(key),
                    "-days",
                    "3650",
                    "-subj",
                    "/CN=harbor-token",
                    "-out",
                    str(certificate),
                ],
                "Harbor token certificate generation",
            ),
        ):
            try:
                result = subprocess.run(  # nosec B603
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise HarborDeployError(f"{label} failed") from error
            require(result.returncode == 0, f"{label} failed")
        return (
            key.read_text(encoding="ascii"),
            certificate.read_text(encoding="ascii"),
        )


def token_secret_manifest() -> str:
    key, certificate = token_tls_material()
    return (
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": "harbor-token",
                    "namespace": NAMESPACE,
                    "labels": {
                        "shell.platform/owner": "sudo",
                        "app.kubernetes.io/managed-by": "Helm",
                    },
                    "annotations": {
                        "meta.helm.sh/release-name": "harbor",
                        "meta.helm.sh/release-namespace": NAMESPACE,
                    },
                },
                "type": "Opaque",
                "stringData": {"tls.key": key, "tls.crt": certificate},
            }
        )
        + "\n"
    )


def remote(
    connection: transport.Connection,
    command: str,
    *,
    label: str,
    input_text: str | None = None,
) -> str:
    return transport.ssh(
        command,
        connection,
        label=label,
        input_text=input_text,
        timeout_seconds=180,
    )


def deploy(connection: transport.Connection) -> None:
    lock = platform_supply.validate_harbor()
    require(
        CHART.is_file() and not CHART.is_symlink(), "staged Harbor chart is missing"
    )
    require(
        hashlib.sha256(CHART.read_bytes()).hexdigest() == lock["chart"]["sha256"],
        "staged Harbor chart checksum changed",
    )
    private = sops_helpers.decrypt_json(HARBOR_INPUT, AGE_KEY)
    with tempfile.TemporaryDirectory(prefix="shell-harbor-") as directory:
        local = Path(directory)
        values = local / VALUES.name
        values.write_bytes(VALUES.read_bytes())
        secret_values = local / "secret-values.json"
        secret_values.write_text(
            json.dumps(
                {
                    "database": {
                        "internal": {"password": private["database_password"]}
                    },
                    "redis": {"internal": {"password": private["core_key"]}},
                    "registry": {
                        "credentials": {
                            "username": private["registry_username"],
                            "password": private["registry_password"],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        secret_values.chmod(0o600)
        remote_dir = remote(
            connection,
            f"set -eu; umask 077; mktemp -d {REMOTE_TMP}/shell-harbor.XXXXXX",
            label="Harbor remote staging",
        ).strip()
        require(
            re.fullmatch(
                rf"{re.escape(REMOTE_TMP)}/shell-harbor\.[A-Za-z0-9]+", remote_dir
            )
            is not None,
            "Harbor remote staging path is unsafe",
        )
        try:
            remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                "create namespace shell-artifacts --dry-run=client -o yaml | "
                "sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl apply "
                "--server-side --field-manager=make-harbor --filename -",
                label="Harbor namespace bootstrap",
            )
            transport.scp(ROOT_CA, f"{remote_dir}/{ROOT_CA.name}", connection)
            transport.scp(CERTIFICATE, f"{remote_dir}/{CERTIFICATE.name}", connection)
            remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                f"apply --server-side --field-manager=make-harbor --filename {shlex.quote(remote_dir)}/{ROOT_CA.name}",
                label="Harbor root CA bootstrap",
            )
            remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                f"apply --server-side --field-manager=make-harbor --filename {shlex.quote(remote_dir)}/{CERTIFICATE.name}",
                label="Harbor certificate bootstrap",
            )
            remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                "wait --for=condition=Ready certificate/harbor-public-tls "
                "--namespace shell-artifacts --timeout=180s",
                label="Harbor certificate readiness",
            )
            remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                "apply --server-side --field-manager=make-harbor --filename -",
                label="Harbor secret bootstrap",
                input_text=secret_manifests(private),
            )
            remote(
                connection,
                "set -eu; if ! sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml "
                "k3s kubectl get secret harbor-token --namespace shell-artifacts "
                ">/dev/null 2>&1; then sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml "
                "k3s kubectl apply --server-side --field-manager=make-harbor "
                "--filename -; fi",
                label="Harbor token secret bootstrap",
                input_text=token_secret_manifest(),
            )
            transport.scp(values, f"{remote_dir}/{VALUES.name}", connection)
            transport.scp(
                secret_values,
                f"{remote_dir}/{secret_values.name}",
                connection,
            )
            transport.scp(CHART, f"{remote_dir}/harbor-1.19.2.tgz", connection)
            remote(
                connection,
                "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml /usr/local/bin/helm upgrade --install harbor "
                f"{shlex.quote(remote_dir)}/harbor-1.19.2.tgz --namespace {NAMESPACE} "
                f"--values {shlex.quote(remote_dir)}/{VALUES.name} "
                f"--values {shlex.quote(remote_dir)}/{secret_values.name} "
                "--atomic --wait --timeout 15m",
                label="Harbor Helm bootstrap",
            )
        finally:
            remote(
                connection,
                f"set -eu; sudo rm -rf -- {shlex.quote(remote_dir)}",
                label="Harbor remote cleanup",
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "apply", "verify"))
    parser.add_argument("--approval")
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        validate_source()
        if args.action == "check":
            print("validated Harbor source")
            return 0
        if args.action == "apply":
            raise HarborDeployError(
                "Harbor apply is blocked until GCP service routing and SUDO signing-key custody exist"
            )
        require(args.inventory, "private INIT inventories are required")
        connection = transport.resolve_connection(args.inventory)
        if args.action == "verify":
            print(
                remote(
                    connection,
                    "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
                    "get pods,service --namespace shell-artifacts --output wide",
                    label="Harbor verification",
                ),
                end="",
            )
    except (
        OSError,
        HarborDeployError,
        transport.TransportError,
        sops_helpers.SopsError,
        validate_harbor_robots.HarborRobotError,
    ) as error:
        print(f"MAKE Harbor operation refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
