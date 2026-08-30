#!/usr/bin/env python3
"""Deploy or verify the GCP-only release-feed manifests from MAKE."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

import k3s_transport as transport

SCRIPT_ROOT = Path(__file__).resolve().parent
ROOT = SCRIPT_ROOT.parents[1]
# Remote mktemp results are regex-validated before use.
REMOTE_TMP = "/tmp"  # nosec B108
MANIFEST_ROOT = ROOT / "make/apps/release-feed/k8s/base"
WATCH_RULE = ROOT / "watch/monitoring/release-feed.rules.yaml"
CONTRACT = ROOT / "make/contracts/release-feed-secret-contract.json"
APPROVAL = "environment-gcp/make/release-feed"
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_PLACEHOLDER = "sha256:REPLACE_WITH_TAR_PROMOTED_DIGEST"
MANIFESTS = (
    "namespace.yaml",
    "networkpolicy.yaml",
    "serviceaccount.yaml",
    "openbao-agent-config.yaml",
    "certificate.yaml",
    "service.yaml",
    "statefulset.yaml",
    "servicemonitor.yaml",
)


class ReleaseFeedDeployError(RuntimeError):
    """MAKE refused an unsafe release-feed deployment."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseFeedDeployError(message)


def read_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing contract: {path}")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, f"duplicate contract key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseFeedDeployError(
            "release-feed secret contract is invalid"
        ) from error
    require(isinstance(value, dict), "release-feed secret contract is not an object")
    return value


def validate_source(*, image_digest: str | None = None) -> None:
    contract = read_json(CONTRACT)
    require(
        set(contract)
        == {
            "description",
            "schema_version",
            "contract_version",
            "contract_id",
            "policy_owner",
            "producer_owner",
            "environment",
            "source_contracts",
            "namespace",
            "application",
            "harbor",
            "openbao",
            "tls",
            "storage",
        }
        and isinstance(contract["description"], str),
        "release-feed secret contract shape changed",
    )
    require(
        contract["schema_version"] == "1.0"
        and contract["contract_version"] == "1.0.0"
        and contract["contract_id"] == "release-feed-secret-contract",
        "release-feed secret contract identity changed",
    )
    require(
        contract["policy_owner"] == "make"
        and contract["producer_owner"] == "sudo"
        and contract["namespace"] == "release-feed",
        "release-feed ownership changed",
    )
    require(
        contract.get("environment") == "environment-gcp",
        "release-feed environment changed",
    )
    source_contracts = contract.get("source_contracts")
    require(
        isinstance(source_contracts, dict),
        "release-feed source contracts are incomplete",
    )
    source_contracts = cast(dict[str, str], source_contracts)
    require(
        source_contracts
        == {
            "sudo_inputs": "sudo/secrets/release-feed-input-contract.json",
            "artifact_supply": "tar/manifests/release-feed-supply.json",
            "watch_policy": "watch/contracts/release-feed-requirements.json",
        },
        "release-feed source contracts changed",
    )
    for relative in source_contracts.values():
        path = ROOT / relative
        require(
            path.is_file() and not path.is_symlink(),
            f"release-feed source contract is missing: {relative}",
        )
    harbor_value = contract["harbor"]
    storage_value = contract["storage"]
    openbao_value = contract["openbao"]
    application_value = contract.get("application")
    require(
        isinstance(harbor_value, dict), "release-feed Harbor contract is incomplete"
    )
    require(
        isinstance(storage_value, dict), "release-feed storage contract is incomplete"
    )
    require(
        isinstance(openbao_value, dict), "release-feed OpenBao contract is incomplete"
    )
    require(
        application_value
        == {
            "max_records": 1000,
            "capacity_warning_remaining": 100,
            "capacity_exhausted_status": 507,
        },
        "release-feed application limits changed",
    )
    harbor = cast(dict[str, Any], harbor_value)
    storage = cast(dict[str, Any], storage_value)
    openbao = cast(dict[str, Any], openbao_value)
    require(
        harbor
        == {
            "endpoint": "registry.shell.internal",
            "address": "10.77.0.221",
            "pull_secret": "release-feed-pull",
            "image_repository": "registry.shell.internal/shell/release-feed",
        },
        "release-feed Harbor contract changed",
    )
    require(
        storage
        == {
            "storage_class": "longhorn",
            "size": "1Gi",
            "access_mode": "ReadWriteOnce",
            "retention": "retain",
        },
        "release-feed storage contract changed",
    )
    require(
        openbao
        == {
            "path": "secret/data/release-feed",
            "keys": ["read_token", "write_token"],
            "service_account": "release-feed",
            "role": "release-feed",
            "audience": "openbao",
        },
        "release-feed OpenBao contract changed",
    )
    require(
        contract["tls"]
        == {
            "secret": "release-feed-tls",
            "dns_names": [
                "releases.shell.internal",
                "release-feed.release-feed.svc",
                "release-feed.release-feed.svc.cluster.local",
            ],
        },
        "release-feed TLS contract changed",
    )
    for name in MANIFESTS:
        path = MANIFEST_ROOT / name
        require(
            path.is_file() and not path.is_symlink(),
            f"release-feed manifest is missing: {name}",
        )
    require(
        WATCH_RULE.is_file() and not WATCH_RULE.is_symlink(),
        "release-feed WATCH rule is missing",
    )
    service = (MANIFEST_ROOT / "service.yaml").read_text(encoding="utf-8")
    statefulset = (MANIFEST_ROOT / "statefulset.yaml").read_text(encoding="utf-8")
    require(
        "loadBalancerIP: 10.77.0.222" in service, "release-feed service address changed"
    )
    require(
        "storageClassName: longhorn" in statefulset,
        "release-feed storage class changed",
    )
    if image_digest is None:
        require(
            IMAGE_PLACEHOLDER in statefulset,
            "release-feed source must remain unpromoted",
        )
    else:
        require(
            IMAGE_DIGEST.fullmatch(image_digest) is not None,
            "release-feed image digest is invalid",
        )


def rendered_manifests(
    image_digest: str,
) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    require(
        IMAGE_DIGEST.fullmatch(image_digest) is not None,
        "release-feed image digest is invalid",
    )
    directory = tempfile.TemporaryDirectory(prefix="shell-release-feed-")
    target = Path(directory.name)
    for name in MANIFESTS:
        source = MANIFEST_ROOT / name
        destination = target / name
        destination.write_text(
            source.read_text(encoding="utf-8")
            .replace(IMAGE_PLACEHOLDER, image_digest)
            .replace(
                "value: unpromoted",
                f"value: {image_digest.removeprefix('sha256:')}",
            ),
            encoding="utf-8",
        )
        destination.chmod(0o600)
    rule = target / WATCH_RULE.name
    rule.write_bytes(WATCH_RULE.read_bytes())
    rule.chmod(0o600)
    return directory, target


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
        timeout_seconds=120,
    )


def apply(
    connection: transport.Connection,
    *,
    image_digest: str,
) -> None:
    temporary, directory = rendered_manifests(image_digest)
    remote_dir = remote(
        connection,
        f"set -eu; umask 077; mktemp -d {REMOTE_TMP}/shell-release-feed.XXXXXX",
        label="release-feed remote staging",
    ).strip()
    require(
        re.fullmatch(
            rf"{re.escape(REMOTE_TMP)}/shell-release-feed\.[A-Za-z0-9]+", remote_dir
        )
        is not None,
        "release-feed remote staging path is unsafe",
    )
    try:
        for name in (*MANIFESTS, WATCH_RULE.name):
            transport.scp(directory / name, f"{remote_dir}/{name}", connection)
        for name in (*MANIFESTS, WATCH_RULE.name):
            remote(
                connection,
                "set -eu; "
                + " ".join(
                    [
                        "sudo",
                        "-E",
                        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml",
                        "k3s",
                        "kubectl",
                        "apply",
                        "--server-side",
                        "--field-manager=make-release-feed",
                        "--filename",
                        shlex.quote(f"{remote_dir}/{name}"),
                    ]
                ),
                label=f"apply release-feed {name}",
            )
    finally:
        temporary.cleanup()


def verify(connection: transport.Connection) -> str:
    return remote(
        connection,
        "set -eu; "
        "sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
        "get statefulset/release-feed service/release-feed "
        "pvc --namespace release-feed --output wide",
        label="release-feed verification",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "apply", "verify"))
    parser.add_argument("--approval")
    parser.add_argument("--image-digest")
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        if args.action == "check":
            validate_source()
            print("validated release-feed source")
            return 0
        if args.action == "apply":
            raise ReleaseFeedDeployError(
                "release-feed apply is blocked until GCP routing and a TAR promotion handoff exist"
            )
        require(args.inventory, "private INIT inventories are required")
        connection = transport.resolve_connection(args.inventory)
        if args.action == "verify":
            validate_source()
            print(verify(connection), end="")
    except (OSError, ReleaseFeedDeployError, transport.TransportError) as error:
        print(f"MAKE release-feed operation refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
