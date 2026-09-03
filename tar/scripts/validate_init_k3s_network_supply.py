#!/usr/bin/env python3
"""Validate the TAR supply contract for INIT's Cilium network foundation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "tar/manifests/init-k3s-network-supply.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")

EXPECTED_HELM_BINARY = {
    "version": "v3.18.4",
    "file_name": "helm",
    "source": "https://get.helm.sh/helm-v3.18.4-linux-amd64.tar.gz",
    "source_sha256": "f8180838c23d7c7d797b208861fecb591d9ce1690d8704ed1e4cb8e2add966c1",
    "archive_member": "linux-amd64/helm",
    "sha256": "84d06a0f5ba17fd9c4d9912613453cdaa95a4f59c8baf20c195b74310b009ea6",
    "size": 59715768,
    "platform": "linux/amd64",
}
EXPECTED_CILIUM_CHART = {
    "repository": "https://helm.cilium.io/",
    "name": "cilium",
    "version": "1.18.2",
    "source": "https://helm.cilium.io/cilium-1.18.2.tgz",
    "sha256": "39b62a72f0892dd16548bd08ee97d5db2e975f7c1f57155578a144186e22992f",
    "size": 229371,
    "max_bytes": 4194304,
}
EXPECTED_CILIUM_IMAGES = {
    "agent": {
        "repository": "quay.io/cilium/cilium",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:858f807ea4e20e85e3ea3240a762e1f4b29f1cb5bbd0463b8aa77e7b097c0667",
    },
    "envoy": {
        "repository": "quay.io/cilium/cilium-envoy",
        "tag": "v1.34.7-1757592137-1a52bb680a956879722f48c591a2ca90f7791324",
        "platform": "linux/amd64",
        "digest": "sha256:7932d656b63f6f866b6732099d33355184322123cfe1182e6f05175a3bc2e0e0",
    },
    "operator": {
        "repository": "quay.io/cilium/operator-generic",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:cb4e4ffc5789fd5ff6a534e3b1460623df61cba00f5ea1c7b40153b5efb81805",
    },
}
EXPECTED_CILIUM_CONFIGURATION = {
    "ipam_mode": "cluster-pool",
    "tunnel_protocol": "vxlan",
    "cni_exclusive": True,
    "kube_proxy_replacement": True,
    "socket_lb_enabled": True,
    "socket_lb_host_namespace_only": True,
    "operator_replicas": 1,
}
EXPECTED_TOP_LEVEL = {
    "schema_version",
    "contract_version",
    "contract_id",
    "policy_owner",
    "execution_owner",
    "proof_status",
    "staging",
    "helm_binary",
    "cilium_chart",
    "cilium_images",
    "cilium_configuration",
}


class NetworkSupplyError(ValueError):
    """The Cilium network supply contract is invalid or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NetworkSupplyError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _safe_path(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    current = Path(value.anchor)
    for component in value.parts[1:]:
        current /= component
        require(not current.is_symlink(), f"unsafe symlinked {label}: {current}")
    return value


def read_json(path: Path, label: str) -> dict[str, Any]:
    path = _safe_path(path, label)
    require(path.is_file(), f"missing regular {label}: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise NetworkSupplyError(f"invalid {label}: {path}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


def _https_url(value: Any, host: str, label: str) -> None:
    require(isinstance(value, str), f"{label} must be a URL")
    parsed = urlsplit(value)
    require(
        parsed.scheme == "https"
        and parsed.hostname == host
        and parsed.username is None
        and parsed.password is None,
        f"{label} must use the official HTTPS host",
    )


def _digest(value: Any, label: str) -> None:
    require(isinstance(value, str) and SHA256.fullmatch(value) is not None, label)


def validate_public(path: Path = LOCK_PATH) -> dict[str, Any]:
    lock = read_json(path, "Cilium network supply lock")
    require(set(lock) == EXPECTED_TOP_LEVEL, "Cilium network supply lock shape changed")
    require(lock["schema_version"] == "1.0", "Cilium network supply schema changed")
    require(
        lock["contract_version"] == "1.0.0", "Cilium network supply version changed"
    )
    require(
        lock["contract_id"] == "init-k3s-network-supply",
        "Cilium network supply ID changed",
    )
    require(lock["policy_owner"] == "tar", "TAR must own Cilium network supply")
    require(
        lock["execution_owner"] == "init", "INIT must consume Cilium network supply"
    )
    require(
        lock["proof_status"] == "source-reference-only",
        "Cilium network proof status changed",
    )
    require(
        lock["staging"]
        == {
            "mode": "local-verified-artifacts",
            "network_acquisition_owner": "tar",
            "consumer_network_acquisition": False,
            "artifact_directory": "init-k3s-network",
            "chart_cache_layout": "charts/{name}-{version}.tgz",
        },
        "Cilium network staging policy changed",
    )

    helm = lock["helm_binary"]
    require(isinstance(helm, dict), "Helm binary entry must be an object")
    require(helm == EXPECTED_HELM_BINARY, "Helm binary pin changed")
    require(
        VERSION.fullmatch(cast(str, helm["version"])) is not None,
        "Helm version is invalid",
    )
    _https_url(helm["source"], "get.helm.sh", "Helm source")
    _digest(helm["source_sha256"], "Helm source SHA-256 is invalid")
    _digest(helm["sha256"], "Helm SHA-256 is invalid")
    require(helm["size"] > 0, "Helm size must be positive")

    chart = lock["cilium_chart"]
    require(isinstance(chart, dict), "Cilium chart entry must be an object")
    require(chart == EXPECTED_CILIUM_CHART, "Cilium chart pin changed")
    _https_url(chart["repository"], "helm.cilium.io", "Cilium chart repository")
    _https_url(chart["source"], "helm.cilium.io", "Cilium chart source")
    require(
        chart["source"].endswith("/cilium-1.18.2.tgz"), "Cilium chart filename changed"
    )
    _digest(chart["sha256"], "Cilium chart SHA-256 is invalid")
    require(
        isinstance(chart["size"], int)
        and isinstance(chart["max_bytes"], int)
        and chart["size"] > 0
        and chart["size"] <= chart["max_bytes"] <= 64 * 1024 * 1024,
        "Cilium chart size is invalid",
    )

    require(
        lock["cilium_images"] == EXPECTED_CILIUM_IMAGES, "Cilium image pins changed"
    )
    for name, image in lock["cilium_images"].items():
        require(
            set(image) == {"repository", "tag", "platform", "digest"},
            f"Cilium {name} image shape changed",
        )
        require(image["platform"] == "linux/amd64", f"Cilium {name} platform changed")
        _digest(
            image["digest"].removeprefix("sha256:"),
            f"Cilium {name} image digest is invalid",
        )
    require(
        lock["cilium_configuration"] == EXPECTED_CILIUM_CONFIGURATION,
        "Cilium configuration changed",
    )
    return lock


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_staged(local_root: Path, lock_path: Path = LOCK_PATH) -> None:
    lock = validate_public(lock_path)
    local_root = _safe_path(local_root, "Cilium network local root")
    require(
        local_root.is_dir() and not local_root.is_symlink(),
        "Cilium network local root is missing",
    )
    require(
        stat.S_IMODE(local_root.stat().st_mode) == 0o700,
        "Cilium network local root must be mode 0700",
    )
    helm = local_root / "helm"
    require(helm.is_file() and not helm.is_symlink(), "staged Helm binary is missing")
    require(
        stat.S_IMODE(helm.stat().st_mode) == 0o600,
        "staged Helm binary must be mode 0600",
    )
    require(
        helm.stat().st_size == lock["helm_binary"]["size"],
        "staged Helm binary size changed",
    )
    require(
        sha256_file(helm) == lock["helm_binary"]["sha256"],
        "staged Helm binary checksum changed",
    )
    chart_root = local_root / "charts"
    require(
        chart_root.is_dir() and not chart_root.is_symlink(),
        "Cilium chart directory is missing",
    )
    require(
        stat.S_IMODE(chart_root.stat().st_mode) == 0o700,
        "Cilium chart directory must be mode 0700",
    )
    chart = lock["cilium_chart"]
    chart_path = local_root / "charts" / f"{chart['name']}-{chart['version']}.tgz"
    require(
        chart_path.is_file() and not chart_path.is_symlink(),
        "staged Cilium chart is missing",
    )
    require(
        stat.S_IMODE(chart_path.stat().st_mode) == 0o600,
        "staged Cilium chart must be mode 0600",
    )
    require(
        chart_path.stat().st_size == chart["size"], "staged Cilium chart size changed"
    )
    require(
        sha256_file(chart_path) == chart["sha256"],
        "staged Cilium chart checksum changed",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-root", type=Path)
    args = parser.parse_args(argv)
    try:
        validate_public()
        if args.staged_root is not None:
            validate_staged(args.staged_root)
    except (OSError, NetworkSupplyError) as error:
        print(f"TAR Cilium network supply validation failed: {error}", file=sys.stderr)
        return 2
    print("validated TAR Cilium network supply contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
