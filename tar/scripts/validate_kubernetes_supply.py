#!/usr/bin/env python3
"""Validate the public TAR supply for the MAKE trust slice."""

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


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPOSITORY_ROOT / "tar/manifests/kubernetes-ecosystem-supply.json"
DEFAULT_LOCAL_ROOT = REPOSITORY_ROOT / ".local/tar/kubernetes"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_CHART = {
    "repository": "https://charts.jetstack.io",
    "name": "cert-manager",
    "version": "v1.21.0",
    "source": "https://charts.jetstack.io/charts/cert-manager-v1.21.0.tgz",
    "sha256": "9c2c6fabf3cf8fe14dacb016f37c819b66bc2c79e8b7acde4573d45ec141fb97",
}
EXPECTED_IMAGES = {
    "quay.io/jetstack/cert-manager-controller:v1.21.0": {
        "repository": "quay.io/jetstack/cert-manager-controller",
        "tag": "v1.21.0",
        "platform": "linux/amd64",
        "digest": "sha256:e370f7800a53078e9d74324287a7d52b553864e55f5b4e521f911c3f6c7da203",
    },
    "quay.io/jetstack/cert-manager-webhook:v1.21.0": {
        "repository": "quay.io/jetstack/cert-manager-webhook",
        "tag": "v1.21.0",
        "platform": "linux/amd64",
        "digest": "sha256:c33cca307541e2d58861a55b1af5f390b7e19c8741e48b433693b73a7cce88b3",
    },
    "quay.io/jetstack/cert-manager-cainjector:v1.21.0": {
        "repository": "quay.io/jetstack/cert-manager-cainjector",
        "tag": "v1.21.0",
        "platform": "linux/amd64",
        "digest": "sha256:ad1dcc5b2fccc420f9b3fbee7ce8a869450c540fd4f2f41de2d95b1ca0c4d701",
    },
    "quay.io/jetstack/cert-manager-startupapicheck:v1.21.0": {
        "repository": "quay.io/jetstack/cert-manager-startupapicheck",
        "tag": "v1.21.0",
        "platform": "linux/amd64",
        "digest": "sha256:68b3c5029dc63e64a6b6435337d7dc0eb169f889a48a02d999d1f22f31865b33",
    },
}


class SupplyError(ValueError):
    """The public Kubernetes supply contract is invalid or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SupplyError(message)


def _check_no_symlink_components(path: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        require(not current.is_symlink(), f"unsafe symlinked {label}: {current}")
    return path


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path, label: str) -> dict[str, Any]:
    path = _check_no_symlink_components(path, label)
    require(path.is_file() and not path.is_symlink(), f"missing regular {label}: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SupplyError(f"invalid JSON for {label}: {path}") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(dict[str, Any], value)


def validate_public(path: Path = LOCK_PATH) -> dict[str, Any]:
    lock = read_json(path, "Kubernetes supply lock")
    require(
        set(lock)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "execution_owner",
            "proof_status",
            "staging",
            "charts",
            "images",
        },
        "Kubernetes supply lock shape changed",
    )
    require(lock["schema_version"] == "1.0", "Kubernetes supply schema changed")
    require(lock["contract_version"] == "1.0.0", "Kubernetes supply version changed")
    require(lock["contract_id"] == "kubernetes-ecosystem-supply", "Kubernetes supply ID changed")
    require(lock["policy_owner"] == "tar", "TAR must own Kubernetes supply")
    require(lock["execution_owner"] == "make", "MAKE must consume Kubernetes supply")
    require(lock["proof_status"] == "source-reference-only", "Kubernetes supply proof changed")
    require(
        lock["staging"]
        == {
            "mode": "local-verified-artifacts",
            "network_acquisition_owner": "tar",
            "consumer_network_acquisition": False,
            "artifact_directory": "kubernetes",
            "chart_cache_layout": "charts/{name}-{version}.tgz",
        },
        "Kubernetes staging policy changed",
    )
    charts = lock["charts"]
    require(isinstance(charts, dict) and set(charts) == {"cert-manager"}, "Kubernetes chart set changed")
    chart = charts["cert-manager"]
    require(chart == EXPECTED_CHART, "cert-manager chart pin changed")
    source = urlsplit(chart["source"])
    repository = urlsplit(chart["repository"])
    require(
        source.scheme == "https"
        and repository.scheme == "https"
        and source.netloc == repository.netloc == "charts.jetstack.io"
        and source.path.endswith("/cert-manager-v1.21.0.tgz"),
        "cert-manager source must remain the official HTTPS archive",
    )
    require(SHA256_PATTERN.fullmatch(chart["sha256"]) is not None, "cert-manager chart checksum is invalid")
    images = lock["images"]
    require(images == EXPECTED_IMAGES, "cert-manager image pins changed")
    for image, details in images.items():
        require(
            isinstance(details, dict)
            and set(details) == {"repository", "tag", "platform", "digest"},
            f"cert-manager image shape changed: {image}",
        )
        require(details["platform"] == "linux/amd64", f"cert-manager image platform changed: {image}")
        require(
            IMAGE_DIGEST_PATTERN.fullmatch(details["digest"]) is not None,
            f"cert-manager image digest is invalid: {image}",
        )
    return lock


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_staged(local_root: Path = DEFAULT_LOCAL_ROOT) -> Path:
    lock = validate_public()
    local_root = _check_no_symlink_components(local_root, "Kubernetes local root")
    require(local_root.is_dir() and not local_root.is_symlink(), "Kubernetes local root must be a directory")
    require(local_root.stat().st_mode & 0o077 == 0, "Kubernetes local root must be private")
    chart_root = _check_no_symlink_components(local_root / "charts", "Kubernetes chart directory")
    require(chart_root.is_dir() and not chart_root.is_symlink(), "Kubernetes chart directory is missing")
    require(
        stat.S_IMODE(chart_root.stat().st_mode) == 0o700,
        "Kubernetes chart directory must be mode 0700",
    )
    chart = lock["charts"]["cert-manager"]
    path = _check_no_symlink_components(
        chart_root / f"{chart['name']}-{chart['version']}.tgz",
        "staged cert-manager chart",
    )
    require(path.is_file() and not path.is_symlink(), "staged cert-manager chart is missing")
    require(
        stat.S_IMODE(path.stat().st_mode) == 0o600,
        "staged cert-manager chart must be mode 0600",
    )
    require(sha256_file(path) == chart["sha256"], "staged cert-manager chart checksum changed")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-root", type=Path)
    args = parser.parse_args(argv)
    try:
        validate_public()
        if args.staged_root is not None:
            validate_staged(args.staged_root)
    except (OSError, SupplyError) as error:
        print(f"Kubernetes supply validation failed: {error}", file=sys.stderr)
        return 2
    print("validated cert-manager Kubernetes supply contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
