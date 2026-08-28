#!/usr/bin/env python3
"""Validate the source-only TAR supply for WATCH metrics and Grafana."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPOSITORY_ROOT / "tar/manifests/watch-supply.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_CHART_SHA256 = (
    "aac57bfb6fb53c3a9c6f4f0526b61145507dd81ff5312c67305ba5e31b7732d6"
)
EXPECTED_IMAGE_DIGESTS = {
    "quay.io/prometheus/prometheus:v3.14.0-distroless": "sha256:50c707e96da5ade383cb1707790576480485e93de06aa60ad8802cb5f744bd0a",
    "quay.io/prometheus/alertmanager:v0.34.0": "sha256:690c7b525f4367aa91f73e2f91c632206d32e97c6384bdbf2fb7a861b420340d",
    "quay.io/prometheus-operator/prometheus-operator:v0.93.1": "sha256:e52bb28fd41c98dd407c7a8cba8bdcfe7eabd7447e250afaf1fe7bb816dedbff",
    "quay.io/prometheus-operator/prometheus-config-reloader:v0.93.1": "sha256:428f088fe6fe07ab138bda92113664b04848a1dc408e4d3680a60ecdb55d1a65",
    "quay.io/prometheus/node-exporter:v1.12.1-distroless": "sha256:8c9bac11973b94b59be88d6e11fee4429aa743c8846cdc75d65b18db33f6a106",
    "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.20.0": "sha256:42cfe3723a5f058171c627537fb57a3ea0f26e4380fa18555a95cb1a1b4cfc5b",
    "docker.io/grafana/grafana:13.2.0": "sha256:3fd54ae1214669f8355f065ec9f6445d5279a3d77095ab048ca045685272429b",
    "ghcr.io/jkroepke/kube-webhook-certgen:1.8.5": "sha256:d0e80b2f62fe43bb5e1b96adc692132fb4522e802f4cf673c09b1f94722b8cb6",
}
EXPECTED_IMAGES = list(EXPECTED_IMAGE_DIGESTS)
EXPECTED_PERSISTENT_IMAGES = EXPECTED_IMAGES[:-1]
EXPECTED_CHART_SOURCE = (
    "https://github.com/prometheus-community/helm-charts/releases/download/"
    "kube-prometheus-stack-88.5.2/kube-prometheus-stack-88.5.2.tgz"
)


class WatchSupplyError(ValueError):
    """The WATCH artifact supply contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchSupplyError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def read_lock(path: Path = LOCK_PATH) -> dict[str, Any]:
    require(
        path.is_file() and not path.is_symlink(), "TAR WATCH supply lock is missing"
    )
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WatchSupplyError("TAR WATCH supply lock is not valid JSON") from error
    require(isinstance(value, dict), "TAR WATCH supply lock must be an object")
    return cast(dict[str, Any], value)


def validate_public(path: Path = LOCK_PATH) -> dict[str, Any]:
    lock = read_lock(path)
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
            "environment",
            "staging",
            "charts",
            "runtime_image_platform",
            "runtime_image_digests",
            "required_runtime_images",
            "persistent_runtime_images",
        },
        "TAR WATCH supply lock shape changed",
    )
    require(lock["schema_version"] == "1.0", "TAR WATCH schema changed")
    require(lock["contract_version"] == "2.0.0", "TAR WATCH version changed")
    require(lock["contract_id"] == "watch-supply", "TAR WATCH contract ID changed")
    require(lock["policy_owner"] == "tar", "TAR must own WATCH supply")
    require(lock["execution_owner"] == "make", "MAKE must consume WATCH supply")
    require(lock["proof_status"] == "source-reference-only", "TAR WATCH proof changed")
    require(lock["environment"] == "environment-gcp", "TAR WATCH environment changed")
    require(
        lock["runtime_image_platform"] == "linux/amd64", "TAR WATCH platform changed"
    )

    staging = lock["staging"]
    require(
        staging
        == {
            "mode": "local-verified-artifacts",
            "network_acquisition_owner": "tar",
            "consumer_network_acquisition": False,
            "artifact_directory": "watch",
            "chart_cache_layout": "charts/{name}-{version}.tgz",
        },
        "TAR WATCH staging boundary changed",
    )
    charts = lock["charts"]
    require(set(charts) == {"kube-prometheus-stack"}, "TAR WATCH chart set changed")
    chart = charts["kube-prometheus-stack"]
    require(
        chart["repository"] == "https://prometheus-community.github.io/helm-charts",
        "WATCH chart repository changed",
    )
    require(chart["name"] == "kube-prometheus-stack", "WATCH chart name changed")
    require(chart["version"] == "88.5.2", "WATCH chart version changed")
    require(chart["source"] == EXPECTED_CHART_SOURCE, "WATCH chart source changed")
    require(chart["sha256"] == EXPECTED_CHART_SHA256, "WATCH chart checksum changed")
    require(
        SHA256_RE.fullmatch(chart["sha256"]) is not None,
        "WATCH chart checksum is invalid",
    )

    required = lock["required_runtime_images"]
    persistent = lock["persistent_runtime_images"]
    runtime = lock["runtime_image_digests"]
    require(required == EXPECTED_IMAGES, "TAR WATCH image set changed")
    require(
        persistent == EXPECTED_PERSISTENT_IMAGES,
        "TAR WATCH persistent image set changed",
    )
    require(
        len(required) == len(set(required)), "TAR WATCH image list contains duplicates"
    )
    require(set(runtime) == set(required), "TAR WATCH digest set changed")
    for image, digest in runtime.items():
        require(
            isinstance(image, str) and ":" in image,
            "TAR WATCH image reference is invalid",
        )
        require(
            isinstance(digest, str) and IMAGE_DIGEST_RE.fullmatch(digest) is not None,
            "TAR WATCH image digest is invalid",
        )
    require(runtime == EXPECTED_IMAGE_DIGESTS, "TAR WATCH image digest changed")
    return lock


def main() -> int:
    try:
        lock = validate_public()
        print(
            f"validated WATCH supply {lock['contract_id']} {lock['contract_version']}"
        )
        return 0
    except (WatchSupplyError, OSError) as error:
        print(f"TAR WATCH supply validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
