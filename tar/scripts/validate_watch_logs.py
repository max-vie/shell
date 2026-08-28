#!/usr/bin/env python3
"""Validate the source-only TAR supply for WATCH logs."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPOSITORY_ROOT / "tar/manifests/watch-logs-supply.json"
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_CHARTS = {
    "loki": {
        "repository": "https://grafana-community.github.io/helm-charts",
        "name": "loki",
        "version": "18.11.2",
        "source": "https://github.com/grafana-community/helm-charts/releases/download/loki-18.11.2/loki-18.11.2.tgz",
        "size_bytes": 196037,
        "sha256": "0848bc2a40bbb8c78d8830fdf2fa79596db395a0d33d539d94c9669d9acc1c59",
    },
    "alloy": {
        "repository": "https://grafana.github.io/helm-charts",
        "name": "alloy",
        "version": "1.11.1",
        "source": "https://github.com/grafana/helm-charts/releases/download/alloy-1.11.1/alloy-1.11.1.tgz",
        "size_bytes": 32214,
        "sha256": "cc4cd48a885c070fe8b2929971552852375c11e92d95fc6337d0c3fa277ac575",
    },
}
EXPECTED_IMAGE_DIGESTS = {
    "docker.io/grafana/loki:3.7.6": "sha256:83c76da7858a8f4f88117ac521864ac33896fdae7a352a1df4068556e7513f64",
    "docker.io/nginxinc/nginx-unprivileged:1.31-alpine": "sha256:f652dfb31ebafe499d61adcbbf6007d898b64cb11234bc6ff864fbbc3ca043b8",
    "docker.io/grafana/alloy:v1.18.1": "sha256:754409730f1a4ed9781f8a2ea3b6a8c55750ee125a267ecf8fb449f9a25c109a",
    "quay.io/prometheus-operator/prometheus-config-reloader:v0.91.0": "sha256:7d9e4eea5f1139e602508871f422b0116c60e87c662f3dcd234d5ab60cd0d8c1",
}


class WatchLogsSupplyError(ValueError):
    """The WATCH logs artifact supply contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchLogsSupplyError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def read_lock(path: Path = LOCK_PATH) -> dict[str, Any]:
    require(
        path.is_file() and not path.is_symlink(),
        "TAR WATCH logs supply lock is missing",
    )
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WatchLogsSupplyError(
            "TAR WATCH logs supply lock is not valid JSON"
        ) from error
    require(isinstance(value, dict), "TAR WATCH logs supply lock must be an object")
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
        "TAR WATCH logs supply lock shape changed",
    )
    require(lock["schema_version"] == "1.0", "TAR WATCH logs schema changed")
    require(lock["contract_version"] == "2.0.0", "TAR WATCH logs version changed")
    require(lock["contract_id"] == "watch-logs-supply", "TAR WATCH logs ID changed")
    require(lock["policy_owner"] == "tar", "TAR must own WATCH logs supply")
    require(lock["execution_owner"] == "make", "MAKE must consume WATCH logs supply")
    require(
        lock["proof_status"] == "source-reference-only",
        "TAR WATCH logs proof changed",
    )
    require(
        lock["environment"] == "environment-gcp", "TAR WATCH logs environment changed"
    )
    require(
        lock["runtime_image_platform"] == "linux/amd64",
        "TAR WATCH logs platform changed",
    )
    require(
        lock["staging"]
        == {
            "mode": "local-verified-artifacts",
            "network_acquisition_owner": "tar",
            "consumer_network_acquisition": False,
            "artifact_directory": "watch",
            "chart_cache_layout": "charts/{name}-{version}.tgz",
        },
        "TAR WATCH logs staging boundary changed",
    )
    require(lock["charts"] == EXPECTED_CHARTS, "TAR WATCH logs chart pins changed")
    required = lock["required_runtime_images"]
    persistent = lock["persistent_runtime_images"]
    runtime = lock["runtime_image_digests"]
    require(
        required == list(EXPECTED_IMAGE_DIGESTS), "TAR WATCH logs image set changed"
    )
    require(persistent == required, "TAR WATCH logs persistent image set changed")
    require(set(runtime) == set(required), "TAR WATCH logs digest set changed")
    require(runtime == EXPECTED_IMAGE_DIGESTS, "TAR WATCH logs image digests changed")
    for image, digest in runtime.items():
        require(
            isinstance(image, str) and ":" in image,
            "TAR WATCH logs image reference is invalid",
        )
        require(
            isinstance(digest, str) and IMAGE_DIGEST_RE.fullmatch(digest) is not None,
            "TAR WATCH logs image digest is invalid",
        )
    return lock


def main() -> int:
    try:
        lock = validate_public()
        print(
            f"validated WATCH logs supply {lock['contract_id']} {lock['contract_version']}"
        )
        return 0
    except (WatchLogsSupplyError, OSError) as error:
        print(f"TAR WATCH logs supply validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
