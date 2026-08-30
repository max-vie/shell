#!/usr/bin/env python3
"""Validate the unpromoted release-feed image supply contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "manifests/release-feed-supply.json"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReleaseFeedSupplyError(ValueError):
    """The release-feed supply contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseFeedSupplyError(message)


def read_lock(path: Path = LOCK) -> dict[str, Any]:
    require(
        path.is_file() and not path.is_symlink(),
        "release-feed supply lock is missing",
    )

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseFeedSupplyError("release-feed supply lock is invalid") from error
    require(isinstance(document, dict), "release-feed supply lock must be an object")
    return cast(dict[str, Any], document)


def validate(path: Path = LOCK) -> dict[str, Any]:
    lock = read_lock(path)
    require(
        set(lock)
        == {
            "description",
            "schema_version",
            "contract_version",
            "contract_id",
            "policy_owner",
            "execution_owner",
            "environment",
            "image_repository",
            "image_platform",
            "image_digest",
            "source_state",
            "base_image",
            "kubernetes_manifest",
            "scan_required",
            "publication",
        },
        "release-feed supply shape changed",
    )
    require(lock["schema_version"] == "1.0", "release-feed supply schema changed")
    require(
        lock["contract_version"] == "1.0.0",
        "release-feed supply version changed",
    )
    require(
        lock["contract_id"] == "release-feed-supply",
        "release-feed supply ID changed",
    )
    require(
        lock["policy_owner"] == "tar" and lock["execution_owner"] == "make",
        "release-feed supply ownership changed",
    )
    require(
        lock["environment"] == "environment-gcp",
        "release-feed supply environment changed",
    )
    require(
        lock["image_repository"] == "registry.shell.internal/shell/release-feed",
        "release-feed repository changed",
    )
    require(lock["image_platform"] == "linux/amd64", "release-feed platform changed")
    require(lock["image_digest"] is None, "release-feed digest must remain unpromoted")
    require(lock["source_state"] == "unpromoted", "release-feed source state changed")
    require(
        lock["base_image"]
        == {
            "repository": "cgr.dev/chainguard/python",
            "digest": "sha256:d812438658b47b73cb4c089f4cca09bca1ba50f6cd1843133864ee074d9ec49b",
        },
        "release-feed base image changed",
    )
    require(
        DIGEST.fullmatch(lock["base_image"]["digest"]) is not None,
        "release-feed base image digest is invalid",
    )
    manifest = ROOT / lock["kubernetes_manifest"]
    require(
        manifest.is_file() and not manifest.is_symlink(),
        "release-feed Kubernetes manifest is missing",
    )
    require(lock["scan_required"] is True, "release-feed scan requirement removed")
    require(
        lock["publication"]
        == {
            "build_context": "make/apps/release-feed",
            "delivery_host": "delivery-01",
            "preserve_digests": True,
            "overwrite": False,
        },
        "release-feed publication policy changed",
    )
    return lock


def main() -> int:
    try:
        validate()
    except (KeyError, OSError, TypeError, ReleaseFeedSupplyError) as error:
        print(f"TAR release-feed validation failed: {error}", file=sys.stderr)
        return 2
    print("validated unpromoted release-feed supply contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
