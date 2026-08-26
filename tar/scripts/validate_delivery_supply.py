#!/usr/bin/env python3
"""Validate the public delivery image supply contract offline."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPOSITORY_ROOT / "tar/manifests/delivery-supply.json"
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_IMAGES = {
    "forgejo": {
        "repository": "codeberg.org/forgejo/forgejo",
        "tag": "16.0.3-rootless",
        "digest": "sha256:214f4ae63ee78be1e445e58573c88dc7215e72091210852e0df94eaac1a25685",
    },
    "forgejo_runner": {
        "repository": "data.forgejo.org/forgejo/runner",
        "tag": "13",
        "digest": "sha256:7fb853bfe73c229be6349398359c0a7bd01fadfd17c106607b2221150b799ed2",
    },
    "caddy": {
        "repository": "docker.io/library/caddy",
        "tag": "2.11.4-alpine",
        "digest": "sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648",
    },
    "node": {
        "repository": "docker.io/library/node",
        "tag": "24-bookworm",
        "digest": "sha256:4196d66a565c6f195728d9952f161f4adfe2ad753052a08b7ec7f1c5a6bda42b",
    },
}


class DeliverySupplyError(ValueError):
    """A delivery image supply contract is invalid or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DeliverySupplyError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def read_json_object(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing regular file: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeliverySupplyError(f"invalid JSON file: {path}") from error
    require(isinstance(value, dict), "delivery supply must be an object")
    return cast(dict[str, Any], value)


def validate_lock(path: Path = LOCK_PATH) -> dict[str, Any]:
    """Validate immutable delivery image references without writing state."""

    lock = read_json_object(path)
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
            "provenance",
            "runtime_image_platform",
            "images",
            "required_images",
        },
        "delivery supply lock shape changed",
    )
    require(lock["schema_version"] == "1.0", "delivery supply schema changed")
    require(lock["contract_version"] == "1.0.0", "delivery supply version changed")
    require(lock["contract_id"] == "delivery-supply", "delivery supply ID changed")
    require(lock["policy_owner"] == "tar", "TAR must own delivery supply")
    require(lock["execution_owner"] == "make", "MAKE must consume delivery supply")
    require(
        lock["proof_status"] == "source-reference-only",
        "delivery supply must remain source-reference-only",
    )
    require(
        lock["provenance"]
        == {
            "basis": "registry-inspection",
            "evidence_class": "operator-reported-source-observation",
            "registry_verification": {
                "status": "verified",
                "date": "2026-08-26",
                "tool": "skopeo",
                "tool_version": "1.22.2",
                "method": "inspect-with-linux-amd64-override",
                "platform": "linux/amd64",
            },
        },
        "delivery supply provenance changed",
    )
    require(lock["runtime_image_platform"] == "linux/amd64", "delivery platform changed")
    require(lock["required_images"] == list(EXPECTED_IMAGES), "required image set changed")

    images = lock["images"]
    require(isinstance(images, dict), "delivery images must be an object")
    require(set(images) == set(EXPECTED_IMAGES), "delivery image set changed")
    for name, image in images.items():
        require(
            isinstance(image, dict)
            and set(image) == {"repository", "tag", "digest"},
            f"delivery image shape changed: {name}",
        )
        require(
            isinstance(image["repository"], str)
            and "/" in image["repository"]
            and not image["repository"].startswith("http"),
            f"delivery image repository is invalid: {name}",
        )
        require(
            isinstance(image["tag"], str) and bool(image["tag"]),
            f"delivery image tag is invalid: {name}",
        )
        require(
            isinstance(image["digest"], str)
            and IMAGE_DIGEST_RE.fullmatch(image["digest"]) is not None,
            f"delivery image digest is invalid: {name}",
        )
    require(images == EXPECTED_IMAGES, "delivery image pins changed")
    return lock


def main(path: Path | None = None) -> int:
    try:
        validate_lock(LOCK_PATH if path is None else path)
    except DeliverySupplyError as error:
        print(f"delivery supply validation failed: {error}", file=sys.stderr)
        return 2
    print("validated delivery supply contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
