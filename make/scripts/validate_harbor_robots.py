#!/usr/bin/env python3
"""Validate the value-free Harbor robot handoff contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "make/contracts/harbor-robot-handoff.json"


class HarborRobotError(ValueError):
    """Harbor robot contract validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HarborRobotError(message)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def validate(path: Path = CONTRACT) -> dict[str, Any]:
    require(
        path.is_file() and not path.is_symlink(), "Harbor robot contract is missing"
    )
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_pairs
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarborRobotError("Harbor robot contract is invalid") from error
    require(isinstance(document, dict), "Harbor robot contract is not an object")
    require(
        set(document)
        == {
            "description",
            "schema_version",
            "contract_version",
            "contract_id",
            "policy_owner",
            "producer_owner",
            "consumer_owners",
            "environment",
            "endpoint",
            "private_handoff",
            "robots",
            "kubernetes_secrets",
            "platform_namespaces",
        },
        "Harbor robot contract shape changed",
    )
    require(
        document["schema_version"] == "1.0"
        and document["contract_version"] == "1.0.0",
        "Harbor robot contract version changed",
    )
    require(
        document["contract_id"] == "harbor-robot-handoff",
        "Harbor robot contract ID changed",
    )
    require(
        document["policy_owner"] == "sudo"
        and document["producer_owner"] == "make"
        and document["consumer_owners"] == ["make", "tar"],
        "Harbor robot ownership changed",
    )
    require(
        document["environment"] == "environment-gcp", "Harbor robot environment changed"
    )
    require(
        document["endpoint"]
        == {
            "hostname": "registry.shell.internal",
            "address": "10.77.0.221",
            "transport": "https",
        },
        "Harbor robot endpoint changed",
    )
    require(
        document["private_handoff"]
        == {
            "path": ".local/sudo/release-feed/harbor-robots.sops.json",
            "storage": "sops-age",
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
        },
        "Harbor robot custody changed",
    )
    require(
        document["robots"]
        == {
            "publisher": {"project": "shell", "permissions": ["pull", "push"]},
            "puller": {"project": "shell", "permissions": ["pull"]},
        },
        "Harbor robot permissions changed",
    )
    require(
        document["kubernetes_secrets"]
        == {"release-feed": "release-feed-pull", "platform": "shell-registry-pull"},
        "Harbor robot Kubernetes secret names changed",
    )
    require(
        document["platform_namespaces"]
        == ["argocd", "kyverno", "openbao", "release-feed"],
        "Harbor robot platform namespace set changed",
    )
    serialized = json.dumps(document)
    require(
        "password" not in serialized.lower(),
        "Harbor robot contract contains a password field",
    )
    require(
        "token" not in serialized.lower(),
        "Harbor robot contract contains a token field",
    )
    return document


def main() -> int:
    try:
        validate()
    except (OSError, HarborRobotError) as error:
        print(f"MAKE Harbor robot validation failed: {error}", file=sys.stderr)
        return 2
    print("validated Harbor robot handoff contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
