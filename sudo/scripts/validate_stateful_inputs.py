#!/usr/bin/env python3
"""Validate SUDO's value-free registry, workload, and OpenBao contracts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]
RELEASE_FEED = ROOT / "sudo/secrets/release-feed-input-contract.json"
OPENBAO = ROOT / "sudo/secrets/openbao-bootstrap-contract.json"
PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


class StatefulInputError(ValueError):
    """A SUDO stateful-input contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StatefulInputError(message)


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, f"duplicate JSON key in {label}: {key}")
            value[key] = item
        return value

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StatefulInputError(f"{label} is invalid JSON") from error
    require(isinstance(document, dict), f"{label} must be an object")
    return cast(dict[str, Any], document)


def validate_common(document: dict[str, Any], contract_id: str, label: str) -> None:
    require(document.get("schema_version") == "1.0", f"{label} schema changed")
    require(document.get("contract_version") == "1.0.0", f"{label} version changed")
    require(document.get("contract_id") == contract_id, f"{label} ID changed")
    require(isinstance(document.get("description"), str), f"{label} description changed")
    require(document.get("policy_owner") == "sudo", f"{label} owner changed")
    require(document.get("consumer_owners") == ["make"], f"{label} consumer changed")
    require(document.get("proof_status") == "source-only", f"{label} proof changed")
    require(
        document.get("environment") == "environment-gcp", f"{label} environment changed"
    )


def validate_custody(custody: Any, label: str, root: str) -> None:
    require(
        custody
        == {
            "root": root,
            "storage": "sops-age",
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
        }
        or custody
        == {
            "root": root,
            "storage": "sops-age",
            "ignored": True,
            "directory_mode": "0700",
            "file_mode": "0600",
            "plaintext_values_tracked": False,
            "publication": "create-only",
        },
        f"{label} private custody changed",
    )


def validate_release_feed(path: Path = RELEASE_FEED) -> dict[str, Any]:
    document = read_json(path, "release-feed input contract")
    require(
        set(document)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "consumer_owners",
            "proof_status",
            "environment",
            "private_custody",
            "inputs",
            "repository_policy",
        },
        "release-feed input shape changed",
    )
    validate_common(document, "release-feed-input-contract", "release-feed input")
    validate_custody(
        document["private_custody"], "release-feed input", ".local/sudo/release-feed"
    )
    inputs = document["inputs"]
    require(
        isinstance(inputs, dict)
        and set(inputs) == {"harbor", "release_feed", "harbor_robots", "age_key"},
        "release-feed input set changed",
    )
    inputs = cast(dict[str, Any], inputs)
    for name, expected_path in (
        ("harbor", ".local/sudo/release-feed/input-set/harbor.sops.json"),
        (
            "release_feed",
            ".local/sudo/release-feed/input-set/release-feed.sops.json",
        ),
    ):
        item = inputs[name]
        require(
            isinstance(item, dict)
            and set(item) == {"path", "storage", "phase", "required_keys"}
            and item["path"] == expected_path
            and item["storage"] == "sops-age"
            and item["phase"]
            == ("before-harbor" if name == "harbor" else "before-openbao-bootstrap")
            and PATH_RE.fullmatch(item["path"]) is not None,
            f"release-feed {name} input changed",
        )
        expected_keys = (
            [
                "admin_password",
                "core_key",
                "core_xsrf_key",
                "jobservice_secret",
                "registry_http_secret",
                "database_password",
                "registry_username",
                "registry_password",
            ]
            if name == "harbor"
            else ["read_token", "write_token"]
        )
        require(
            item["required_keys"] == expected_keys, f"release-feed {name} keys changed"
        )
    robots = inputs["harbor_robots"]
    require(
        isinstance(robots, dict)
        and set(robots)
        == {"path", "storage", "producer", "consumers", "phase", "required_keys"}
        and robots["path"] == ".local/sudo/release-feed/harbor-robots.sops.json"
        and robots["storage"] == "sops-age"
        and robots["producer"] == "make-after-harbor-bootstrap"
        and robots["consumers"] == ["make", "tar"]
        and robots["phase"] == "after-harbor"
        and robots["required_keys"] == ["publisher", "puller"],
        "release-feed Harbor robot handoff changed",
    )
    age_key = inputs["age_key"]
    require(
        age_key
        == {
            "path": ".local/sudo/release-feed/age-key.txt",
            "storage": "plaintext-age-identity",
            "consumer": "SOPS_AGE_KEY_FILE",
            "ignored": True,
            "file_mode": "0600",
        },
        "release-feed age key boundary changed",
    )
    require(
        document["repository_policy"]
        == {"contract_tracked": True, "private_values_tracked": False},
        "release-feed repository policy changed",
    )
    return document


def validate_openbao(path: Path = OPENBAO) -> dict[str, Any]:
    document = read_json(path, "OpenBao bootstrap contract")
    require(
        set(document)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "consumer_owners",
            "proof_status",
            "environment",
            "private_custody",
            "cluster",
            "initialization",
            "kubernetes_auth_inputs",
            "kubernetes_auth",
        },
        "OpenBao bootstrap shape changed",
    )
    validate_common(document, "openbao-bootstrap-contract", "OpenBao bootstrap")
    validate_custody(
        document["private_custody"], "OpenBao bootstrap", ".local/sudo/openbao"
    )
    require(
        document["cluster"]
        == {
            "name": "gcp",
            "service": "openbao-active.openbao.svc.cluster.local",
            "port": 8200,
            "tls_required": True,
            "external_endpoint": False,
        },
        "OpenBao cluster boundary changed",
    )
    require(
        document["initialization"]
        == {
            "status": "blocked-independent-custody-required",
            "shares": 5,
            "threshold": 3,
            "storage": "sops-age",
            "required_outputs": ["root_token", "unseal_shares", "release_feed_role"],
        },
        "OpenBao initialization policy changed",
    )
    require(
        document["kubernetes_auth_inputs"]
        == {
            "status": "blocked",
            "reason": "K3s API CA and reviewer identity handoffs are not implemented",
        },
        "OpenBao Kubernetes auth inputs changed",
    )
    require(
        document["kubernetes_auth"]
        == {
            "mount": "auth/kubernetes",
            "role": "release-feed",
            "service_account": "release-feed",
            "namespace": "release-feed",
            "audience": "openbao",
            "policy": "release-feed",
        },
        "OpenBao Kubernetes auth boundary changed",
    )
    return document


def main() -> int:
    try:
        validate_release_feed()
        validate_openbao()
    except (KeyError, OSError, TypeError, StatefulInputError) as error:
        print(f"SUDO stateful-input validation failed: {error}", file=sys.stderr)
        return 2
    print("validated SUDO stateful input contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
