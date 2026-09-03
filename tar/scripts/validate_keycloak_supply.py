#!/usr/bin/env python3
"""Validate the source-only TAR image supply for Keycloak."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "tar/manifests/keycloak-supply.json"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE = re.compile(r"^[a-z0-9./_-]+:[A-Za-z0-9._-]+$")
RUNTIME = re.compile(
    r"^(?:quay\.io|docker\.io)/[a-z0-9/_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$"
)
EXPECTED_TOP_LEVEL = {
    "schema_version",
    "contract_version",
    "contract_id",
    "description",
    "policy_owner",
    "execution_owner",
    "proof_status",
    "environment",
    "staging",
    "images",
}
EXPECTED_STAGING = {
    "mode": "digest-locked-source-references",
    "network_acquisition_owner": "tar",
    "consumer_network_acquisition": False,
    "runtime_reference_mode": "upstream-digest",
}
EXPECTED_IMAGES = {
    "keycloak": {
        "source": "quay.io/keycloak/keycloak:26.7.2",
        "runtime": "quay.io/keycloak/keycloak:26.7.2@sha256:831330513f55695572286e521f94fcd3c7e285250ed5b848090265a33192f669",
        "platform": "linux/amd64",
        "digest": "sha256:831330513f55695572286e521f94fcd3c7e285250ed5b848090265a33192f669",
    },
    "postgresql": {
        "source": "docker.io/library/postgres:17.5-bookworm",
        "runtime": "docker.io/library/postgres:17.5-bookworm@sha256:fbcea1bd13b6a882cd6caa6b58db3ae5c102efe50ec625b3e2a5cbc50db5bfe4",
        "platform": "linux/amd64",
        "digest": "sha256:fbcea1bd13b6a882cd6caa6b58db3ae5c102efe50ec625b3e2a5cbc50db5bfe4",
    },
}


class KeycloakSupplyError(ValueError):
    """The Keycloak TAR supply contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KeycloakSupplyError(message)


def read_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "Keycloak supply lock is missing")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise KeycloakSupplyError("Keycloak supply lock is invalid JSON") from error
    require(isinstance(document, dict), "Keycloak supply lock must be an object")
    return cast(dict[str, Any], document)


def validate_public(path: Path = LOCK_PATH) -> dict[str, Any]:
    document = read_json(path)
    require(set(document) == EXPECTED_TOP_LEVEL, "Keycloak supply shape changed")
    require(document["schema_version"] == "1.0", "Keycloak supply schema changed")
    require(document["contract_version"] == "1.0.0", "Keycloak supply version changed")
    require(document["contract_id"] == "keycloak-supply", "Keycloak supply ID changed")
    require(bool(document["description"]), "Keycloak supply description is empty")
    require(document["policy_owner"] == "tar", "TAR must own Keycloak supply")
    require(document["execution_owner"] == "make", "MAKE must consume Keycloak supply")
    require(
        document["proof_status"] == "source-reference-only",
        "Keycloak supply proof changed",
    )
    require(document["environment"] == "environment-gcp", "Keycloak supply environment changed")
    require(document["staging"] == EXPECTED_STAGING, "Keycloak staging policy changed")
    require(document["images"] == EXPECTED_IMAGES, "Keycloak image pins changed")
    for name, image in document["images"].items():
        require(set(image) == {"source", "runtime", "platform", "digest"}, f"Keycloak {name} image shape changed")
        require(SOURCE.fullmatch(image["source"]) is not None, f"Keycloak {name} source changed")
        require(RUNTIME.fullmatch(image["runtime"]) is not None, f"Keycloak {name} runtime reference changed")
        require(image["platform"] == "linux/amd64", f"Keycloak {name} platform changed")
        require(DIGEST.fullmatch(image["digest"]) is not None, f"Keycloak {name} digest changed")
        require(image["digest"] in image["runtime"], f"Keycloak {name} runtime digest changed")
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=LOCK_PATH)
    args = parser.parse_args(argv)
    try:
        validate_public(args.lock)
    except (OSError, KeycloakSupplyError) as error:
        print(f"TAR Keycloak supply validation failed: {error}", file=sys.stderr)
        return 2
    print("validated TAR Keycloak image supply contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
