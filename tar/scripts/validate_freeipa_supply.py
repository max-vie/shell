#!/usr/bin/env python3
"""Validate the source-only TAR package contract for FreeIPA."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "tar/manifests/freeipa-supply.json"
EXPECTED_TOP_LEVEL = {
    "schema_version",
    "contract_version",
    "contract_id",
    "description",
    "policy_owner",
    "execution_owner",
    "proof_status",
    "environment",
    "consumer",
    "acquisition",
    "packages",
}
EXPECTED_ACQUISITION = {
    "mode": "native-dnf",
    "distribution": "AlmaLinux",
    "major_version": "9",
    "repository_family": "AlmaLinux 9 native repositories",
    "network_acquisition_owner": "init",
    "consumer_network_acquisition": True,
}
EXPECTED_PACKAGES = ["ipa-server", "ipa-server-dns", "samba-common-libs"]


class FreeIPASupplyError(ValueError):
    """The TAR FreeIPA package contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FreeIPASupplyError(message)


def read_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "FreeIPA supply lock is missing")

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
        raise FreeIPASupplyError("FreeIPA supply lock is invalid JSON") from error
    require(isinstance(document, dict), "FreeIPA supply lock must be an object")
    return cast(dict[str, Any], document)


def validate_public(path: Path = LOCK_PATH) -> dict[str, Any]:
    document = read_json(path)
    require(set(document) == EXPECTED_TOP_LEVEL, "FreeIPA supply lock shape changed")
    require(document["schema_version"] == "1.0", "FreeIPA supply schema changed")
    require(document["contract_version"] == "1.0.0", "FreeIPA supply version changed")
    require(document["contract_id"] == "freeipa-supply", "FreeIPA supply ID changed")
    require(bool(document["description"]), "FreeIPA supply description is empty")
    require(document["policy_owner"] == "tar", "TAR must own FreeIPA supply policy")
    require(document["execution_owner"] == "init", "INIT must consume FreeIPA supply")
    require(
        document["proof_status"] == "source-reference-only",
        "FreeIPA supply proof changed",
    )
    require(
        document["environment"] == "environment-gcp",
        "FreeIPA supply environment changed",
    )
    require(document["consumer"] == "identity-01", "FreeIPA supply consumer changed")
    require(
        document["acquisition"] == EXPECTED_ACQUISITION,
        "FreeIPA acquisition policy changed",
    )
    require(document["packages"] == EXPECTED_PACKAGES, "FreeIPA package set changed")
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=LOCK_PATH)
    args = parser.parse_args(argv)
    try:
        validate_public(args.lock)
    except (OSError, FreeIPASupplyError) as error:
        print(f"TAR FreeIPA supply validation failed: {error}", file=sys.stderr)
        return 2
    print("validated TAR FreeIPA package supply contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
