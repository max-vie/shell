#!/usr/bin/env python3
"""Validate WATCH's source-only platform add-on contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "watch/contracts/platform-addons-requirements.json"
TAR_SCRIPTS = ROOT / "tar/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
import validate_platform_supply as platform_supply  # noqa: E402


class PlatformAddonsWatchError(ValueError):
    """WATCH platform add-on validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlatformAddonsWatchError(message)


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing {label}")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PlatformAddonsWatchError(f"invalid {label}") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(dict[str, Any], value)


def validate(path: Path = CONTRACT) -> dict[str, Any]:
    document = read_json(path, "platform add-on WATCH contract")
    require(
        set(document)
        == {
            "description",
            "schema_version",
            "contract_version",
            "contract_id",
            "policy_owner",
            "consumer_owners",
            "proof_status",
            "environment",
            "cluster",
            "supply",
            "add_ons",
            "evidence",
            "failure_policy",
        },
        "platform add-on WATCH shape changed",
    )
    require(
        document["schema_version"] == "1.0"
        and document["contract_version"] == "1.0.0"
        and document["contract_id"] == "platform-addons-requirements",
        "platform add-on WATCH identity changed",
    )
    require(
        document["policy_owner"] == "watch"
        and document["consumer_owners"] == ["make", "watch"]
        and document["proof_status"] == "source-only"
        and document["environment"] == "environment-gcp",
        "platform add-on WATCH ownership changed",
    )
    require(
        document["cluster"]
        == {
            "name": "gcp",
            "inventory_group": "gcp_k3s_servers",
            "first_server": "gcp-k3s-01",
            "first_server_address": "10.77.0.201",
            "nodes": ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"],
        },
        "platform add-on WATCH cluster changed",
    )
    require(
        document["supply"] == "tar/manifests/platform-addons-supply.json",
        "platform add-on WATCH supply changed",
    )
    supply = platform_supply.validate_platform()
    require(
        supply["service_routing"]["provider"]
        == "gcp-internal-proxy-network-load-balancer",
        "platform add-on WATCH routing changed",
    )
    require(
        document["add_ons"]
        == {
            "metallb": {
                "namespace": "metallb-system",
                "release": "metallb",
                "service_advertisements": [],
            },
            "longhorn": {
                "namespace": "longhorn-system",
                "release": "longhorn",
                "data_path": "/var/lib/longhorn",
                "storage_class": "longhorn",
                "default": True,
                "expected_nodes": 3,
                "default_replica_count": 3,
            },
        },
        "platform add-on WATCH policy changed",
    )
    require(
        document["evidence"]
        == [
            "three declared GCP K3s nodes are Ready",
            "MetalLB controller and speakers are ready without service advertisements",
            "three Longhorn nodes have ready and schedulable disks",
            "Longhorn is the only default storage class",
        ]
        and document["failure_policy"] == "read-only-diagnosis",
        "platform add-on WATCH evidence changed",
    )
    make_script = ROOT / "make/scripts/deploy_platform_addons.py"
    require(
        make_script.is_file() and not make_script.is_symlink(),
        "MAKE add-on source is missing",
    )
    source = make_script.read_text(encoding="utf-8")
    for fragment in (
        "environment-gcp/make/platform-addons",
        "k3s_transport",
        "/var/lib/longhorn",
    ):
        require(fragment in source, f"MAKE add-on source is missing: {fragment}")
    for forbidden in ("BGPPeer", "BGPAdvertisement", "L2Advertisement", "IPAddressPool"):
        require(forbidden not in source, f"MAKE add-on source contains {forbidden}")
    return document


def main() -> int:
    try:
        validate()
    except (OSError, PlatformAddonsWatchError, platform_supply.PlatformSupplyError) as error:
        print(f"WATCH platform add-on validation failed: {error}", file=sys.stderr)
        return 2
    print("validated WATCH platform add-on policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
