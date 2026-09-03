#!/usr/bin/env python3
"""Validate the TAR pins shared by scanning, audit, load, and transfer tools."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tar/scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "tar/scripts"))
import validate_delivery_supply as delivery  # noqa: E402
import validate_kubernetes_supply as kubernetes  # noqa: E402


EXPECTED = {
    "trivy": ("0.73.0", "docker.io/aquasec/trivy:0.73.0"),
    "kube-bench": ("0.16.0", "docker.io/aquasec/kube-bench:v0.16.0"),
    "k6": ("2.1.0", "docker.io/grafana/k6:2.1.0"),
}


class SecurityToolingError(ValueError):
    """The public security-tooling supply contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SecurityToolingError(message)


def validate() -> dict[str, Any]:
    try:
        lock = kubernetes.validate_public()
        delivery_lock = delivery.validate_lock()
    except (kubernetes.SupplyError, delivery.DeliverySupplyError) as error:
        raise SecurityToolingError(str(error)) from error

    tools = lock["tools"]
    for name, (version, image) in EXPECTED.items():
        entry = tools.get(name)
        require(
            isinstance(entry, dict)
            and entry.get("version") == version
            and entry.get("image") == image,
            f"{name} tool pin changed",
        )
        require(image in lock["images"], f"{name} image is not locked")
        require(
            lock["images"][image]["tag"] == image.rsplit(":", 1)[1]
            and lock["images"][image]["platform"] == "linux/amd64",
            f"{name} image metadata changed",
        )

    require(
        tools["skopeo"]
        == {
            "version": "1.22.2",
            "binary": "skopeo",
            "execution_host": "delivery-01",
            "authfile_mode": "0600",
            "preserve_digests": True,
        },
        "Skopeo transfer pin changed",
    )
    require(
        delivery_lock["provenance"]["registry_verification"]["tool"] == "skopeo"
        and delivery_lock["provenance"]["registry_verification"]["tool_version"]
        == tools["skopeo"]["version"],
        "Skopeo provenance changed",
    )
    return lock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        lock = validate()
        print(
            f"validated security tooling ({len(EXPECTED)} tools, "
            f"{len(lock['images'])} locked images)"
        )
        return 0
    except (OSError, KeyError, SecurityToolingError) as error:
        print(f"security tooling validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
