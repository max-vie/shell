#!/usr/bin/env python3
"""Validate the source-only platform add-on and service supply locks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[1]
PLATFORM_LOCK = ROOT / "manifests/platform-addons-supply.json"
SERVICE_LOCK = ROOT / "manifests/platform-services-supply.json"
HARBOR_LOCK = ROOT / "manifests/harbor-supply.json"
HARBOR_VALUES = ROOT / "manifests/harbor-values.json"
HEX = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class PlatformSupplyError(ValueError):
    """A platform supply contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlatformSupplyError(message)


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing {label}")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PlatformSupplyError(f"invalid {label}") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(dict[str, Any], value)


def validate_chart(chart: Any, label: str) -> None:
    require(isinstance(chart, dict), f"{label} must be an object")
    require(
        set(chart) >= {"repository", "name", "version", "source", "sha256"},
        f"{label} shape changed",
    )
    require(
        isinstance(chart["name"], str) and bool(chart["name"]),
        f"{label} name missing",
    )
    require(
        isinstance(chart["version"], str)
        and re.fullmatch(r"[0-9A-Za-z.+-]+", chart["version"]) is not None,
        f"{label} version changed",
    )
    require(
        isinstance(chart["sha256"], str) and HEX.fullmatch(chart["sha256"]) is not None,
        f"{label} checksum changed",
    )
    require(
        isinstance(chart["source"], str) and chart["source"].startswith("https://"),
        f"{label} source must use HTTPS",
    )


def validate_platform(path: Path = PLATFORM_LOCK) -> dict[str, Any]:
    lock = read_json(path, "platform add-on supply")
    require(lock["schema_version"] == "1.0", "platform add-on schema changed")
    require(
        lock["contract_id"] == "platform-addons-supply", "platform add-on ID changed"
    )
    require(lock["policy_owner"] == "tar", "TAR must own platform add-on supply")
    require(lock["execution_owner"] == "make", "MAKE must consume platform supply")
    require(lock["environment"] == "environment-gcp", "platform environment changed")
    require(lock["k3s_version"] == "v1.34.10+k3s1", "K3s version changed")
    require(
        lock["controller_tools"] == {"helm": "3.18.4"},
        "platform controller tool pin changed",
    )
    require(
        lock["service_addresses"]
        == {
            "proxmox_host": "10.77.0.220",
            "harbor": "10.77.0.221",
            "release_feed": "10.77.0.222",
        },
        "platform service addresses changed",
    )
    require(set(lock["charts"]) == {"metallb", "longhorn"}, "platform chart set changed")
    for name, chart in lock["charts"].items():
        validate_chart(chart, f"platform {name} chart")
    images = lock["runtime_image_digests"]
    require(
        isinstance(images, dict) and bool(images),
        "platform add-on image pins missing",
    )
    require(
        all(DIGEST.fullmatch(value) is not None for value in images.values()),
        "platform add-on image digest changed",
    )
    return lock


def image_references(value: Any) -> list[tuple[str, str]]:
    if isinstance(value, dict):
        result: list[tuple[str, str]] = []
        repository = value.get("repository")
        tag = value.get("tag")
        if isinstance(repository, str) and isinstance(tag, str):
            result.append((repository, tag))
        for item in value.values():
            result.extend(image_references(item))
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(image_references(item))
        return result
    return []


def validate_harbor(path: Path = HARBOR_LOCK) -> dict[str, Any]:
    lock = read_json(path, "Harbor supply")
    require(lock["contract_id"] == "harbor-supply", "Harbor ID changed")
    require(
        lock["policy_owner"] == "tar" and lock["execution_owner"] == "make",
        "Harbor ownership changed",
    )
    validate_chart(lock["chart"], "Harbor chart")
    require(
        lock["endpoint"]
        == {
            "hostname": "registry.shell.internal",
            "address": "10.77.0.221",
            "transport": "https",
        },
        "Harbor endpoint changed",
    )
    require(set(lock["profiles"]) == {"full"}, "Harbor profile set changed")
    require(
        lock["profiles"]["full"]["trivy"] is True,
        "Harbor full profile must enable Trivy",
    )
    images = lock["runtime_image_digests"]
    require(isinstance(images, dict) and len(images) == 10, "Harbor image set changed")
    require(
        all(DIGEST.fullmatch(value) for value in images.values()),
        "Harbor image digest changed",
    )
    values = read_json(HARBOR_VALUES, "Harbor full values")
    require(
        values["expose"]["loadBalancer"]["IP"] == "10.77.0.221",
        "Harbor values address changed",
    )
    require(
        values["externalURL"] == "https://registry.shell.internal", "Harbor URL changed"
    )
    require(values["trivy"]["enabled"] is True, "Harbor values must enable Trivy")
    require(
        values["persistence"]["enabled"] is True,
        "Harbor persistence must remain enabled",
    )
    references: dict[str, str] = {}
    for repository, tag in image_references(values):
        tag_name, separator, digest = tag.partition("@")
        key = f"{repository}:{tag_name}"
        require(separator == "@", f"Harbor image lacks a digest: {key}")
        require(key not in references, f"Harbor image is duplicated: {key}")
        references[key] = digest
    require(set(references) == set(images), "Harbor values and image lock differ")
    for key, digest in references.items():
        require(digest == images[key], f"Harbor image digest changed: {key}")
    return lock


def validate_services(path: Path = SERVICE_LOCK) -> dict[str, Any]:
    lock = read_json(path, "platform services supply")
    require(
        lock["contract_id"] == "platform-services-supply",
        "platform services ID changed",
    )
    require(
        lock["policy_owner"] == "tar" and lock["execution_owner"] == "make",
        "platform services ownership changed",
    )
    require(
        lock["environment"] == "environment-gcp",
        "platform services environment changed",
    )
    require(
        set(lock["charts"]) == {"harbor", "argo-cd", "openbao"},
        "platform service chart set changed",
    )
    for name, chart in lock["charts"].items():
        validate_chart(chart, f"platform service {name} chart")
    require(
        lock["image_resolution"]["argo_cd"]
        == "blocked-unresolved-runtime-images",
        "Argo image resolution policy changed",
    )
    for name, relative in (
        ("harbor", "tar/manifests/harbor-supply.json"),
        ("release_feed", "tar/manifests/release-feed-supply.json"),
    ):
        require(
            lock["image_resolution"][name] == relative
            and (ROOT.parent / relative).is_file(),
            f"platform {name} supply reference changed",
        )
    images = lock["runtime_image_digests"]
    require(
        images
        == {
            "quay.io/openbao/openbao:2.6.1": "sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0"
        },
        "OpenBao image pin changed",
    )
    return lock


def validate_staged(local_root: Path) -> None:
    validate_platform()
    validate_services()
    validate_harbor()
    for lock_path in (PLATFORM_LOCK, SERVICE_LOCK):
        lock = read_json(lock_path, "supply")
        for chart in lock["charts"].values():
            path = local_root / "charts" / f"{chart['name']}-{chart['version']}.tgz"
            require(
                path.is_file() and not path.is_symlink(),
                f"staged chart missing: {path.name}",
            )
            require(
                hashlib.sha256(path.read_bytes()).hexdigest() == chart["sha256"],
                f"staged chart checksum changed: {path.name}",
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-root", type=Path)
    args = parser.parse_args(argv)
    try:
        validate_platform()
        validate_services()
        validate_harbor()
        if args.staged_root is not None:
            validate_staged(args.staged_root)
    except (KeyError, OSError, TypeError, PlatformSupplyError) as error:
        print(f"TAR platform supply validation failed: {error}", file=sys.stderr)
        return 2
    print("validated TAR platform service supply")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
