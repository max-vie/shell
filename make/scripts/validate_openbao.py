#!/usr/bin/env python3
"""Validate OpenBao's source-only GitOps boundary."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
VALUES = ROOT / "make/gitops/values/openbao.yaml"
APPLICATION = ROOT / "make/gitops/applications/children/openbao.yaml"
PLATFORM = ROOT / "make/gitops/platform/openbao"
CONTRACT = ROOT / "sudo/secrets/openbao-bootstrap-contract.json"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class OpenBaoValidationError(ValueError):
    """OpenBao source validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OpenBaoValidationError(message)


def validate() -> dict[str, Any]:
    require(VALUES.is_file() and not VALUES.is_symlink(), "OpenBao values are missing")
    require(
        APPLICATION.is_file() and not APPLICATION.is_symlink(),
        "OpenBao Application is missing",
    )
    require(
        CONTRACT.is_file() and not CONTRACT.is_symlink(),
        "OpenBao SUDO contract is missing",
    )
    try:
        values = yaml.safe_load(VALUES.read_text(encoding="utf-8"))
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        raise OpenBaoValidationError("OpenBao source is not parseable") from error
    require(isinstance(values, dict), "OpenBao values must be a mapping")
    require(values["global"]["tlsDisable"] is False, "OpenBao TLS must stay enabled")
    require(
        values["server"]["ha"]["raft"]["enabled"] is True,
        "OpenBao Raft must stay enabled",
    )
    require(values["server"]["ha"]["replicas"] == 3, "OpenBao must remain three-node")
    require(
        values["server"]["dataStorage"]["storageClass"] == "longhorn",
        "OpenBao data storage changed",
    )
    require(
        values["server"]["auditStorage"]["storageClass"] == "longhorn",
        "OpenBao audit storage changed",
    )
    require(
        values["server"]["service"]["type"] == "ClusterIP",
        "OpenBao must remain ClusterIP",
    )
    require(
        values["injector"]["enabled"] is False, "OpenBao injector is outside this slice"
    )
    require(values["csi"]["enabled"] is False, "OpenBao CSI is outside this slice")
    require(values["ui"]["enabled"] is False, "OpenBao UI is outside this slice")
    tag = values["server"]["image"]["tag"]
    require(
        isinstance(tag, str)
        and "@" in tag
        and DIGEST.fullmatch(tag.rsplit("@", 1)[1]) is not None,
        "OpenBao image must be digest pinned",
    )
    application = APPLICATION.read_text(encoding="utf-8")
    require(
        "registry.shell.internal/shell/charts" in application,
        "OpenBao must use the Harbor chart source",
    )
    require(
        "https://forgejo.shell.internal/shell/make.git" in application,
        "OpenBao must use the SHELL Forgejo source",
    )
    require('sync-wave: "30"' in application, "OpenBao sync wave changed")
    for path in PLATFORM.glob("*.yaml"):
        require(
            "keycloak" not in path.read_text(encoding="utf-8").lower(),
            "OpenBao source must not depend on Keycloak",
        )
    require(
        contract.get("cluster", {}).get("external_endpoint") is False,
        "OpenBao external endpoint must stay disabled",
    )
    require(
        contract.get("kubernetes_auth", {}).get("role") == "release-feed",
        "OpenBao release-feed role changed",
    )
    require(
        contract.get("initialization", {}).get("status")
        == "blocked-independent-custody-required"
        and contract.get("kubernetes_auth_inputs", {}).get("status") == "blocked",
        "OpenBao live bootstrap must remain blocked",
    )
    return values


def main() -> int:
    try:
        validate()
    except (OSError, OpenBaoValidationError) as error:
        print(f"MAKE OpenBao validation failed: {error}", file=sys.stderr)
        return 2
    print("validated OpenBao GitOps source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
