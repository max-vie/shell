#!/usr/bin/env python3
"""Publish staged Argo CD and OpenBao charts into Harbor through delivery-01."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any, cast

MAKE_SCRIPTS = Path(__file__).resolve().parents[2] / "make/scripts"
if str(MAKE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(MAKE_SCRIPTS))
import sops_helpers  # noqa: E402
import validate_platform_supply as supply  # noqa: E402
import register_forgejo_runner as delivery  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
CHART_ROOT = ROOT / ".local/tar/platform-addons/charts"
ROBOT_HANDOFF = ROOT / ".local/sudo/release-feed/harbor-robots.sops.json"
AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
APPROVAL = "environment-gcp/tar/platform-charts"
CHARTS = ("argo-cd-10.1.4.tgz", "openbao-0.28.6.tgz")


class ChartPublicationError(RuntimeError):
    """Platform chart publication failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ChartPublicationError(message)


def run(command: list[str], *, label: str, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(  # nosec B603
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            cwd=ROOT,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ChartPublicationError(f"{label} could not complete") from error
    if result.returncode:
        raise ChartPublicationError(f"{label} failed")
    return result.stdout


def scp(local: Path, remote: str, connection: delivery.DeliveryConnection) -> None:
    require(
        local.is_file() and not local.is_symlink(), f"chart is missing: {local.name}"
    )
    run(
        [
            "scp",
            "-F",
            "/dev/null",
            "-q",
            *connection.options,
            str(local),
            f"{connection.target}:{remote}",
        ],
        label=f"transfer platform chart {local.name}",
    )


def publish(approval: str, inventory: list[Path]) -> dict[str, Any]:
    require(approval == APPROVAL, f"APPROVAL must be {APPROVAL}")
    raise ChartPublicationError(
        "platform chart publication is blocked until Helm provenance, isolated credentials, and Argo image pins exist"
    )
    supply.validate_staged(CHART_ROOT.parent)
    supply.validate_services()
    require(bool(inventory), "private INIT inventories are required")
    robots = sops_helpers.decrypt_json(ROBOT_HANDOFF, AGE_KEY)
    publisher = robots.get("publisher")
    require(isinstance(publisher, dict), "Harbor publisher handoff is missing")
    publisher = cast(dict[str, Any], publisher)
    username = publisher.get("username")
    password = publisher.get("password")
    require(
        isinstance(username, str) and isinstance(password, str),
        "Harbor publisher handoff is incomplete",
    )
    username = cast(str, username)
    password = cast(str, password)
    connection = delivery.resolve_connection(inventory)
    helm = shutil.which("helm")
    require(helm is not None, "local Helm client is missing")
    helm = cast(str, helm)
    helm_version = run(
        [helm, "version", "--short"], label="inspect Helm client"
    ).strip()
    require(
        re.fullmatch(r"v3\.18\.4(?:\+.*)?", helm_version) is not None,
        "local Helm client must be the locked v3.18.4 release",
    )
    remote_helm = "/tmp/shell-helm-platform"  # nosec B108
    run(
        [
            "scp",
            "-F",
            "/dev/null",
            "-q",
            *connection.options,
            helm,
            f"{connection.target}:{remote_helm}",
        ],
        label="transfer Helm client",
    )
    try:
        delivery.ssh(
            f"set -eu; chmod 0700 {remote_helm}",
            connection,
            label="prepare delivery Helm client",
        )
        for chart_name in CHARTS:
            source = CHART_ROOT / chart_name
            scp(source, f"/tmp/{chart_name}", connection)  # nosec B108
            delivery.ssh(
                "set -eu; IFS= read -r ROBOT_USER; IFS= read -r ROBOT_TOKEN; "
                "printf '%s' \"$ROBOT_TOKEN\" | "
                f"{remote_helm} registry login registry.shell.internal "
                '--username "$ROBOT_USER" --password-stdin >/dev/null; '
                f"{remote_helm} push /tmp/{chart_name} "
                "oci://registry.shell.internal/shell/charts >/dev/null; "
                f"rm -f -- /tmp/{chart_name}",
                connection,
                label=f"publish Harbor chart {chart_name}",
                input_text=f"{username}\n{password}\n",
            )
    finally:
        delivery.ssh(
            f"set -eu; rm -f -- {remote_helm}",
            connection,
            label="remove delivery Helm client",
        )
    return {
        "repository": "registry.shell.internal/shell/charts",
        "charts": list(CHARTS),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        print(json.dumps(publish(args.approval, args.inventory), sort_keys=True))
    except (
        OSError,
        ChartPublicationError,
        sops_helpers.SopsError,
        supply.PlatformSupplyError,
        delivery.RunnerError,
    ) as error:
        print(f"TAR platform chart publication failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
