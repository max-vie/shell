#!/usr/bin/env python3
"""Build locally and publish the release-feed image through delivery-01."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

MAKE_SCRIPTS = Path(__file__).resolve().parents[2] / "make/scripts"
if str(MAKE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(MAKE_SCRIPTS))
import sops_helpers  # noqa: E402
import validate_release_feed as supply  # noqa: E402
import register_forgejo_runner as delivery  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT / "make/apps/release-feed"
ROBOT_HANDOFF = ROOT / ".local/sudo/release-feed/harbor-robots.sops.json"
AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
APPROVAL = "environment-gcp/tar/release-feed-publication"
IMAGE = "registry.shell.internal/shell/release-feed"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# Remote mktemp results are regex-validated before use.
REMOTE_TMP = "/tmp"  # nosec B108


class PublicationError(RuntimeError):
    """Release-feed image publication failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicationError(message)


def run(command: list[str], *, label: str, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(  # nosec B603
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            cwd=ROOT,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PublicationError(f"{label} could not complete") from error
    if result.returncode:
        raise PublicationError(f"{label} failed")
    return result.stdout


def source_revision() -> str:
    value = run(["git", "rev-parse", "HEAD"], label="source revision").strip()
    require(
        re.fullmatch(r"[0-9a-f]{40}", value) is not None,
        "source revision is invalid",
    )
    require(
        run(["git", "status", "--porcelain"], label="source cleanliness").strip() == "",
        "release-feed publication requires a clean source tree",
    )
    return value


def scp(local: Path, remote: str, connection: delivery.DeliveryConnection) -> None:
    require(
        local.is_file() and not local.is_symlink(),
        "release-feed archive is missing",
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
        label="release-feed archive transfer",
    )


def publish(approval: str, inventory: list[Path]) -> dict[str, Any]:
    require(approval == APPROVAL, f"APPROVAL must be {APPROVAL}")
    raise PublicationError(
        "release-feed publication is blocked until immutable tags and a promotion handoff exist"
    )
    require(
        APP_ROOT.is_dir() and not APP_ROOT.is_symlink(),
        "release-feed source is missing",
    )
    supply.validate()
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
    revision = source_revision()
    local_tag = f"localhost/release-feed:{revision}"
    with tempfile.TemporaryDirectory(prefix="shell-release-feed-publish-") as directory:
        archive = Path(directory) / "release-feed.oci.tar"
        run(
            [
                "podman",
                "build",
                "--pull=never",
                "--format",
                "oci",
                "--build-arg",
                f"APP_VERSION={revision}",
                "--tag",
                local_tag,
                str(APP_ROOT),
            ],
            label="release-feed image build",
        )
        run(
            [
                "trivy",
                "image",
                "--exit-code",
                "1",
                "--severity",
                "HIGH,CRITICAL",
                "--ignore-unfixed",
                local_tag,
            ],
            label="release-feed vulnerability scan",
        )
        run(
            [
                "podman",
                "save",
                "--format",
                "oci-archive",
                "--output",
                str(archive),
                local_tag,
            ],
            label="release-feed OCI archive",
        )
        remote_directory = delivery.ssh(
            f"set -eu; umask 077; mktemp -d {REMOTE_TMP}/shell-release-feed.XXXXXX",
            connection,
            label="release-feed remote staging",
        ).strip()
        require(
            re.fullmatch(
                rf"{re.escape(REMOTE_TMP)}/shell-release-feed\.[A-Za-z0-9]+",
                remote_directory,
            )
            is not None,
            "release-feed remote staging path is unsafe",
        )
        remote_path = f"{remote_directory}/release-feed.oci.tar"
        try:
            scp(archive, remote_path, connection)
            command = (
                "set -eu; IFS= read -r ROBOT_USER; IFS= read -r ROBOT_TOKEN; "
                'AUTH=$(mktemp); trap \'rm -f "$AUTH"\' EXIT INT HUP TERM; '
                'AUTH_B64=$(printf \'%s:%s\' "$ROBOT_USER" "$ROBOT_TOKEN" | base64 -w0); '
                'printf \'{"auths":{"registry.shell.internal":{"auth":"%s"}}}\\n\' "$AUTH_B64" > "$AUTH"; '
                f'skopeo copy --preserve-digests --authfile "$AUTH" '
                f"oci-archive:{remote_path} docker://{IMAGE}:{revision} >/dev/null; "
                f"skopeo inspect --authfile \"$AUTH\" --format '{{{{.Digest}}}}' "
                f"docker://{IMAGE}:{revision}"
            )
            digest = delivery.ssh(
                command,
                connection,
                label="release-feed Harbor publication",
                input_text=f"{username}\n{password}\n",
            ).strip()
        finally:
            delivery.ssh(
                f"set -eu; rm -rf -- {shlex.quote(remote_directory)}",
                connection,
                label="release-feed remote cleanup",
            )
    require(
        DIGEST.fullmatch(digest) is not None,
        "Harbor returned an invalid image digest",
    )
    return {
        "source_revision": revision,
        "image": IMAGE,
        "tag": revision,
        "digest": digest,
        "scan_required": True,
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
        PublicationError,
        sops_helpers.SopsError,
        supply.ReleaseFeedSupplyError,
        delivery.RunnerError,
    ) as error:
        print(f"TAR release-feed publication failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
