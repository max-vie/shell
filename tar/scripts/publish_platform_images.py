#!/usr/bin/env python3
"""Mirror the pinned OpenBao image into Harbor through delivery-01."""

from __future__ import annotations

import argparse
import json
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
ROBOT_HANDOFF = ROOT / ".local/sudo/release-feed/harbor-robots.sops.json"
AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
APPROVAL = "environment-gcp/tar/platform-images"
SOURCE = "quay.io/openbao/openbao@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0"
DESTINATION = "registry.shell.internal/shell/system/openbao:2.6.1"
EXPECTED = "sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0"


class ImagePublicationError(RuntimeError):
    """Platform image publication failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ImagePublicationError(message)


def publish(approval: str, inventory: list[Path]) -> dict[str, Any]:
    require(approval == APPROVAL, f"APPROVAL must be {APPROVAL}")
    raise ImagePublicationError(
        "platform image publication is blocked until Harbor routing and robot custody exist"
    )
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
    command = (
        "set -eu; IFS= read -r ROBOT_USER; IFS= read -r ROBOT_TOKEN; "
        "AUTH=$(mktemp); trap 'rm -f \"$AUTH\"' EXIT INT HUP TERM; "
        'AUTH_B64=$(printf \'%s:%s\' "$ROBOT_USER" "$ROBOT_TOKEN" | base64 -w0); '
        'printf \'{"auths":{"registry.shell.internal":{"auth":"%s"}}}\\n\' "$AUTH_B64" > "$AUTH"; '
        f'skopeo copy --preserve-digests --authfile "$AUTH" '
        f"docker://{SOURCE} docker://{DESTINATION} >/dev/null; "
        f"DIGEST=$(skopeo inspect --authfile \"$AUTH\" --format '{{{{.Digest}}}}' "
        f'docker://{DESTINATION}); test "$DIGEST" = {EXPECTED}; printf \'%s\\n\' "$DIGEST"'
    )
    digest = delivery.ssh(
        command,
        connection,
        label="OpenBao Harbor image publication",
        input_text=f"{username}\n{password}\n",
    ).strip()
    require(digest == EXPECTED, "Harbor returned an unexpected OpenBao image digest")
    return {
        "source": SOURCE,
        "destination": DESTINATION,
        "digest": digest,
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
        ImagePublicationError,
        sops_helpers.SopsError,
        supply.PlatformSupplyError,
        delivery.RunnerError,
    ) as error:
        print(f"TAR platform image publication failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
