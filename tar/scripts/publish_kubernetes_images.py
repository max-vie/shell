#!/usr/bin/env python3
"""Transfer one locked Kubernetes image to Harbor through delivery-01."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]
MAKE_SCRIPTS = ROOT / "make/scripts"
if str(MAKE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(MAKE_SCRIPTS))
import register_forgejo_runner as delivery  # noqa: E402
import sops_helpers  # noqa: E402
import validate_harbor_robots  # noqa: E402

if str(ROOT / "tar/scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "tar/scripts"))
import validate_kubernetes_supply as supply  # noqa: E402
import validate_security_tooling  # noqa: E402


ROBOT_HANDOFF = ROOT / ".local/sudo/release-feed/harbor-robots.sops.json"
AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
APPROVAL = "environment-gcp/tar/skopeo-transfer"
DESTINATION_PREFIX = "registry.shell.internal/shell/system/"
IMAGE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ImageTransferError(RuntimeError):
    """Skopeo image transfer failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ImageTransferError(message)


def locked_source(lock: dict[str, Any], source: str) -> tuple[str, str]:
    entry = lock["images"].get(source)
    require(isinstance(entry, dict), "source image is not in the TAR lock")
    digest = entry.get("digest")
    require(isinstance(digest, str) and IMAGE_DIGEST.fullmatch(digest) is not None, "source image digest is invalid")
    return f"{source}@{digest}", digest


def expected_destination(source: str) -> str:
    repository, tag = source.rsplit(":", 1)
    name = repository.rsplit("/", 1)[-1]
    require(IMAGE_NAME.fullmatch(name) is not None, "source image name is unsafe")
    require(TAG.fullmatch(tag) is not None and tag != "latest", "source image tag is unsafe")
    return f"{DESTINATION_PREFIX}{name}:{tag}-amd64"


def validate_request(
    source: str, destination: str, lock: dict[str, Any] | None = None
) -> tuple[str, str]:
    lock = lock or supply.validate_public()
    source_ref, digest = locked_source(lock, source)
    require(destination == expected_destination(source), "destination does not match the locked image")
    require(destination.startswith(DESTINATION_PREFIX), "destination is outside the Harbor system project")
    require("@" not in destination and ":latest" not in destination, "destination must use one immutable tag")
    return source_ref, digest


def remote_command(source_ref: str, destination: str, digest: str) -> str:
    require(IMAGE_DIGEST.fullmatch(digest) is not None, "expected image digest is invalid")
    source = shlex.quote(source_ref)
    target = shlex.quote(destination)
    expected = shlex.quote(digest)
    return (
        "set -eu; IFS= read -r ROBOT_USER; IFS= read -r ROBOT_TOKEN; "
        'AUTH=$(mktemp); trap \'rm -f "$AUTH"\' EXIT INT HUP TERM; '
        'AUTH_B64=$(printf \'%s:%s\' "$ROBOT_USER" "$ROBOT_TOKEN" | base64 -w0); '
        'printf \'{"auths":{"registry.shell.internal":{"auth":"%s"}}}\\n\' "$AUTH_B64" > "$AUTH"; '
        f"if DEST_DIGEST=$(skopeo inspect --override-os linux --override-arch amd64 "
        f"--authfile \"$AUTH\" --format '{{{{.Digest}}}}' docker://{target} 2>/dev/null); then "
        f"test \"$DEST_DIGEST\" = {expected}; printf '%s\\n' \"$DEST_DIGEST\"; exit 0; fi; "
        f"skopeo copy --override-os linux --override-arch amd64 --preserve-digests "
        f"--authfile \"$AUTH\" docker://{source} docker://{target} >/dev/null; "
        f"DEST_DIGEST=$(skopeo inspect --override-os linux --override-arch amd64 "
        f"--authfile \"$AUTH\" --format '{{{{.Digest}}}}' docker://{target}); "
        f"test \"$DEST_DIGEST\" = {expected}; printf '%s\\n' \"$DEST_DIGEST\""
    )


def publisher() -> tuple[str, str]:
    validate_harbor_robots.validate()
    document = sops_helpers.decrypt_json(ROBOT_HANDOFF, AGE_KEY)
    item = document.get("publisher")
    require(isinstance(item, dict), "Harbor publisher handoff is missing")
    item = cast(dict[str, Any], item)
    username = item.get("username")
    password = item.get("password")
    require(
        isinstance(username, str) and bool(username) and isinstance(password, str) and bool(password),
        "Harbor publisher handoff is incomplete",
    )
    return cast(str, username), cast(str, password)


def publish(
    source: str,
    destination: str,
    approval: str,
    inventory: list[Path],
) -> dict[str, str]:
    lock = supply.validate_public()
    validate_security_tooling.validate()
    source_ref, digest = validate_request(source, destination, lock)
    require(approval == APPROVAL, f"approval must be {APPROVAL}")
    require(bool(inventory), "private INIT inventories are required")
    username, password = publisher()
    connection = delivery.resolve_connection(inventory)
    observed = delivery.ssh(
        remote_command(source_ref, destination, digest),
        connection,
        label=f"Skopeo Harbor transfer {destination.rsplit('/', 1)[-1]}",
        input_text=f"{username}\n{password}\n",
    ).strip()
    require(IMAGE_DIGEST.fullmatch(observed) is not None, "Harbor returned an invalid image digest")
    require(observed == digest, "Harbor image digest differs from the locked source")
    return {"source": source_ref, "destination": destination, "digest": observed}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preview", "publish"))
    parser.add_argument("--source")
    parser.add_argument("--destination")
    parser.add_argument("--approval", default="")
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    args = parser.parse_args(argv)
    try:
        lock = supply.validate_public()
        if args.action == "preview":
            print(json.dumps({"images": sorted(lock["images"]), "approval": APPROVAL}, sort_keys=True))
            return 0
        require(isinstance(args.source, str) and isinstance(args.destination, str), "--source and --destination are required")
        result = publish(args.source, args.destination, args.approval, args.inventory)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (
        OSError,
        ImageTransferError,
        sops_helpers.SopsError,
        delivery.RunnerError,
        validate_harbor_robots.HarborRobotError,
        supply.SupplyError,
        validate_security_tooling.SecurityToolingError,
    ) as error:
        print(f"TAR Skopeo transfer refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
