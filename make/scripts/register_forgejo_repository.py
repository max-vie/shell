#!/usr/bin/env python3
"""Register SHELL's Forgejo repository and encrypt its bot credential.

This controller-side script uses the existing MAKE runner transport: the
fixed INIT inventory reaches ``delivery-01`` through the reviewed IAP route,
and the delivery helper keeps credentials out of command arguments. The
repository handoff contains only the credential contract values and is always
written as a mode-0600 SOPS/age file.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import shlex
import sys
from pathlib import Path
from typing import Any, cast

import register_forgejo_runner as delivery


REPOSITORY_ROOT = delivery.REPOSITORY_ROOT
DEFAULT_BOOTSTRAP = REPOSITORY_ROOT / ".local/sudo/delivery/bootstrap.sops.json"
DEFAULT_AGE_KEY = REPOSITORY_ROOT / ".local/sudo/delivery/age-key.txt"
DEFAULT_REPOSITORY_HANDOFF = (
    REPOSITORY_ROOT / ".local/sudo/delivery/forgejo-repository.sops.json"
)
DEFAULT_INVENTORY = delivery.DEFAULT_INVENTORY
DEFAULT_CONNECTION_INVENTORY = delivery.DEFAULT_CONNECTION_INVENTORY

DELIVERY_NODE = delivery.DELIVERY_NODE
DELIVERY_URL = delivery.DELIVERY_URL
DELIVERY_FQDN = delivery.DELIVERY_FQDN
PLATFORM_CA = delivery.PLATFORM_CA
REPOSITORY_APPROVAL = "environment-gcp/make/forgejo-repository"

ORG_NAME = "shell"
REPOSITORY_NAME = "make"
BOT_USERNAME = "shell-make"
BOT_EMAIL = "shell-make@shell.internal"
REPOSITORY_URL = f"{DELIVERY_URL}/{ORG_NAME}/{REPOSITORY_NAME}.git"
TOKEN_NAME = "make-repo"  # nosec B105 - this is a public token label
TOKEN_SCOPES = ["write:repository"]
TOKEN_REPOSITORIES = [{"owner": ORG_NAME, "name": REPOSITORY_NAME}]
WORKFLOW_PATH = ".forgejo/workflows/ci.yml"
WORKFLOW_CONTENT = """name: ci
on:
  push:
    branches: [main]
jobs:
  validate:
    runs-on: docker
    steps:
      - uses: actions/checkout@v4
      - run: test -f README.md
"""
README_CONTENT = "# shell/make\n\nMAKE-owned delivery repository.\n"


class RepositoryError(RuntimeError):
    """Repository registration input or operation is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RepositoryError(message)


def bootstrap_admin(document: dict[str, Any]) -> tuple[str, str]:
    require(document.get("class") == "forgejo_bootstrap", "bootstrap class changed")
    values = document.get("forgejo_bootstrap")
    require(isinstance(values, dict), "bootstrap payload must be an object")
    values = cast(dict[str, Any], values)
    username = values.get("admin_username")
    password = values.get("admin_password")
    if not isinstance(username, str) or not username:
        raise RepositoryError("bootstrap admin username is missing")
    if not isinstance(password, str) or not password:
        raise RepositoryError("bootstrap admin password is missing")
    require("\n" not in username and "\r" not in username, "bootstrap username contains a newline")
    require("\n" not in password and "\r" not in password, "bootstrap password contains a newline")
    return username, password


def validate_repository_document(document: dict[str, Any]) -> dict[str, Any]:
    require(
        set(document)
        == {
            "schema_version",
            "contract_id",
            "class",
            "issuer",
            "deployment_target",
            "one_time_bootstrap",
            "rotation",
            "forgejo_repository",
        },
        "repository handoff shape changed",
    )
    require(document["schema_version"] == "1.0", "repository schema version changed")
    require(document["contract_id"] == "delivery-input-contract", "repository contract ID changed")
    require(document["class"] == "forgejo_repository", "repository class changed")
    require(document["issuer"] == "forgejo-after-bootstrap", "repository issuer changed")
    require(document["deployment_target"] == "delivery-node-only", "repository target changed")
    require(document["one_time_bootstrap"] is True, "repository bootstrap policy changed")
    require(document["rotation"] == "explicit-approved", "repository rotation policy changed")

    repository = document["forgejo_repository"]
    require(isinstance(repository, dict), "repository handoff payload must be an object")
    repository = cast(dict[str, Any], repository)
    require(
        set(repository) == {"url", "username", "api_token"},
        "repository handoff payload shape changed",
    )
    require(repository["url"] == REPOSITORY_URL, "repository URL changed")
    require(repository["username"] == BOT_USERNAME, "repository bot changed")
    require(
        isinstance(repository["api_token"], str)
        and re.fullmatch(r"[0-9a-f]{40}", repository["api_token"]) is not None,
        "repository API token shape changed",
    )
    return document


def api(
    method: str,
    path: str,
    username: str,
    password: str,
    connection: delivery.DeliveryConnection,
    *,
    payload: dict[str, Any] | None = None,
    ok_codes: tuple[int, ...] = (200,),
) -> tuple[int, str]:
    """Call one fixed Forgejo API path on the delivery host."""

    require(method in {"GET", "POST", "PUT", "DELETE"}, "API method is not allowed")
    require(
        re.fullmatch(r"/api/v1/[A-Za-z0-9_./-]+", path) is not None,
        "API path is not allowed",
    )
    payload_b64 = ""
    if payload is not None:
        payload_b64 = base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
    expected = "|".join(str(code) for code in ok_codes)
    remote = f"""set -eu
IFS= read -r API_USER
IFS= read -r API_PASS
IFS= read -r PAYLOAD_B64
umask 077
NETRC=$(mktemp)
BODY=$(mktemp)
trap 'rm -f "$NETRC" "$BODY"' EXIT INT HUP TERM
printf 'machine {DELIVERY_FQDN} login %s password %s\\n' "$API_USER" "$API_PASS" > "$NETRC"
if [ -n "$PAYLOAD_B64" ]; then
  PAYLOAD=$(printf '%s' "$PAYLOAD_B64" | base64 -d)
  CODE=$(curl --silent --show-error --netrc-file "$NETRC" --cacert {shlex.quote(PLATFORM_CA)} -o "$BODY" -w '%{{http_code}}' -X {method} -H 'Accept: application/json' -H 'Content-Type: application/json' --data "$PAYLOAD" {shlex.quote(DELIVERY_URL + path)})
else
  CODE=$(curl --silent --show-error --netrc-file "$NETRC" --cacert {shlex.quote(PLATFORM_CA)} -o "$BODY" -w '%{{http_code}}' -X {method} -H 'Accept: application/json' {shlex.quote(DELIVERY_URL + path)})
fi
case "$CODE" in
  {expected}) ;;
  *) echo 'Forgejo API request failed' >&2; exit 1 ;;
esac
printf '%s\\n' "$CODE"
cat "$BODY"
"""
    output = delivery.ssh(
        remote,
        connection,
        label=f"Forgejo API {method} {path}",
        input_text=f"{username}\n{password}\n{payload_b64}\n",
    )
    code_line, _, body = output.partition("\n")
    try:
        return int(code_line), body
    except ValueError as error:
        raise RepositoryError("Forgejo API returned an invalid status") from error


def api_json(
    method: str,
    path: str,
    username: str,
    password: str,
    connection: delivery.DeliveryConnection,
    *,
    payload: dict[str, Any] | None = None,
    ok_codes: tuple[int, ...] = (200,),
) -> tuple[int, Any]:
    code, body = api(
        method,
        path,
        username,
        password,
        connection,
        payload=payload,
        ok_codes=ok_codes,
    )
    if not body.strip():
        return code, None
    try:
        return code, json.loads(body)
    except json.JSONDecodeError as error:
        raise RepositoryError(f"Forgejo API {method} {path} returned non-JSON") from error


def ensure_bot_user(
    admin_username: str,
    admin_password: str,
    connection: delivery.DeliveryConnection,
) -> None:
    code, _ = api_json(
        "GET",
        f"/api/v1/users/{BOT_USERNAME}",
        admin_username,
        admin_password,
        connection,
        ok_codes=(200, 404),
    )
    if code == 200:
        return
    bot_password = secrets.token_urlsafe(24)
    api_json(
        "POST",
        "/api/v1/admin/users",
        admin_username,
        admin_password,
        connection,
        payload={
            "username": BOT_USERNAME,
            "email": BOT_EMAIL,
            "password": bot_password,
            "must_change_password": False,  # nosec B105 - boolean policy flag
        },
        ok_codes=(201,),
    )


def ensure_organization(
    admin_username: str,
    admin_password: str,
    connection: delivery.DeliveryConnection,
) -> None:
    code, _ = api_json(
        "GET",
        f"/api/v1/orgs/{ORG_NAME}",
        admin_username,
        admin_password,
        connection,
        ok_codes=(200, 404),
    )
    if code == 200:
        return
    api_json(
        "POST",
        "/api/v1/orgs",
        admin_username,
        admin_password,
        connection,
        payload={
            "username": ORG_NAME,
            "full_name": "SHELL delivery org",
            "visibility": "private",
        },
        ok_codes=(201,),
    )


def ensure_repository(
    admin_username: str,
    admin_password: str,
    connection: delivery.DeliveryConnection,
) -> None:
    code, _ = api_json(
        "GET",
        f"/api/v1/repos/{ORG_NAME}/{REPOSITORY_NAME}",
        admin_username,
        admin_password,
        connection,
        ok_codes=(200, 404),
    )
    if code == 200:
        return
    api_json(
        "POST",
        f"/api/v1/orgs/{ORG_NAME}/repos",
        admin_username,
        admin_password,
        connection,
        payload={
            "name": REPOSITORY_NAME,
            "auto_init": True,
            "private": True,
            "default_branch": "main",
        },
        ok_codes=(201,),
    )


def grant_bot_write(
    admin_username: str,
    admin_password: str,
    connection: delivery.DeliveryConnection,
) -> None:
    api_json(
        "PUT",
        f"/api/v1/repos/{ORG_NAME}/{REPOSITORY_NAME}/collaborators/{BOT_USERNAME}",
        admin_username,
        admin_password,
        connection,
        payload={"permission": "write"},
        ok_codes=(204,),
    )


def create_bot_token(
    admin_username: str,
    admin_password: str,
    connection: delivery.DeliveryConnection,
) -> str:
    code, tokens = api_json(
        "GET",
        f"/api/v1/admin/users/{BOT_USERNAME}/tokens",
        admin_username,
        admin_password,
        connection,
        ok_codes=(200,),
    )
    if code == 200 and isinstance(tokens, list):
        for item in tokens:
            if not isinstance(item, dict) or item.get("name") != TOKEN_NAME:
                continue
            token_id = item.get("id")
            require(
                isinstance(token_id, int) and token_id > 0,
                "existing make-repo token has no valid ID",
            )
            api_json(
                "DELETE",
                f"/api/v1/admin/users/{BOT_USERNAME}/tokens/{token_id}",
                admin_username,
                admin_password,
                connection,
                ok_codes=(204,),
            )
    _, body = api_json(
        "POST",
        f"/api/v1/admin/users/{BOT_USERNAME}/tokens",
        admin_username,
        admin_password,
        connection,
        # Git push requires repository write scope. Forgejo 15+ restricts this
        # token to the one MAKE repository named below.
        payload={
            "name": TOKEN_NAME,
            "scopes": TOKEN_SCOPES,
            "repositories": TOKEN_REPOSITORIES,
        },
        ok_codes=(201,),
    )
    token = body.get("sha1") if isinstance(body, dict) else None
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{40}", token) is None:
        raise RepositoryError("Forgejo bot token shape changed")
    return token


def seed_repository(token: str, connection: delivery.DeliveryConnection) -> None:
    remote = f"""set -eu
IFS= read -r BOT_TOKEN
umask 077
SEED=$(mktemp -d)
trap 'rm -rf "$SEED"' EXIT INT HUP TERM
printf 'machine {DELIVERY_FQDN} login {BOT_USERNAME} password %s\\n' "$BOT_TOKEN" > "$SEED/.netrc"
REPO="$SEED/repo"
HOME="$SEED" git clone {shlex.quote(REPOSITORY_URL)} "$REPO" >/dev/null 2>&1
cd "$REPO"
printf '%s' {shlex.quote(README_CONTENT)} > "$SEED/README.expected"
if [ -e README.md ]; then
  test -f README.md
  cmp --silent README.md "$SEED/README.expected"
else
  cp "$SEED/README.expected" README.md
fi
mkdir -p .forgejo/workflows
printf '%s' {shlex.quote(WORKFLOW_CONTENT)} > "$SEED/workflow.expected"
if [ -e {shlex.quote(WORKFLOW_PATH)} ]; then
  test -f {shlex.quote(WORKFLOW_PATH)}
  cmp --silent {shlex.quote(WORKFLOW_PATH)} "$SEED/workflow.expected"
else
  cp "$SEED/workflow.expected" {shlex.quote(WORKFLOW_PATH)}
fi
git add README.md {shlex.quote(WORKFLOW_PATH)}
if git diff --cached --quiet; then
  exit 0
fi
git -c user.email={shlex.quote(BOT_EMAIL)} -c user.name={shlex.quote(BOT_USERNAME)} commit -m 'Seed shell/make' >/dev/null
HOME="$SEED" git push origin main >/dev/null 2>&1
"""
    delivery.ssh(
        remote,
        connection,
        label="Forgejo repository seed",
        input_text=f"{token}\n",
    )


def verify_repository(token: str, connection: delivery.DeliveryConnection) -> None:
    api_json(
        "GET",
        "/api/v1/user",
        BOT_USERNAME,
        token,
        connection,
        ok_codes=(200,),
    )
    api_json(
        "GET",
        f"/api/v1/repos/{ORG_NAME}/{REPOSITORY_NAME}",
        BOT_USERNAME,
        token,
        connection,
        ok_codes=(200,),
    )


def register(
    bootstrap_sops: Path,
    age_key: Path,
    repository_sops: Path,
    inventory_paths: list[Path],
    *,
    approval: str | None = None,
    rotate: bool = False,
    validate_only: bool = False,
    verify_only: bool = False,
) -> dict[str, Any]:
    repository_sops = delivery.absolute_path(repository_sops, "SOPS repository handoff")
    delivery.require_private_directory(
        repository_sops.parent, "SOPS repository handoff directory"
    )
    existing: dict[str, Any] | None = None
    if repository_sops.exists() or repository_sops.is_symlink():
        delivery.require_private_file(repository_sops, "SOPS repository handoff")
        existing = validate_repository_document(
            delivery.decrypt_document(repository_sops, age_key)
        )
        if validate_only:
            print(f"validated repository handoff {repository_sops}")
            return existing
        if verify_only:
            connection = delivery.resolve_connection(inventory_paths)
            token = cast(dict[str, Any], existing["forgejo_repository"])["api_token"]
            verify_repository(cast(str, token), connection)
            print("verified Forgejo repository handoff and API access")
            return existing
        if not rotate:
            print(f"reused repository handoff {repository_sops}")
            return existing

    require(not validate_only and not verify_only, "repository handoff is missing")
    require(not rotate or existing is not None, "repository handoff is missing for rotation")
    require(approval == REPOSITORY_APPROVAL, "exact repository registration approval is required")
    bootstrap = delivery.decrypt_document(bootstrap_sops, age_key)
    admin_username, admin_password = bootstrap_admin(bootstrap)
    connection = delivery.resolve_connection(inventory_paths)
    ensure_bot_user(admin_username, admin_password, connection)
    ensure_organization(admin_username, admin_password, connection)
    ensure_repository(admin_username, admin_password, connection)
    grant_bot_write(admin_username, admin_password, connection)
    token = create_bot_token(admin_username, admin_password, connection)
    seed_repository(token, connection)
    verify_repository(token, connection)

    document = validate_repository_document(
        {
            "schema_version": "1.0",
            "contract_id": "delivery-input-contract",
            "class": "forgejo_repository",
            "issuer": "forgejo-after-bootstrap",
            "deployment_target": "delivery-node-only",
            "one_time_bootstrap": True,
            "rotation": "explicit-approved",
            "forgejo_repository": {
                "url": REPOSITORY_URL,
                "username": BOT_USERNAME,
                "api_token": token,
            },
        }
    )
    delivery.encrypt_document(document, repository_sops, age_key)
    require(
        validate_repository_document(
            delivery.decrypt_document(repository_sops, age_key)
        )
        == document,
        "repository SOPS roundtrip mismatch",
    )
    print(f"registered {ORG_NAME}/{REPOSITORY_NAME} and wrote encrypted handoff")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap-sops", type=Path, default=DEFAULT_BOOTSTRAP)
    parser.add_argument("--age-key", type=Path, default=DEFAULT_AGE_KEY)
    parser.add_argument(
        "--repository-sops", type=Path, default=DEFAULT_REPOSITORY_HANDOFF
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        action="append",
        dest="inventory_paths",
        default=None,
    )
    parser.add_argument("--approval")
    parser.add_argument("--rotate", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if sum((args.validate_only, args.verify_only, args.rotate)) > 1:
        print(
            "repository registration failed: validation, verification, and rotation are exclusive",
            file=sys.stderr,
        )
        return 2
    inventory_paths = args.inventory_paths or [
        DEFAULT_INVENTORY,
        DEFAULT_CONNECTION_INVENTORY,
    ]
    try:
        register(
            args.bootstrap_sops,
            args.age_key,
            args.repository_sops,
            inventory_paths,
            approval=args.approval,
            rotate=args.rotate,
            validate_only=args.validate_only,
            verify_only=args.verify_only,
        )
        return 0
    except (RepositoryError, delivery.RunnerError, OSError, json.JSONDecodeError) as error:
        print(f"repository registration failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
