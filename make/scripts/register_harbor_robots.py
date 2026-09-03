#!/usr/bin/env python3
"""Register existing Harbor robot handoffs as Kubernetes pull secrets."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any, cast

import k3s_transport as transport
import sops_helpers
import validate_harbor_robots


ROOT = Path(__file__).resolve().parents[2]
HANDOFF = ROOT / ".local/sudo/release-feed/harbor-robots.sops.json"
AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
HARBOR_INPUT = ROOT / ".local/sudo/release-feed/input-set/harbor.sops.json"
APPROVAL = "environment-gcp/make/harbor-robots"
REGISTRY = "registry.shell.internal"
PROJECT = "shell"
PUBLISHER_NAME = "release-feed-publisher"
PULLER_NAME = "release-feed-puller"


class HarborRobotOperationError(RuntimeError):
    """Harbor robot registration was refused."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HarborRobotOperationError(message)


def robot(values: dict[str, Any], name: str) -> tuple[str, str]:
    item = values.get(name)
    require(isinstance(item, dict), f"{name} robot handoff is missing")
    item = cast(dict[str, Any], item)
    username = item.get("username")
    password = item.get("password")
    require(
        isinstance(username, str)
        and isinstance(password, str)
        and bool(username)
        and bool(password),
        f"{name} robot handoff is incomplete",
    )
    return cast(str, username), cast(str, password)


def secret(
    name: str,
    username: str,
    password: str,
    namespace: str = "release-feed",
) -> str:
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    document = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/part-of": "shell-platform"},
        },
        "type": "kubernetes.io/dockerconfigjson",
        "stringData": {
            ".dockerconfigjson": json.dumps(
                {"auths": {REGISTRY: {"auth": auth}}},
                separators=(",", ":"),
            )
        },
    }
    return json.dumps(document)


def api(
    connection: transport.Connection,
    method: str,
    path: str,
    username: str,
    password: str,
    *,
    payload: dict[str, Any] | None = None,
    expected: tuple[int, ...] = (200,),
) -> Any:
    require(
        re.fullmatch(r"/api/[A-Za-z0-9_/?=&.-]+", path) is not None,
        "Harbor API path is unsafe",
    )
    body = json.dumps(payload) if payload is not None else ""
    command = (
        "set -eu; IFS= read -r API_USER; IFS= read -r API_PASS; "
        "NETRC=$(mktemp); BODY=$(mktemp); "
        'trap \'rm -f "$NETRC" "$BODY"\' EXIT INT HUP TERM; '
        "printf 'machine registry.shell.internal login %s password %s\\n' "
        '"$API_USER" "$API_PASS" > "$NETRC"; '
        f"CODE=$(curl --resolve registry.shell.internal:443:10.77.0.221 "
        "--cacert /usr/local/share/ca-certificates/shell-platform-ca.crt "
        '--netrc-file "$NETRC" --silent --show-error --output "$BODY" '
        f'--write-out "%{{http_code}}" --request {method} '
        '-H "Accept: application/json" -H "Content-Type: application/json" '
        f"{('--data ' + shlex.quote(body)) if body else ''} "
        f"'https://registry.shell.internal{path}'); "
        'printf "%s\\n" "$CODE"; cat "$BODY"'
    )
    output = transport.ssh(
        command,
        connection,
        label=f"Harbor API {method} {path}",
        input_text=f"{username}\n{password}\n",
        timeout_seconds=90,
    )
    code, _, response = output.partition("\n")
    require(
        code.isdigit() and int(code) in expected,
        f"Harbor API {method} {path} returned an unexpected status",
    )
    if not response.strip():
        return None
    try:
        return json.loads(response)
    except json.JSONDecodeError as error:
        raise HarborRobotOperationError(
            "Harbor API response is invalid JSON"
        ) from error


def robot_payload(name: str, actions: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "description": "SHELL release-feed image delivery",
        "level": "project",
        "duration": -1,
        "permissions": [
            {
                "kind": "project",
                "namespace": PROJECT,
                "access": [
                    {"resource": "repository", "action": action} for action in actions
                ],
            }
        ],
    }


def register(connection: transport.Connection, *, rotate: bool) -> dict[str, Any]:
    if HANDOFF.exists() or HANDOFF.is_symlink():
        require(not HANDOFF.is_symlink(), "Harbor robot handoff is a symlink")
        sops_helpers.private_file(HANDOFF, "Harbor robot handoff")
        if not rotate:
            return sops_helpers.decrypt_json(HANDOFF, AGE_KEY)
    harbor = sops_helpers.decrypt_json(HARBOR_INPUT, AGE_KEY)
    password = harbor.get("admin_password")
    require(
        isinstance(password, str) and bool(password),
        "Harbor admin input is incomplete",
    )
    password = cast(str, password)
    api(
        connection,
        "POST",
        "/api/v2.0/projects",
        "admin",
        password,
        payload={"project_name": PROJECT, "public": False},
        expected=(201, 409),
    )
    project = api(
        connection,
        "GET",
        f"/api/v2.0/projects/{PROJECT}",
        "admin",
        password,
    )
    require(isinstance(project, dict), "Harbor project response is invalid")
    project_id = project.get("project_id")
    require(isinstance(project_id, int), "Harbor project identity is missing")
    if rotate:
        existing = api(
            connection,
            "GET",
            f"/api/v2.0/robots?project_id={project_id}&page=1&page_size=100",
            "admin",
            password,
        )
        require(isinstance(existing, list), "Harbor robot list is invalid")
        for item in existing:
            if not isinstance(item, dict) or item.get("name") not in {
                PUBLISHER_NAME,
                PULLER_NAME,
            }:
                continue
            robot_id = item.get("id")
            require(isinstance(robot_id, int), "Harbor robot ID is missing")
            api(
                connection,
                "DELETE",
                f"/api/v2.0/robots/{robot_id}",
                "admin",
                password,
                expected=(200, 204),
            )
    publisher = api(
        connection,
        "POST",
        "/api/v2.0/robots",
        "admin",
        password,
        payload=robot_payload(PUBLISHER_NAME, ["pull", "push"]),
        expected=(201,),
    )
    puller = api(
        connection,
        "POST",
        "/api/v2.0/robots",
        "admin",
        password,
        payload=robot_payload(PULLER_NAME, ["pull"]),
        expected=(201,),
    )
    require(
        isinstance(publisher, dict)
        and isinstance(puller, dict)
        and isinstance(publisher.get("secret"), str)
        and isinstance(puller.get("secret"), str),
        "Harbor robot response did not include secrets",
    )
    document = {
        "schema_version": "1.0",
        "environment": "environment-gcp",
        "publisher": {
            "username": publisher.get("name"),
            "password": publisher.get("secret"),
        },
        "puller": {
            "username": puller.get("name"),
            "password": puller.get("secret"),
        },
    }
    HANDOFF.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    HANDOFF.parent.chmod(0o700)
    output = HANDOFF
    if output.exists():
        output = HANDOFF.with_name(f".{HANDOFF.name}.next")
        require(
            not output.exists() and not output.is_symlink(),
            "next Harbor handoff already exists",
        )
    sops_helpers.encrypt_json(document, output, AGE_KEY)
    if output != HANDOFF:
        os.replace(output, HANDOFF)
        HANDOFF.chmod(0o600)
    return document


def apply(inventory: list[Path], *, rotate: bool) -> None:
    validate_harbor_robots.validate()
    connection = transport.resolve_connection(inventory)
    values = register(connection, rotate=rotate)
    puller = robot(values, "puller")
    for namespace in ("release-feed", "openbao", "argocd", "kyverno"):
        transport.ssh(
            "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
            f"create namespace {namespace} --dry-run=client -o yaml | "
            "sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl apply "
            "--server-side --field-manager=make-harbor-robots --filename -",
            connection,
            label=f"Harbor robot namespace {namespace}",
        )
    documents = (
        "\n---\n".join(
            [
                secret("release-feed-pull", *puller, "release-feed"),
                secret("shell-registry-pull", *puller, "release-feed"),
                secret("shell-registry-pull", *puller, "openbao"),
                secret("shell-registry-pull", *puller, "argocd"),
                secret("shell-registry-pull", *puller, "kyverno"),
            ]
        )
        + "\n"
    )
    transport.ssh(
        "set -eu; sudo -E KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3s kubectl "
        "apply --server-side --field-manager=make-harbor-robots --filename -",
        connection,
        label="Harbor robot Kubernetes secrets",
        input_text=documents,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--inventory", action="append", type=Path, default=[])
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--rotate", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_harbor_robots.validate()
        if args.check_only:
            print("validated Harbor robot source contract")
            return 0
        raise HarborRobotOperationError(
            "Harbor robot registration is blocked until durable replacement and custody publication exist"
        )
        require(args.approval == APPROVAL, f"approval must be {APPROVAL}")
        require(args.inventory, "private INIT inventories are required")
        apply(args.inventory, rotate=args.rotate)
    except (
        OSError,
        HarborRobotOperationError,
        transport.TransportError,
        sops_helpers.SopsError,
        validate_harbor_robots.HarborRobotError,
    ) as error:
        print(f"MAKE Harbor robot operation refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
