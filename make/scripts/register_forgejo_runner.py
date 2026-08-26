#!/usr/bin/env python3
"""Register the MAKE Forgejo Actions runner and encrypt its handoff.

The controller creates a 40-character shared secret, registers it through the
fixed delivery host's Forgejo CLI, and stores the resulting runner
configuration only in a mode-0600 SOPS/age handoff. Credentials and runner
tokens never appear in command arguments or process output.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import stat
import subprocess  # nosec B404
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AGE_KEY = REPOSITORY_ROOT / ".local/sudo/delivery/age-key.txt"
DEFAULT_RUNNER_HANDOFF = (
    REPOSITORY_ROOT / ".local/sudo/delivery/forgejo-runner.sops.json"
)
DEFAULT_INVENTORY = REPOSITORY_ROOT / ".local/ansible/inventory.json"
DEFAULT_CONNECTION_INVENTORY = (
    REPOSITORY_ROOT / ".local/ansible/connection-inventory.yml"
)

DELIVERY_NODE = "delivery-01"
DELIVERY_ADDRESS = "10.77.0.211"
DELIVERY_FQDN = "forgejo.shell.internal"
DELIVERY_URL = f"https://{DELIVERY_FQDN}"
SERVICE_USER = "shell-delivery"
RUNNER_NAME = "shell-runner-01"
RUNNER_LABEL = "docker:docker://docker.io/library/node:24-bookworm"
RUNNER_APPROVAL = "environment-gcp/make/forgejo-delivery"
RUNNER_IMAGE = (
    "data.forgejo.org/forgejo/runner:13@"
    "sha256:7fb853bfe73c229be6349398359c0a7bd01fadfd17c106607b2221150b799ed2"
)
PLATFORM_CA = "/usr/local/share/ca-certificates/shell-platform-ca.crt"


class RunnerError(RuntimeError):
    """A runner registration input or operation is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RunnerError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def absolute_path(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    for component in (value, *value.parents):
        require(not component.is_symlink(), f"unsafe symlinked {label}: {component}")
    return value


def require_private_file(path: Path, label: str) -> Path:
    value = absolute_path(path, label)
    require(value.is_file(), f"missing regular {label}: {value}")
    require(stat.S_IMODE(value.stat().st_mode) == 0o600, f"{label} must be mode 0600")
    return value


def require_private_directory(path: Path, label: str) -> Path:
    value = absolute_path(path, label)
    require(value.is_dir(), f"missing private {label}: {value}")
    require(stat.S_IMODE(value.stat().st_mode) == 0o700, f"{label} must be mode 0700")
    return value


def run(
    command: list[str],
    *,
    label: str,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
) -> str:
    try:
        completed = subprocess.run(  # nosec B603
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
    except OSError as error:
        raise RunnerError(f"{label} could not start") from error
    if completed.returncode:
        detail = completed.stderr.strip().splitlines()
        suffix = detail[-1] if detail else f"exit {completed.returncode}"
        raise RunnerError(f"{label} failed: {suffix}")
    return completed.stdout


def read_json_document(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RunnerError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


def decrypt_document(ciphertext: Path, age_key: Path) -> dict[str, Any]:
    ciphertext = require_private_file(ciphertext, "SOPS runner handoff")
    age_key = require_private_file(age_key, "SOPS/age identity")
    environment = os.environ.copy()
    environment["SOPS_AGE_KEY_FILE"] = str(age_key)
    raw = run(
        ["sops", "--decrypt", "--output-type", "json", str(ciphertext)],
        label=f"SOPS decrypt {ciphertext.name}",
        environment=environment,
    )
    return read_json_document(raw, "decrypted runner handoff")


def age_recipient(age_key: Path) -> str:
    age_key = require_private_file(age_key, "SOPS/age identity")
    recipient = run(
        ["age-keygen", "-y", str(age_key)],
        label="age recipient derivation",
    ).strip()
    require(recipient.startswith("age1"), "age identity did not yield an age recipient")
    return recipient


def encrypt_document(document: dict[str, Any], output: Path, age_key: Path) -> None:
    age_key = require_private_file(age_key, "SOPS/age identity")
    output = absolute_path(output, "SOPS runner handoff")
    require_private_directory(output.parent, "SOPS runner handoff directory")
    if output.exists() or output.is_symlink():
        require(not output.is_symlink(), "refusing to replace a symlinked SOPS handoff")

    plaintext_fd, plaintext_name = tempfile.mkstemp(
        prefix=f".{output.name}.plaintext.", dir=output.parent
    )
    encrypted_fd, encrypted_name = tempfile.mkstemp(
        prefix=f".{output.name}.encrypted.", dir=output.parent
    )
    os.close(encrypted_fd)
    encrypted = Path(encrypted_name)
    encrypted.unlink()
    plaintext = Path(plaintext_name)
    try:
        os.fchmod(plaintext_fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(plaintext_fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        run(
            [
                "sops",
                "--encrypt",
                "--age",
                age_recipient(age_key),
                "--input-type",
                "json",
                "--output-type",
                "json",
                "--output",
                str(encrypted),
                str(plaintext),
            ],
            label="SOPS runner handoff encryption",
        )
        require(encrypted.is_file() and not encrypted.is_symlink(), "SOPS output is not regular")
        encrypted.chmod(0o600)
        os.replace(encrypted, output)
        output.chmod(0o600)
    finally:
        if plaintext.exists():
            plaintext.unlink()
        if encrypted.exists():
            encrypted.unlink()


def validate_runner_document(document: dict[str, Any]) -> dict[str, Any]:
    require(
        set(document)
        == {
            "schema_version",
            "contract_id",
            "class",
            "issuer",
            "deployment_target",
            "one_time_bootstrap",
            "forgejo_runner",
        },
        "runner handoff shape changed",
    )
    require(document["schema_version"] == "1.0", "runner schema version changed")
    require(document["contract_id"] == "delivery-input-contract", "runner contract ID changed")
    require(document["class"] == "forgejo_runner", "runner class changed")
    require(document["issuer"] == "forgejo-after-bootstrap", "runner issuer changed")
    require(document["deployment_target"] == DELIVERY_NODE, "runner target changed")
    require(document["one_time_bootstrap"] is True, "runner bootstrap policy changed")

    runner = document["forgejo_runner"]
    require(isinstance(runner, dict), "runner handoff payload must be an object")
    runner = cast(dict[str, Any], runner)
    require(
        set(runner) == {"url", "name", "uuid", "token", "runner_config"},
        "runner handoff payload shape changed",
    )
    require(runner["url"] == DELIVERY_URL, "runner URL changed")
    require(runner["name"] == RUNNER_NAME, "runner name changed")
    runner_uuid = runner["uuid"]
    runner_token = runner["token"]
    require(isinstance(runner_uuid, str), "runner UUID is missing")
    try:
        uuid.UUID(runner_uuid)
    except (ValueError, AttributeError) as error:
        raise RunnerError("runner UUID is invalid") from error
    require(isinstance(runner_token, str), "runner token shape changed")
    require(
        re.fullmatch(r"[0-9a-f]{40}", runner_token) is not None,
        "runner token shape changed",
    )

    config = runner["runner_config"]
    require(isinstance(config, dict), "runner configuration must be an object")
    config = cast(dict[str, Any], config)
    require(isinstance(config.get("address"), str), "runner address is missing")
    require(config["address"].startswith(DELIVERY_URL), "runner address changed")
    require(config.get("uuid") == runner["uuid"], "runner UUID does not match configuration")
    require(config.get("token") == runner["token"], "runner token does not match configuration")
    require(config.get("name") == RUNNER_NAME, "runner configuration name changed")
    return document


@dataclass(frozen=True)
class DeliveryConnection:
    target: str
    options: tuple[str, ...]


def resolve_connection(inventory_paths: list[Path]) -> DeliveryConnection:
    if not inventory_paths:
        raise RunnerError("a private INIT inventory is required")
    command = ["ansible-inventory"]
    for path in inventory_paths:
        command.extend(["-i", str(require_private_file(path, "INIT connection inventory"))])
    command.extend(["--host", DELIVERY_NODE])
    host = read_json_document(run(command, label="INIT inventory lookup"), "INIT inventory host")
    require(host.get("ansible_host") == DELIVERY_ADDRESS, "INIT inventory targets the wrong delivery address")
    user = host.get("ansible_user")
    if (
        not isinstance(user, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]+", user)
        or user == "root"
    ):
        raise RunnerError("INIT inventory has an unsafe SSH user")

    common_args = host.get("ansible_ssh_common_args")
    if not isinstance(common_args, str):
        raise RunnerError("INIT inventory lacks SSH route options")
    tokens = shlex.split(common_args)
    require(len(tokens) % 2 == 0, "INIT SSH route options are malformed")
    options: list[str] = []
    seen: set[str] = set()
    for index in range(0, len(tokens), 2):
        require(tokens[index] == "-o", "INIT SSH route contains an unsafe option")
        option = tokens[index + 1]
        key, separator, value = option.partition("=")
        if not separator or key not in {
            "ProxyCommand",
            "UserKnownHostsFile",
            "StrictHostKeyChecking",
        }:
            raise RunnerError("INIT SSH option is not allowed")
        options.extend(["-o", option])
        seen.add(key)
        if key == "ProxyCommand":
            require(
                re.fullmatch(
                    r"gcloud compute start-iap-tunnel delivery-01 %p "
                    r"--listen-on-stdin --project=[A-Za-z0-9._-]+ "
                    r"--zone=[A-Za-z0-9-]+",
                    value,
                )
                is not None,
                "INIT SSH route is not the fixed delivery IAP route",
            )
        elif key == "UserKnownHostsFile":
            require(value.startswith("/"), "INIT known-hosts path must be absolute")
        else:
            require(value == "yes", "INIT host-key policy must be strict")
    require(seen == {"ProxyCommand", "UserKnownHostsFile", "StrictHostKeyChecking"}, "INIT SSH route is incomplete")

    key_path = host.get("ansible_ssh_private_key_file") or host.get("ansible_private_key_file")
    if key_path is not None:
        if not isinstance(key_path, str) or not key_path.startswith("/"):
            raise RunnerError("INIT SSH key path must be absolute")
        require_private_file(Path(key_path), "INIT SSH private key")
        options.extend(["-o", "IdentitiesOnly=yes", "-i", key_path])
    return DeliveryConnection(target=f"{user}@{DELIVERY_ADDRESS}", options=tuple(options))


def ssh(
    command: str,
    connection: DeliveryConnection,
    *,
    label: str,
    input_text: str | None = None,
) -> str:
    return run(
        [
            "ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            *connection.options,
            connection.target,
            command,
        ],
        label=label,
        input_text=input_text,
    )


def runner_secret(existing: dict[str, Any] | None = None) -> str:
    if existing is None:
        return secrets.token_hex(20)
    current = cast(dict[str, Any], existing["forgejo_runner"])["token"]
    if (
        not isinstance(current, str)
        or re.fullmatch(r"[0-9a-f]{40}", current) is None
    ):
        raise RunnerError("existing runner token shape changed")
    return current[:16] + secrets.token_hex(12)


def offline_register(secret: str, connection: DeliveryConnection) -> str:
    require(
        re.fullmatch(r"[0-9a-f]{40}", secret) is not None,
        "runner shared secret shape changed",
    )
    remote = f"""set -eu
IFS= read -r RUNNER_SECRET
printf '%s' "$RUNNER_SECRET" |
  sudo runuser -u {shlex.quote(SERVICE_USER)} -- \
  env HOME=/home/{SERVICE_USER} XDG_RUNTIME_DIR=/run/user/$(id -u {SERVICE_USER}) \
  podman exec -i forgejo forgejo forgejo-cli actions register \
  --name {shlex.quote(RUNNER_NAME)} \
  --labels {shlex.quote(RUNNER_LABEL)} \
  --secret-stdin stdin
"""
    output = ssh(
        remote,
        connection,
        label="Forgejo offline runner registration",
        input_text=f"{secret}\n",
    )
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    require(bool(lines), "Forgejo offline registration returned no UUID")
    runner_uuid = lines[-1]
    try:
        uuid.UUID(runner_uuid)
    except ValueError as error:
        raise RunnerError(
            "Forgejo offline registration returned an invalid UUID"
        ) from error
    return runner_uuid


def register(
    age_key: Path,
    runner_sops: Path,
    inventory_paths: list[Path],
    *,
    approval: str | None = None,
    rotate: bool = False,
    validate_only: bool = False,
) -> dict[str, Any]:
    runner_sops = absolute_path(runner_sops, "SOPS runner handoff")
    require_private_directory(runner_sops.parent, "SOPS runner handoff directory")
    existing: dict[str, Any] | None = None
    if runner_sops.exists() or runner_sops.is_symlink():
        require_private_file(runner_sops, "SOPS runner handoff")
        existing = validate_runner_document(decrypt_document(runner_sops, age_key))
        if validate_only or not rotate:
            print(f"validated runner handoff {runner_sops}")
            return existing

    require(not validate_only, "runner handoff is missing")
    require(approval == RUNNER_APPROVAL, "exact runner registration approval is required")
    connection = resolve_connection(inventory_paths)
    token = runner_secret(existing)
    runner_config = {
        "address": DELIVERY_URL,
        "uuid": offline_register(token, connection),
        "token": token,
        "name": RUNNER_NAME,
    }
    document = validate_runner_document(
        {
            "schema_version": "1.0",
            "contract_id": "delivery-input-contract",
            "class": "forgejo_runner",
            "issuer": "forgejo-after-bootstrap",
            "deployment_target": DELIVERY_NODE,
            "one_time_bootstrap": True,
            "forgejo_runner": {
                "url": DELIVERY_URL,
                "name": RUNNER_NAME,
                "uuid": runner_config["uuid"],
                "token": runner_config["token"],
                "runner_config": runner_config,
            },
        }
    )
    encrypt_document(document, runner_sops, age_key)
    require(
        validate_runner_document(decrypt_document(runner_sops, age_key)) == document,
        "runner SOPS roundtrip mismatch",
    )
    print(f"registered runner {RUNNER_NAME} and wrote encrypted handoff")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--age-key", type=Path, default=DEFAULT_AGE_KEY)
    parser.add_argument("--runner-sops", type=Path, default=DEFAULT_RUNNER_HANDOFF)
    parser.add_argument(
        "--inventory",
        type=Path,
        action="append",
        dest="inventory_paths",
        default=None,
    )
    parser.add_argument("--rotate", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--approval")
    args = parser.parse_args()
    inventory_paths = args.inventory_paths or [
        DEFAULT_INVENTORY,
        DEFAULT_CONNECTION_INVENTORY,
    ]
    try:
        register(
            args.age_key,
            args.runner_sops,
            inventory_paths,
            approval=args.approval,
            rotate=args.rotate,
            validate_only=args.validate_only,
        )
        return 0
    except (RunnerError, OSError, json.JSONDecodeError) as error:
        print(f"runner registration failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
