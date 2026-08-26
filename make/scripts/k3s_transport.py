#!/usr/bin/env python3
"""Fixed private-inventory transport for MAKE's monitoring deployment."""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast


K3S_NODE = "gcp-k3s-01"
K3S_ADDRESS = "10.77.0.201"
K3S_ZONE = "europe-west4-a"
K3S_CLUSTER = "gcp"
K3S_INVENTORY_GROUP = "gcp_k3s_servers"
DEFAULT_TIMEOUT_SECONDS = 60


class TransportError(RuntimeError):
    """The private INIT transport cannot safely reach the fixed K3s server."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TransportError(message)


def absolute_path(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    for component in (value, *value.parents):
        require(not component.is_symlink(), f"unsafe symlinked {label}: {component}")
    return value


def require_private_file(path: Path, label: str) -> Path:
    value = absolute_path(path, label)
    require(value.is_file(), f"missing regular {label}: {value}")
    require(
        stat.S_IMODE(value.stat().st_mode) == 0o600,
        f"{label} must be mode 0600",
    )
    return value


def require_regular_file(path: Path, label: str) -> Path:
    value = absolute_path(path, label)
    require(value.is_file(), f"missing regular {label}: {value}")
    return value


def run(
    command: list[str],
    *,
    label: str,
    input_text: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    require(timeout_seconds > 0, f"{label} timeout must be positive")
    try:
        completed = subprocess.run(  # nosec B603
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise TransportError(
            f"{label} timed out after {timeout_seconds} seconds"
        ) from error
    except OSError as error:
        raise TransportError(f"{label} could not start") from error
    if completed.returncode:
        detail = completed.stderr.strip().splitlines()
        suffix = detail[-1] if detail else f"exit {completed.returncode}"
        raise TransportError(f"{label} failed: {suffix}")
    return completed.stdout


def read_json(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise TransportError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


@dataclass(frozen=True)
class Connection:
    target: str
    options: tuple[str, ...]


def resolve_connection(inventory_paths: list[Path]) -> Connection:
    if not inventory_paths:
        raise TransportError("private INIT inventories are required")
    command = ["ansible-inventory"]
    for path in inventory_paths:
        command.extend(["-i", str(require_private_file(path, "INIT inventory"))])
    command.extend(["--host", K3S_NODE])
    host = read_json(run(command, label="INIT K3s inventory lookup"), "INIT K3s host")
    require(
        host.get("ansible_host") == K3S_ADDRESS,
        "INIT inventory targets the wrong K3s server",
    )
    user = host.get("ansible_user")
    if (
        not isinstance(user, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]+", user)
        or user == "root"
    ):
        raise TransportError("INIT inventory has an unsafe K3s SSH user")

    common_args = host.get("ansible_ssh_common_args")
    if not isinstance(common_args, str):
        raise TransportError("INIT inventory lacks K3s SSH route options")
    tokens = shlex.split(common_args)
    require(len(tokens) % 2 == 0, "INIT K3s SSH route options are malformed")
    options: list[str] = []
    seen: set[str] = set()
    project_id = host.get("gcp_project_id")
    require(
        isinstance(project_id, str)
        and re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id) is not None,
        "INIT inventory has an unsafe GCP project ID",
    )
    require(host.get("gcp_zone") == K3S_ZONE, "INIT inventory has the wrong K3s zone")
    expected_proxy = (
        f"gcloud compute start-iap-tunnel {K3S_NODE} %p --listen-on-stdin "
        f"--project={project_id} --zone={K3S_ZONE}"
    )
    for index in range(0, len(tokens), 2):
        require(tokens[index] == "-o", "INIT K3s SSH route contains an unsafe option")
        option = tokens[index + 1]
        key, separator, value = option.partition("=")
        if not separator or key not in {
            "ProxyCommand",
            "UserKnownHostsFile",
            "StrictHostKeyChecking",
        }:
            raise TransportError("INIT K3s SSH option is not allowed")
        require(key not in seen, "INIT K3s SSH route repeats an option")
        seen.add(key)
        options.extend(["-o", option])
        if key == "ProxyCommand":
            require(
                value == expected_proxy,
                "INIT K3s SSH route is not the fixed GCP IAP route",
            )
        elif key == "UserKnownHostsFile":
            require(value.startswith("/"), "INIT known-hosts path must be absolute")
            require_regular_file(Path(value), "INIT known-hosts file")
        else:
            require(value == "yes", "INIT K3s host-key policy must be strict")
    require(
        seen == {"ProxyCommand", "UserKnownHostsFile", "StrictHostKeyChecking"},
        "INIT K3s SSH route is incomplete",
    )

    key_path = host.get("ansible_ssh_private_key_file") or host.get(
        "ansible_private_key_file"
    )
    if key_path is not None:
        if not isinstance(key_path, str) or not key_path.startswith("/"):
            raise TransportError("INIT K3s SSH key path must be absolute")
        require_private_file(Path(key_path), "INIT K3s SSH private key")
        options.extend(["-o", "IdentitiesOnly=yes", "-i", key_path])
    return Connection(target=f"{user}@{K3S_ADDRESS}", options=tuple(options))


def ssh(
    command: str,
    connection: Connection,
    *,
    label: str,
    input_text: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
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
        timeout_seconds=timeout_seconds,
    )


def scp(
    local: Path,
    remote: str,
    connection: Connection,
    *,
    timeout_seconds: int = 120,
) -> None:
    local = require_regular_file(local, "local monitoring artifact")
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
        label=f"copy monitoring artifact {local.name}",
        timeout_seconds=timeout_seconds,
    )
