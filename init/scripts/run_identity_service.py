#!/usr/bin/env python3
"""Run the fixed SHELL FreeIPA configuration or verification workflow."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
IDENTITY_HOST = "identity-01"
IDENTITY_ADDRESS = "10.77.0.210"
IDENTITY_GROUP = "identity_nodes"
APPROVAL = "environment-gcp/init/identity-service"
KEYCLOAK_BIND_APPROVAL = "environment-gcp/init/keycloak-ldap-bind"
PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
ZONE_PATTERN = re.compile(r"^[a-z][a-z0-9-]+[0-9]-[a-z]$")


class IdentityLauncherError(ValueError):
    """A FreeIPA identity handoff cannot be executed safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IdentityLauncherError(message)


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "JSON contains duplicate object keys")
        value[key] = item
    return value


def _check_path_components(path: Path, root: Path, label: str) -> None:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise IdentityLauncherError(f"{label} escaped the repository") from error
    current = root
    for component in relative.parts:
        current /= component
        require(not current.is_symlink(), f"{label} contains a symlink")


def _require_private_directory(path: Path, root: Path, label: str) -> None:
    _check_path_components(path, root, label)
    require(path.is_dir(), f"{label} is not a directory")
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE,
        f"{label} must be mode 0700",
    )


def _require_private_file(path: Path, root: Path, label: str) -> None:
    _check_path_components(path, root, label)
    require(not path.is_symlink() and path.is_file(), f"{label} is not a regular file")
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
        f"{label} must be mode 0600",
    )
    _require_private_directory(path.parent, root, f"{label} parent")


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise IdentityLauncherError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    return cast(dict[str, Any], value)


def validate_inventory(
    inventory: Path,
    connection: Path,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    run_process: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Validate the exact generated identity target and GCP IAP route."""

    _require_private_file(inventory, repository_root, "private identity inventory")
    _require_private_file(connection, repository_root, "private connection inventory")
    command = [
        "ansible-inventory",
        "--inventory",
        str(inventory),
        "--inventory",
        str(connection),
        "--list",
    ]
    try:
        result = run_process(
            command,
            cwd=str(repository_root),
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise IdentityLauncherError(
            "identity inventory lookup could not complete"
        ) from error
    require(
        result.returncode == 0,
        "identity inventory lookup failed",
    )
    document = _read_json_from_text(result.stdout, "identity inventory")
    group_value = document.get(IDENTITY_GROUP)
    require(isinstance(group_value, dict), "identity inventory group is missing")
    group = cast(dict[str, Any], group_value)
    require(group.get("hosts") == [IDENTITY_HOST], "identity inventory target changed")
    metadata_value = document.get("_meta")
    require(isinstance(metadata_value, dict), "identity inventory metadata is missing")
    metadata = cast(dict[str, Any], metadata_value)
    hostvars_value = metadata.get("hostvars")
    require(
        isinstance(hostvars_value, dict),
        "identity inventory host variables are missing",
    )
    hostvars = cast(dict[str, Any], hostvars_value)
    host_value = hostvars.get(IDENTITY_HOST)
    require(isinstance(host_value, dict), "identity inventory host is missing")
    host = cast(dict[str, Any], host_value)
    require(
        host.get("ansible_host") == IDENTITY_ADDRESS, "identity host address changed"
    )
    require(
        host.get("shell_expected_address") == IDENTITY_ADDRESS,
        "identity expected address changed",
    )
    require(host.get("shell_role") == "identity", "identity host role changed")
    require(host.get("shell_cluster") == "shared", "identity host cluster changed")
    require(host.get("shell_transport") == "gcp_iap", "identity host transport changed")
    require(
        host.get("shell_operating_system") == "almalinux-9",
        "identity host operating system changed",
    )
    user = host.get("ansible_user")
    require(
        isinstance(user, str) and bool(user) and user != "root",
        "identity host requires a non-root SSH user",
    )
    require(
        host.get("ansible_connection", "ssh") == "ssh",
        "identity host must use the SSH connection plugin",
    )
    common_args_value = host.get("ansible_ssh_common_args")
    require(isinstance(common_args_value, str), "identity host SSH route is missing")
    common_args = cast(str, common_args_value)
    require(
        "StrictHostKeyChecking=yes" in common_args
        and re.search(r"StrictHostKeyChecking=(?:no|off|accept-new)", common_args)
        is None,
        "identity host requires strict SSH host-key checking",
    )
    project_id = host.get("gcp_project_id")
    zone = host.get("gcp_zone")
    require(
        isinstance(project_id, str)
        and PROJECT_PATTERN.fullmatch(project_id) is not None,
        "identity host GCP project ID is invalid",
    )
    require(
        isinstance(zone, str) and ZONE_PATTERN.fullmatch(zone) is not None,
        "identity host GCP zone is invalid",
    )
    for fragment in (
        "gcloud compute start-iap-tunnel",
        "{{ inventory_hostname | quote }}",
        "{{ gcp_project_id | quote }}",
        "{{ gcp_zone | quote }}",
    ):
        require(
            fragment in common_args, "identity host must use the reviewed GCP IAP route"
        )
    return host


def _read_json_from_text(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, str), f"{label} output is not text")
    try:
        document = json.loads(value, object_pairs_hook=_no_duplicate_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise IdentityLauncherError(f"{label} output is not valid JSON") from error
    require(isinstance(document, dict), f"{label} output must be a JSON object")
    return cast(dict[str, Any], document)


def _write_temporary_variables(
    values: dict[str, Any], directory: Path, repository_root: Path
) -> Path:
    _require_private_directory(
        directory, repository_root, "identity temporary directory"
    )
    descriptor, name = tempfile.mkstemp(
        prefix=".identity-", suffix=".json", dir=directory
    )
    path = Path(name)
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(values, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise
    return path


def execute(
    action: str,
    *,
    approval: str = "",
    check: bool = False,
    repository_root: Path = REPOSITORY_ROOT,
    run_process: Callable[..., Any] = subprocess.run,
) -> int:
    require(
        action in {"configure", "bind", "verify"},
        "action must be configure, bind, or verify",
    )
    if action in {"configure", "bind"} and not check:
        expected_approval = APPROVAL if action == "configure" else KEYCLOAK_BIND_APPROVAL
        require(approval == expected_approval, f"approval must be {expected_approval}")
    repository_root = repository_root.resolve(strict=True)
    inventory = repository_root / ".local/ansible/inventory.json"
    connection = repository_root / ".local/ansible/connection-inventory.yml"
    profile = repository_root / "sudo/access/freeipa-host-profile.json"
    temporary_directory = repository_root / ".local/ansible/.identity-service"
    _require_private_file(inventory, repository_root, "private identity inventory")
    _require_private_file(connection, repository_root, "private connection inventory")
    require(
        profile.is_file() and not profile.is_symlink(),
        "FreeIPA host profile is missing",
    )
    validate_inventory(
        inventory,
        connection,
        repository_root=repository_root,
        run_process=run_process,
    )

    if action in {"configure", "bind"} and not check:
        _require_private_file(
            repository_root / ".local/sudo/identity/freeipa.sops.json",
            repository_root,
            "private FreeIPA input",
        )
        _require_private_file(
            repository_root / ".local/sudo/identity/age-key.txt",
            repository_root,
            "FreeIPA SOPS/age key",
        )
        if action == "bind":
            _require_private_file(
                repository_root / ".local/sudo/keycloak/keycloak.sops.json",
                repository_root,
                "private Keycloak input",
            )
            _require_private_file(
                repository_root / ".local/sudo/keycloak/age-key.txt",
                repository_root,
                "Keycloak SOPS/age key",
            )

    values = {"shell_identity_approval": approval}
    temporary = _write_temporary_variables(values, temporary_directory, repository_root)
    command = [
        "ansible-playbook",
        "--inventory",
        str(inventory),
        "--inventory",
        str(connection),
        "--extra-vars",
        f"@{temporary}",
    ]
    if action in {"configure", "bind"} and check:
        command.append("--check")
    command.append(
        str(
            repository_root
            / (
                "init/ansible/playbooks/configure-identity-service.yml"
                if action == "configure"
                else "init/ansible/playbooks/configure-keycloak-ldap-bind.yml"
                if action == "bind"
                else "init/ansible/playbooks/verify-identity-service.yml"
            )
        )
    )
    try:
        completed = run_process(command, cwd=str(repository_root), check=False)
        return int(completed.returncode)
    finally:
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    configure = actions.add_parser("configure", help="configure the FreeIPA service")
    configure.add_argument("--approval", default="")
    configure.add_argument("--check", action="store_true")
    bind = actions.add_parser("bind", help="configure the Keycloak LDAP bind principal")
    bind.add_argument("--approval", default="")
    bind.add_argument("--check", action="store_true")
    actions.add_parser("verify", help="verify the FreeIPA service")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return execute(
            args.action,
            approval=str(getattr(args, "approval", "")),
            check=bool(getattr(args, "check", False)),
        )
    except (OSError, IdentityLauncherError) as error:
        print(f"INIT identity launcher failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
