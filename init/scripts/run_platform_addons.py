#!/usr/bin/env python3
"""Fixed INIT launcher for the GCP platform add-on playbooks."""

from __future__ import annotations

import argparse
import json
import os
import site
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))
import run_k3s_runtime as k3s_runtime  # noqa: E402

INVENTORY = ROOT / ".local/ansible/inventory.json"
CONNECTION_INVENTORY = ROOT / ".local/ansible/connection-inventory.yml"
PLAYBOOK_ROOT = ROOT / "init/ansible/playbooks"
COLLECTIONS_ROOT = Path(site.getusersitepackages()) / "ansible_collections"
COLLECTIONS_PATH = str(COLLECTIONS_ROOT)
GROUP = "gcp_k3s_servers"
CONFIGURE_APPROVAL = "environment-gcp/init/platform-hosts"
FORMAT_APPROVAL = "environment-gcp/init/platform-hosts-format"
TRUST_APPROVAL = "environment-gcp/init/registry-trust"
PLAYBOOKS = {
    "configure": "configure-platform-addons.yml",
    "verify": "verify-platform-addons.yml",
    "registry-trust": "configure-platform-registry-trust.yml",
    "registry-trust-verify": "verify-platform-registry-trust.yml",
}


class PlatformLauncherError(RuntimeError):
    """The fixed platform launcher rejected its inputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlatformLauncherError(message)


def private_file(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    require(value.is_relative_to(ROOT), f"{label} must remain inside the repository")
    for component in (value, *value.parents):
        require(not component.is_symlink(), f"{label} contains a symlink")
    require(value.is_file() and not value.is_symlink(), f"{label} is missing")
    require(stat.S_IMODE(value.stat().st_mode) == 0o600, f"{label} must be mode 0600")
    require(value.stat().st_uid == os.geteuid(), f"{label} has the wrong owner")
    for parent in value.parents:
        if parent == ROOT:
            break
        require(
            parent.is_dir()
            and parent.stat().st_uid == os.geteuid()
            and stat.S_IMODE(parent.stat().st_mode) == 0o700,
            f"{label} parent must be owned and mode 0700",
        )
    return value


def load_inventory(path: Path) -> dict[str, Any]:
    private_file(path, "INIT inventory")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PlatformLauncherError("INIT inventory is invalid JSON") from error
    require(isinstance(value, dict), "INIT inventory must be an object")
    return cast(dict[str, Any], value)


def validate_ansible_posix() -> None:
    collection = COLLECTIONS_ROOT / "ansible/posix"
    manifest = collection / "MANIFEST.json"
    for path in (COLLECTIONS_ROOT, *COLLECTIONS_ROOT.parents):
        require(not path.is_symlink(), "Ansible collection path contains a symlink")
    for path in (COLLECTIONS_ROOT, collection.parent, collection, manifest):
        require(not path.is_symlink(), "Ansible collection path contains a symlink")
        require(path.exists(), "ansible.posix collection path is missing")
        require(path.stat().st_uid == os.geteuid(), "Ansible collection has wrong owner")
    require(collection.is_dir(), "ansible.posix collection is missing")
    require(manifest.is_file(), "ansible.posix manifest is missing")
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PlatformLauncherError("ansible.posix manifest is invalid") from error
    information = document.get("collection_info")
    require(isinstance(information, dict), "ansible.posix identity is missing")
    require(
        information.get("namespace") == "ansible"
        and information.get("name") == "posix"
        and information.get("version") == "2.2.0",
        "ansible.posix must be version 2.2.0",
    )


def run_ansible(
    command: list[str], **kwargs: Any
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["ANSIBLE_COLLECTIONS_PATH"] = COLLECTIONS_PATH
    return subprocess.run(command, env=environment, **kwargs)  # nosec B603


def validate_inventory(path: Path) -> None:
    document = load_inventory(path)
    all_group = document.get("all", {})
    require(isinstance(all_group, dict), "INIT inventory has no all group")
    groups = all_group.get("children", {})
    require(isinstance(groups, dict), "INIT inventory has no children")
    shell_nodes = groups.get("shell_nodes")
    require(isinstance(shell_nodes, dict), "INIT inventory has no shell_nodes group")
    platform_groups = shell_nodes.get("children")
    require(isinstance(platform_groups, dict), "INIT inventory has no platform groups")
    target = platform_groups.get(GROUP)
    require(isinstance(target, dict), "INIT inventory has no GCP K3s group")
    hosts = target.get("hosts")
    require(
        isinstance(hosts, dict)
        and list(hosts) == ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"],
        "INIT inventory GCP K3s host set changed",
    )


def run(
    action: str,
    *,
    check: bool,
    approval: str = "",
    format_data_disk: bool = False,
) -> None:
    require(action in PLAYBOOKS, "unsupported platform action")
    require(
        not format_data_disk or action == "configure",
        "data-disk formatting is valid only for configure",
    )
    validate_inventory(INVENTORY)
    private_file(CONNECTION_INVENTORY, "INIT connection inventory")
    validate_ansible_posix()
    try:
        k3s_runtime.validate_connection_inventory(
            INVENTORY,
            CONNECTION_INVENTORY,
            "gcp",
            ROOT,
            run_ansible,
        )
    except k3s_runtime.RuntimeLauncherError as error:
        raise PlatformLauncherError(str(error)) from error
    if not check and action == "configure":
        expected = FORMAT_APPROVAL if format_data_disk else CONFIGURE_APPROVAL
        require(approval == expected, f"approval must be {expected}")
    if not check and action == "registry-trust":
        require(approval == TRUST_APPROVAL, f"approval must be {TRUST_APPROVAL}")
    playbook = PLAYBOOK_ROOT / PLAYBOOKS[action]
    require(
        playbook.is_file() and not playbook.is_symlink(),
        "platform playbook is missing",
    )
    command = ["ansible-playbook"]
    for path in (INVENTORY, CONNECTION_INVENTORY):
        command.extend(["-i", str(path)])
    command.extend([str(playbook), "-e", f"shell_platform_target_group={GROUP}"])
    if format_data_disk:
        command.extend(["-e", "shell_platform_format_data_disk=true"])
    if check:
        command.insert(1, "--check")
    try:
        result = run_ansible(
            command,
            cwd=ROOT,
            check=False,
            timeout=1800,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PlatformLauncherError("platform Ansible invocation failed") from error
    if result.returncode:
        raise PlatformLauncherError("platform Ansible invocation returned an error")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=PLAYBOOKS)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--approval", default="")
    parser.add_argument("--format-data-disk", action="store_true")
    args = parser.parse_args(argv)
    try:
        run(
            args.action,
            check=args.check,
            approval=args.approval,
            format_data_disk=args.format_data_disk,
        )
    except PlatformLauncherError as error:
        print(f"INIT platform launcher refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
