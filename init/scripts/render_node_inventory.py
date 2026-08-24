"""Render the private Ansible inventory from the three OpenTofu roots.

OpenTofu remains the source of truth for node names, addresses, zones, and VM
IDs. This adapter validates those facts, derives role and transport labels from
the owning root, and writes a JSON inventory for Ansible. It does not run
OpenTofu, read credentials, start guests, or connect to a host.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
# Anchor private handoff data to the checkout, independent of the caller's
# working directory.
DEFAULT_OUTPUT = REPOSITORY_ROOT / ".local" / "ansible" / "inventory.json"
EXPECTED_SHARED = {
    "identity-01": "identity",
    "delivery-01": "delivery",
}
EXPECTED_GCP_K3S = {
    "gcp-k3s-01",
    "gcp-k3s-02",
    "gcp-k3s-03",
}
EXPECTED_PROXMOX_K3S = {
    "proxmox-k3s-01",
    "proxmox-k3s-02",
    "proxmox-k3s-03",
}
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class InventoryError(ValueError):
    """Raised when OpenTofu output cannot safely become inventory."""


def load_json(path: Path, label: str) -> Any:
    if path.is_symlink() or not path.is_file():
        raise InventoryError(f"{label} must be a regular file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise InventoryError(f"{label} is not valid JSON: {path}") from error


def output_map(value: Any, key: str, label: str) -> dict[str, Any]:
    """Accept either `tofu output -json NAME` or the complete output object."""

    if not isinstance(value, dict):
        raise InventoryError(f"{label} must contain a node mapping")
    if key in value:
        envelope = value[key]
        required = {"sensitive", "type", "value"}
        if not isinstance(envelope, dict) or not required.issubset(envelope):
            raise InventoryError(f"{label} has a malformed complete output envelope")
        if not isinstance(envelope["sensitive"], bool):
            raise InventoryError(f"{label} output sensitivity metadata must be boolean")
        value = envelope["value"]
    elif any(
        isinstance(item, dict) and {"sensitive", "type", "value"}.issubset(item)
        for item in value.values()
    ):
        raise InventoryError(f"complete output is missing {key}")
    if not isinstance(value, dict):
        raise InventoryError(f"{label} must contain a node mapping")
    return value


def require_string(value: Any, field: str, node_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InventoryError(f"{node_name} requires a non-empty {field}")
    return value


def is_rfc1918(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return isinstance(address, ipaddress.IPv4Address) and any(
        address in network for network in RFC1918_NETWORKS
    )


def private_ipv4(value: Any, field: str, node_name: str) -> str:
    # GCP output is a host address without a prefix. Reject public addresses
    # before they can become an Ansible connection target.
    raw = require_string(value, field, node_name)
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as error:
        raise InventoryError(f"{node_name} has an invalid {field}: {raw}") from error
    if not is_rfc1918(address):
        raise InventoryError(
            f"{node_name} {field} must be an RFC1918 IPv4 address: {raw}"
        )
    return str(address)


def private_interface(value: Any, field: str, node_name: str) -> tuple[str, str]:
    # Proxmox output includes the guest prefix. Preserve the CIDR for later
    # network checks while giving Ansible the address portion separately.
    raw = require_string(value, field, node_name)
    if "/" not in raw:
        raise InventoryError(f"{node_name} {field} must be a usable host CIDR: {raw}")
    try:
        interface = ipaddress.ip_interface(raw)
    except ValueError as error:
        raise InventoryError(f"{node_name} has an invalid {field}: {raw}") from error
    if not is_rfc1918(interface.ip):
        raise InventoryError(f"{node_name} {field} must be an RFC1918 IPv4 CIDR: {raw}")
    if interface.network.prefixlen == 0 or (
        interface.network.prefixlen <= 30
        and interface.ip
        in {interface.network.network_address, interface.network.broadcast_address}
    ):
        raise InventoryError(f"{node_name} {field} must be a usable host CIDR: {raw}")
    return str(interface.ip), str(interface)


def exact_names(actual: dict[str, Any], expected: set[str], label: str) -> None:
    # A complete set comparison prevents a partial or newly invented root
    # output from silently changing the Ansible target set.
    actual_names = set(actual)
    if actual_names != expected:
        missing = sorted(expected - actual_names)
        extra = sorted(actual_names - expected)
        raise InventoryError(f"{label} set differs: missing={missing}, extra={extra}")


def normalize_gcp_nodes(
    nodes: dict[str, Any], expected: dict[str, str] | set[str], cluster: str
) -> list[dict[str, Any]]:
    expected_names = set(expected)
    exact_names(nodes, expected_names, f"{cluster} GCP node")
    normalized: list[dict[str, Any]] = []
    for name in sorted(nodes):
        record = nodes[name]
        if not isinstance(record, dict):
            raise InventoryError(f"{name} must contain an object")
        if require_string(record.get("name"), "name", name) != name:
            raise InventoryError(f"{name} output name does not match its map key")
        address = private_ipv4(record.get("internal_ip"), "internal_ip", name)
        zone = require_string(record.get("zone"), "zone", name)
        # These values are derived from the owning root. The current OpenTofu
        # outputs carry infrastructure facts, not Ansible policy labels.
        role = expected[name] if isinstance(expected, dict) else "k3s"
        normalized.append(
            {
                "name": name,
                "address": address,
                "role": role,
                "cluster": cluster,
                "transport": "gcp_iap",
                "gcp_zone": zone,
            }
        )
    return normalized


def normalize_proxmox_nodes(nodes: dict[str, Any]) -> list[dict[str, Any]]:
    exact_names(nodes, EXPECTED_PROXMOX_K3S, "Proxmox K3s node")
    normalized: list[dict[str, Any]] = []
    for name in sorted(nodes):
        record = nodes[name]
        if not isinstance(record, dict):
            raise InventoryError(f"{name} must contain an object")
        if require_string(record.get("name"), "name", name) != name:
            raise InventoryError(f"{name} output name does not match its map key")
        address, address_cidr = private_interface(
            record.get("address"), "address", name
        )
        vm_id = record.get("vm_id")
        if isinstance(vm_id, bool) or not isinstance(vm_id, int) or vm_id <= 0:
            raise InventoryError(f"{name} requires a positive JSON integer vm_id")
        # Keep the PVE placement facts for the later ProxyJump/guest workflow;
        # they are not credentials and do not start or inspect the host.
        pve_node = require_string(record.get("node"), "node", name)
        normalized.append(
            {
                "name": name,
                "address": address,
                "address_cidr": address_cidr,
                "role": "k3s",
                "cluster": "proxmox",
                "transport": "proxmox_ssh",
                "proxmox_vm_id": vm_id,
                "proxmox_node": pve_node,
            }
        )
    return normalized


def validate_unique_nodes(nodes: list[dict[str, Any]]) -> None:
    # Addresses must be unique across both independent clusters. VM IDs only
    # exist on Proxmox, so that check is limited to records that carry one.
    addresses = [node["address"] for node in nodes]
    if len(addresses) != len(set(addresses)):
        raise InventoryError("node addresses must be unique across all clusters")
    vm_ids = [node["proxmox_vm_id"] for node in nodes if "proxmox_vm_id" in node]
    if len(vm_ids) != len(set(vm_ids)):
        raise InventoryError("Proxmox VM IDs must be unique")


def inventory(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    # Keep cluster groups separate while exposing role groups for later
    # identity and delivery playbooks.
    group_hosts: dict[str, dict[str, dict[str, Any]]] = {
        "gcp_shared_nodes": {},
        "gcp_k3s_servers": {},
        "proxmox_k3s_servers": {},
    }
    role_hosts: dict[str, dict[str, dict[str, Any]]] = {
        "identity_nodes": {},
        "delivery_nodes": {},
    }

    for node in nodes:
        name = node["name"]
        hostvars = {
            "ansible_host": node["address"],
            "shell_expected_address": node["address"],
            "shell_role": node["role"],
            "shell_cluster": node["cluster"],
            "shell_transport": node["transport"],
        }
        if node["transport"] == "gcp_iap":
            hostvars["gcp_zone"] = node["gcp_zone"]
            group = (
                "gcp_shared_nodes" if node["cluster"] == "shared" else "gcp_k3s_servers"
            )
        else:
            hostvars.update(
                {
                    "shell_address_cidr": node["address_cidr"],
                    "proxmox_vm_id": node["proxmox_vm_id"],
                    "proxmox_node": node["proxmox_node"],
                }
            )
            group = "proxmox_k3s_servers"
        group_hosts[group][name] = hostvars
        if node["role"] == "identity":
            role_hosts["identity_nodes"][name] = {}
        if node["role"] == "delivery":
            role_hosts["delivery_nodes"][name] = {}

    return {
        "all": {
            "children": {
                "shell_nodes": {
                    "children": {
                        group: {"hosts": hosts} for group, hosts in group_hosts.items()
                    }
                },
                **{group: {"hosts": hosts} for group, hosts in role_hosts.items()},
            }
        }
    }


def build_inventory(args: argparse.Namespace) -> dict[str, Any]:
    # Each file is one OpenTofu root's output. Accepting named or raw outputs
    # keeps the handoff read-only and avoids a shared-state dependency here.
    shared = output_map(
        load_json(args.shared_nodes_file, "shared nodes"),
        "shared_nodes",
        "shared nodes",
    )
    gcp_k3s = output_map(
        load_json(args.gcp_k3s_file, "GCP K3s nodes"), "k3s_nodes", "GCP K3s nodes"
    )
    proxmox = output_map(
        load_json(args.proxmox_k3s_file, "Proxmox K3s nodes"),
        "nodes",
        "Proxmox K3s nodes",
    )
    nodes = [
        *normalize_gcp_nodes(shared, EXPECTED_SHARED, "shared"),
        *normalize_gcp_nodes(gcp_k3s, EXPECTED_GCP_K3S, "gcp"),
        *normalize_proxmox_nodes(proxmox),
    ]
    validate_unique_nodes(nodes)
    return inventory(nodes)


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    # Local path checks keep generated inventory inside a private handoff. The
    # temporary file and destination share a directory, making replace atomic.
    path = Path(os.path.abspath(path))
    for component in (path, *path.parents):
        if component.is_symlink():
            raise InventoryError(f"refusing symlinked output path: {component}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory_mode = stat.S_IMODE(path.parent.stat().st_mode)
    if directory_mode & 0o077:
        raise InventoryError(f"output directory must be private: {path.parent}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shared-nodes-file", type=Path, required=True)
    parser.add_argument("--gcp-k3s-file", type=Path, required=True)
    parser.add_argument("--proxmox-k3s-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the three outputs without writing an inventory",
    )
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        value = build_inventory(args)
        if not args.validate_only:
            atomic_write(args.output, value)
    except (InventoryError, OSError) as error:
        print(f"inventory handoff failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
