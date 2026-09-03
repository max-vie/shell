#!/usr/bin/env python3
"""Run the fixed SHELL K3s configuration or verification workflow.

The launcher is the controller-side boundary for the two K3s playbooks. It
accepts a cluster name, derives every Ansible selector, and validates the
private handoffs before Ansible can connect to a guest.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat

# Every invocation below uses a fixed argv list and leaves shell execution off.
import subprocess  # nosec B404
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Callable, cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TAR_SCRIPTS = REPOSITORY_ROOT / "tar/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
import validate_init_k3s_network_supply as network_supply  # noqa: E402

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
VERSION_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:\+[A-Za-z0-9.-]+)?$")
ENDPOINT_PATTERN = re.compile(
    r"^https://([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):6443$"
)
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")
GCP_API_NETWORK = ipaddress.ip_network("10.77.0.0/24")
GCP_RESERVED_API_HOSTS = frozenset(
    ipaddress.ip_address(value)
    for value in (
        "10.77.0.201",
        "10.77.0.202",
        "10.77.0.203",
        "10.77.0.210",
        "10.77.0.211",
        "10.77.0.220",
        "10.77.0.221",
        "10.77.0.222",
    )
)
K3S_HOST_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.77.0.0/24", "10.66.0.0/24", "10.77.2.0/23")
)
GENERATED_TARGET_HOST_VARS = frozenset(
    {
        "ansible_host",
        "shell_expected_address",
        "shell_role",
        "shell_cluster",
        "shell_transport",
        "shell_operating_system",
        "shell_inventory_k3s_api_address",
        "shell_inventory_k3s_api_endpoint",
        "shell_inventory_k3s_api_host",
        "gcp_zone",
        "gcp_project_id",
        "shell_address_cidr",
        "proxmox_vm_id",
        "proxmox_node",
        "proxmox_host",
        "proxmox_host_address",
    }
)
CONNECTION_HOST_VARS = frozenset(
    {
        "ansible_connection",
        "ansible_user",
        "ansible_ssh_common_args",
        "ansible_ssh_private_key_file",
        "ansible_python_interpreter",
        "ansible_port",
        "gcp_known_hosts_file",
    }
)

CLUSTERS: dict[str, dict[str, Any]] = {
    "gcp": {
        "target_group": "gcp_k3s_servers",
        "hosts": ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"],
        "addresses": {
            "gcp-k3s-01": "10.77.0.201",
            "gcp-k3s-02": "10.77.0.202",
            "gcp-k3s-03": "10.77.0.203",
        },
        "transport": "gcp_iap",
        "vip_enabled": False,
        "runtime_keys": {"shell_k3s_pod_cidr", "shell_k3s_service_cidr"},
    },
    "proxmox": {
        "target_group": "proxmox_k3s_servers",
        "hosts": [
            "proxmox-k3s-01",
            "proxmox-k3s-02",
            "proxmox-k3s-03",
        ],
        "addresses": {
            "proxmox-k3s-01": "10.66.0.201",
            "proxmox-k3s-02": "10.66.0.202",
            "proxmox-k3s-03": "10.66.0.203",
        },
        "transport": "proxmox_ssh",
        "vip_enabled": True,
        "runtime_keys": {
            "shell_k3s_pod_cidr",
            "shell_k3s_service_cidr",
            "shell_k3s_api_vip_interface",
        },
    },
}


class RuntimeLauncherError(ValueError):
    """A K3s runtime handoff cannot be executed safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeLauncherError(message)


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeLauncherError("JSON contains duplicate object keys")
        value[key] = item
    return value


def _require_regular_file(path: Path, label: str) -> None:
    require(not path.is_symlink(), f"{label} must not be a symlink")
    require(path.is_file(), f"{label} must be a regular file")


def _check_path_components(path: Path, root: Path, label: str) -> None:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise RuntimeLauncherError(f"{label} escaped the repository") from error
    current = root
    for component in relative.parts:
        current /= component
        require(not current.is_symlink(), f"{label} contains a symlink")


def _check_private_parents(path: Path, root: Path, label: str) -> None:
    current = path.parent
    while current != root:
        require(current.is_dir(), f"{label} parent is not a directory")
        metadata = current.stat()
        require(metadata.st_uid == os.geteuid(), f"{label} parent has the wrong owner")
        require(
            stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE,
            f"{label} parent must have mode 0700",
        )
        current = current.parent
    require(current == root, f"{label} escaped the repository")


def _require_private_file(path: Path, label: str, repository_root: Path) -> None:
    _require_regular_file(path, label)
    _check_path_components(path, repository_root, label)
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
        f"{label} must have mode 0600",
    )
    _check_private_parents(path, repository_root, label)


def _require_private_directory(path: Path, repository_root: Path, label: str) -> None:
    _check_path_components(path, repository_root, label)
    require(path.is_dir(), f"{label} must be a directory")
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE,
        f"{label} must have mode 0700",
    )


def _read_json(
    path: Path, label: str, *, private: bool, repository_root: Path
) -> dict[str, Any]:
    if private:
        _require_private_file(path, label, repository_root)
    else:
        _require_regular_file(path, label)
        _check_path_components(path, repository_root, label)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeLauncherError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    return cast(dict[str, Any], value)


def _paths(repository_root: Path, cluster: str) -> dict[str, Path]:
    local = repository_root / ".local"
    ansible = local / "ansible"
    return {
        "inventory": ansible / "inventory.json",
        "connection": ansible / "connection-inventory.yml",
        "supply": ansible / "k3s-runtime-supply.json",
        "network_supply": ansible / "k3s-network-supply.json",
        "runtime": ansible / "k3s-runtime" / f"{cluster}.json",
        "temporary": ansible / ".k3s-runtime",
        "lock": repository_root / "tar/manifests/init-k3s-runtime-supply.json",
        "network_lock": repository_root / "tar/manifests/init-k3s-network-supply.json",
        "configure": repository_root
        / "init/ansible/playbooks/configure-k3s-runtime.yml",
        "verify": repository_root / "init/ansible/playbooks/verify-k3s-runtime.yml",
    }


def _cluster_contract(cluster: str) -> dict[str, Any]:
    try:
        return CLUSTERS[cluster]
    except KeyError as error:
        raise RuntimeLauncherError("cluster must be one of: gcp, proxmox") from error


def _validate_inventory_api(variables: dict[str, Any], cluster: str) -> tuple[str, str]:
    inventory_address = variables.get("shell_inventory_k3s_api_address")
    endpoint = variables.get("shell_inventory_k3s_api_endpoint")
    api_host = variables.get("shell_inventory_k3s_api_host")
    if not isinstance(inventory_address, str):
        raise RuntimeLauncherError("inventory API address is missing")
    if not isinstance(endpoint, str):
        raise RuntimeLauncherError("inventory API endpoint is missing")
    if not isinstance(api_host, str):
        raise RuntimeLauncherError("inventory API host is missing")
    match = ENDPOINT_PATTERN.fullmatch(endpoint)
    if match is None:
        raise RuntimeLauncherError("inventory API endpoint is invalid")
    require(match.group(1) == api_host, "inventory API host does not match endpoint")
    require(
        inventory_address == api_host,
        "inventory API address does not match endpoint host",
    )
    try:
        api_address = ipaddress.ip_address(api_host)
    except ValueError as error:
        raise RuntimeLauncherError(
            "inventory API host must be an IPv4 address"
        ) from error
    require(
        isinstance(api_address, ipaddress.IPv4Address),
        "inventory API host must be an IPv4 address",
    )
    if cluster == "gcp":
        require(
            api_address in GCP_API_NETWORK
            and api_address not in GCP_RESERVED_API_HOSTS
            and api_address
            not in {
                GCP_API_NETWORK.network_address,
                GCP_API_NETWORK.broadcast_address,
            },
            f"GCP API host must be an unreserved address in {GCP_API_NETWORK}",
        )
    if cluster == "proxmox":
        require(endpoint == "https://10.66.0.200:6443", "Proxmox API endpoint changed")
        require(api_host == "10.66.0.200", "Proxmox API host changed")
    return endpoint, api_host


def _require_inventory_host(host: dict[str, Any], name: str, cluster: str) -> None:
    contract = _cluster_contract(cluster)
    expected = contract["addresses"][name]
    require(host.get("ansible_host") == expected, f"{name} address changed")
    require(
        host.get("shell_expected_address") == expected,
        f"{name} expected address changed",
    )
    require(host.get("shell_role") == "k3s", f"{name} role changed")
    require(host.get("shell_cluster") == cluster, f"{name} cluster changed")
    require(
        host.get("shell_transport") == contract["transport"],
        f"{name} transport changed",
    )
    require(
        host.get("shell_operating_system") == "debian-13",
        f"{name} operating system changed",
    )


def _inventory_group(document: dict[str, Any], cluster: str) -> tuple[str, str]:
    contract = _cluster_contract(cluster)
    target_group = contract["target_group"]
    try:
        group = document["all"]["children"]["shell_nodes"]["children"][target_group]
    except (KeyError, TypeError) as error:
        raise RuntimeLauncherError(f"inventory is missing {target_group}") from error
    require(isinstance(group, dict), f"inventory group {target_group} is invalid")
    hosts = group.get("hosts")
    require(isinstance(hosts, dict), f"inventory group {target_group} has no hosts")
    require(
        list(hosts) == contract["hosts"],
        f"inventory group {target_group} must contain the exact ordered hosts",
    )
    variables = group.get("vars")
    require(isinstance(variables, dict), f"inventory group {target_group} has no vars")
    endpoint, api_host = _validate_inventory_api(variables, cluster)
    for name in contract["hosts"]:
        host = hosts[name]
        require(isinstance(host, dict), f"inventory host {name} is invalid")
        _require_inventory_host(host, name, cluster)
    return endpoint, api_host


def load_inventory(path: Path, cluster: str, repository_root: Path) -> tuple[str, str]:
    document = _read_json(
        path, "K3s inventory", private=True, repository_root=repository_root
    )
    return _inventory_group(document, cluster)


def _require_connection_host(host: dict[str, Any], name: str, cluster: str) -> None:
    unexpected = set(host) - GENERATED_TARGET_HOST_VARS - CONNECTION_HOST_VARS
    require(
        not unexpected,
        f"connection inventory added unsupported variables to {name}",
    )
    _require_inventory_host(host, name, cluster)
    connection = host.get("ansible_connection", "ssh")
    require(connection == "ssh", f"{name} must use the SSH connection plugin")
    user = host.get("ansible_user")
    if not isinstance(user, str) or not user or user == "root":
        raise RuntimeLauncherError(f"{name} requires a non-root SSH user")
    common_args = host.get("ansible_ssh_common_args")
    if not isinstance(common_args, str):
        raise RuntimeLauncherError(f"{name} requires reviewed SSH common arguments")
    require(
        "StrictHostKeyChecking=yes" in common_args
        and re.search(r"StrictHostKeyChecking=(?:no|off|accept-new)", common_args)
        is None,
        f"{name} requires strict SSH host-key checking",
    )
    if cluster == "gcp":
        for fragment in (
            "gcloud compute start-iap-tunnel",
            "{{ inventory_hostname | quote }}",
            "{{ gcp_project_id | quote }}",
            "{{ gcp_zone | quote }}",
        ):
            require(
                fragment in common_args,
                f"{name} must use the reviewed GCP IAP route",
            )
    else:
        require(
            "ProxyJump" in common_args or "ProxyCommand" in common_args,
            f"{name} must use the reviewed Proxmox proxy route",
        )
        require(
            "proxmox-host" in common_args or "10.77.0.220" in common_args,
            f"{name} must route through the declared Proxmox host",
        )
    if "ansible_port" in host:
        port = host["ansible_port"]
        require(
            isinstance(port, int) and not isinstance(port, bool) and port == 22,
            f"{name} must use SSH port 22",
        )


def _parse_inventory_output(stdout: Any) -> dict[str, Any]:
    if not isinstance(stdout, str):
        raise RuntimeLauncherError("Ansible inventory output is not text")
    try:
        value = json.loads(stdout, object_pairs_hook=_no_duplicate_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeLauncherError(
            "Ansible inventory output is not valid JSON"
        ) from error
    require(isinstance(value, dict), "Ansible inventory output must be an object")
    return cast(dict[str, Any], value)


def validate_connection_inventory(
    inventory_path: Path,
    connection_path: Path,
    cluster: str,
    repository_root: Path,
    run_process: Callable[..., Any],
) -> None:
    """Validate the effective target inventory before Ansible can connect."""

    baseline = _read_json(
        inventory_path,
        "K3s inventory",
        private=True,
        repository_root=repository_root,
    )
    baseline_endpoint, baseline_api_host = _inventory_group(baseline, cluster)
    contract = _cluster_contract(cluster)
    try:
        baseline_group = baseline["all"]["children"]["shell_nodes"]["children"][
            contract["target_group"]
        ]
    except (KeyError, TypeError) as error:
        raise RuntimeLauncherError(
            "K3s inventory target group is unavailable"
        ) from error
    if not isinstance(baseline_group, dict):
        raise RuntimeLauncherError("K3s inventory target group is invalid")
    baseline_hosts = baseline_group.get("hosts")
    if not isinstance(baseline_hosts, dict):
        raise RuntimeLauncherError("K3s inventory target hosts are unavailable")

    command = [
        "ansible-inventory",
        "--inventory",
        str(inventory_path),
        "--inventory",
        str(connection_path),
        "--list",
    ]
    completed = run_process(
        command,
        cwd=str(repository_root),
        check=False,
        capture_output=True,
        text=True,
    )
    require(
        completed.returncode == 0,
        "combined Ansible connection inventory could not be rendered",
    )
    document = _parse_inventory_output(completed.stdout)
    target = document.get(contract["target_group"])
    if not isinstance(target, dict):
        raise RuntimeLauncherError("combined inventory is missing the K3s target group")
    hosts = target.get("hosts")
    require(
        isinstance(hosts, list) and hosts == contract["hosts"],
        "combined inventory changed the exact ordered K3s target group",
    )
    metadata = document.get("_meta")
    if not isinstance(metadata, dict):
        raise RuntimeLauncherError("combined inventory has no host metadata")
    hostvars = metadata.get("hostvars")
    if not isinstance(hostvars, dict):
        raise RuntimeLauncherError("combined inventory has no host variables")
    expected_api = (baseline_endpoint, baseline_api_host)
    for name in contract["hosts"]:
        host = hostvars.get(name)
        if not isinstance(host, dict):
            raise RuntimeLauncherError(f"combined inventory is missing {name}")
        baseline_host = baseline_hosts.get(name)
        if not isinstance(baseline_host, dict):
            raise RuntimeLauncherError(f"K3s inventory baseline is missing {name}")
        for key, value in baseline_host.items():
            require(
                host.get(key) == value,
                f"connection inventory changed generated variable {key} on {name}",
            )
        _require_connection_host(host, name, cluster)
        api = _validate_inventory_api(host, cluster)
        require(
            api == expected_api,
            "combined inventory changed the shared K3s API contract",
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_supply(path: Path, lock_path: Path, repository_root: Path) -> dict[str, str]:
    handoff = _read_json(
        path, "TAR K3s handoff", private=True, repository_root=repository_root
    )
    lock = _read_json(
        lock_path, "TAR K3s supply lock", private=False, repository_root=repository_root
    )
    require(
        set(lock)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "policy_owner",
            "execution_owner",
            "proof_status",
            "k3s_binary",
            "kube_vip_image",
        },
        "TAR K3s supply lock shape changed",
    )
    require(
        lock["schema_version"] == "1.0"
        and lock["contract_version"] == "1.0.0"
        and lock["contract_id"] == "init-k3s-runtime-supply"
        and lock["policy_owner"] == "tar"
        and lock["execution_owner"] == "init"
        and lock["proof_status"] == "source-reference-only",
        "TAR K3s supply lock metadata changed",
    )
    k3s = lock.get("k3s_binary")
    kube_vip = lock.get("kube_vip_image")
    if not isinstance(k3s, dict):
        raise RuntimeLauncherError("TAR K3s binary lock is invalid")
    if not isinstance(kube_vip, dict):
        raise RuntimeLauncherError("TAR Kube-VIP lock is invalid")
    require(
        set(k3s) == {"version", "file_name", "source", "sha256", "size"},
        "TAR K3s binary lock shape changed",
    )
    require(
        set(kube_vip) == {"repository", "tag", "platform", "digest"},
        "TAR Kube-VIP lock shape changed",
    )
    source = k3s.get("source")
    if not isinstance(source, str):
        raise RuntimeLauncherError("TAR K3s source is invalid")
    source_url = urllib.parse.urlsplit(source)
    require(
        source_url.scheme == "https"
        and source_url.hostname == "github.com"
        and source_url.username is None
        and source_url.password is None,
        "TAR K3s source must be the official HTTPS URL",
    )
    require(k3s.get("file_name") == "k3s", "TAR K3s filename changed")
    require(kube_vip.get("platform") == "linux/amd64", "Kube-VIP platform changed")
    require(
        set(handoff)
        == {
            "shell_k3s_version",
            "shell_k3s_binary_path",
            "shell_k3s_binary_sha256",
            "shell_k3s_api_vip_image_repository",
            "shell_k3s_api_vip_image_digest",
        },
        "TAR K3s handoff shape changed",
    )
    version = handoff["shell_k3s_version"]
    require(version == k3s.get("version"), "K3s version changed")
    require(
        isinstance(version, str) and VERSION_PATTERN.fullmatch(version) is not None,
        "K3s version is invalid",
    )
    checksum = handoff["shell_k3s_binary_sha256"]
    require(
        checksum == k3s.get("sha256")
        and isinstance(checksum, str)
        and SHA256_PATTERN.fullmatch(checksum) is not None,
        "K3s binary checksum changed",
    )
    repository = handoff["shell_k3s_api_vip_image_repository"]
    digest = handoff["shell_k3s_api_vip_image_digest"]
    require(isinstance(repository, str), "Kube-VIP repository is invalid")
    require(isinstance(digest, str), "Kube-VIP digest is invalid")
    require(repository == kube_vip.get("repository"), "Kube-VIP repository changed")
    require(digest == kube_vip.get("digest"), "Kube-VIP digest changed")
    require(
        isinstance(digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
        "Kube-VIP digest is invalid",
    )
    binary_value = handoff["shell_k3s_binary_path"]
    require(isinstance(binary_value, str), "K3s binary path is invalid")
    binary = Path(binary_value)
    require(binary.is_absolute(), "K3s binary path must be absolute")
    expected_binary = repository_root / ".local/tar/init-k3s-runtime/k3s"
    require(binary == expected_binary, "K3s binary path changed")
    _require_private_file(binary, "staged K3s binary", repository_root)
    expected_size = k3s.get("size")
    require(
        isinstance(expected_size, int)
        and not isinstance(expected_size, bool)
        and expected_size > 0,
        "K3s size is invalid",
    )
    require(binary.stat().st_size == expected_size, "staged K3s binary size changed")
    require(
        _sha256(binary) == checksum, "staged K3s binary checksum does not match TAR"
    )
    return {
        "shell_k3s_version": version,
        "shell_k3s_binary_path": str(binary),
        "shell_k3s_binary_sha256": checksum,
        "shell_k3s_api_vip_image_repository": repository,
        "shell_k3s_api_vip_image_digest": digest,
    }


def load_runtime_vars(
    path: Path, cluster: str, repository_root: Path
) -> dict[str, str]:
    document = _read_json(
        path,
        "private K3s runtime variables",
        private=True,
        repository_root=repository_root,
    )
    contract = _cluster_contract(cluster)
    require(
        set(document) == contract["runtime_keys"], "K3s runtime variable shape changed"
    )
    result: dict[str, str] = {}
    networks: list[ipaddress.IPv4Network] = []
    for key in ("shell_k3s_pod_cidr", "shell_k3s_service_cidr"):
        value = document.get(key)
        if not isinstance(value, str):
            raise RuntimeLauncherError(f"{key} must be a string")
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise RuntimeLauncherError(f"{key} must be an IPv4 CIDR") from error
        if not isinstance(network, ipaddress.IPv4Network):
            raise RuntimeLauncherError(f"{key} must be an IPv4 CIDR")
        require(str(network) == value, f"{key} is not canonical")
        result[key] = value
        networks.append(network)
    require(networks[0] != networks[1], "K3s pod and service CIDRs must differ")
    require(
        not networks[0].overlaps(networks[1]),
        "K3s pod and service CIDRs must not overlap",
    )
    require(
        all(
            not network.overlaps(host_network)
            for network in networks
            for host_network in K3S_HOST_NETWORKS
        ),
        "K3s pod and service CIDRs overlap a declared host network",
    )
    if cluster == "proxmox":
        interface = document.get("shell_k3s_api_vip_interface")
        if not isinstance(interface, str):
            raise RuntimeLauncherError("Kube-VIP interface must be a string")
        require(
            INTERFACE_PATTERN.fullmatch(interface) is not None,
            "Kube-VIP interface is invalid",
        )
        result["shell_k3s_api_vip_interface"] = interface
    return result


def load_network_supply(
    path: Path, lock_path: Path, repository_root: Path
) -> dict[str, Any]:
    """Validate the private TAR-to-INIT Cilium handoff."""

    handoff = _read_json(
        path,
        "TAR Cilium network handoff",
        private=True,
        repository_root=repository_root,
    )
    lock = network_supply.validate_public(lock_path)
    require(
        set(handoff)
        == {
            "shell_k3s_helm_version",
            "shell_k3s_helm_path",
            "shell_k3s_helm_sha256",
            "shell_k3s_cilium_chart_path",
            "shell_k3s_cilium_chart_sha256",
            "shell_k3s_cilium_chart_version",
            "shell_k3s_cilium_images",
            "shell_k3s_cilium_configuration",
        },
        "TAR Cilium network handoff shape changed",
    )

    helm = cast(dict[str, Any], lock["helm_binary"])
    helm_path_value = handoff["shell_k3s_helm_path"]
    require(isinstance(helm_path_value, str), "Helm binary path is invalid")
    helm_path = Path(helm_path_value)
    expected_helm_path = repository_root / ".local/tar/init-k3s-network/helm"
    require(helm_path == expected_helm_path, "Helm binary path changed")
    _require_private_file(helm_path, "staged Helm binary", repository_root)
    require(
        handoff["shell_k3s_helm_version"] == helm["version"],
        "Helm version changed",
    )
    require(
        handoff["shell_k3s_helm_sha256"] == helm["sha256"],
        "Helm binary checksum changed",
    )
    require(helm_path.stat().st_size == helm["size"], "staged Helm binary size changed")
    require(
        _sha256(helm_path) == handoff["shell_k3s_helm_sha256"],
        "staged Helm binary checksum does not match TAR",
    )

    chart = cast(dict[str, Any], lock["cilium_chart"])
    chart_path_value = handoff["shell_k3s_cilium_chart_path"]
    require(isinstance(chart_path_value, str), "Cilium chart path is invalid")
    chart_path = Path(chart_path_value)
    expected_chart_path = (
        repository_root / ".local/tar/init-k3s-network/charts/cilium-1.18.2.tgz"
    )
    require(chart_path == expected_chart_path, "Cilium chart path changed")
    _require_private_file(chart_path, "staged Cilium chart", repository_root)
    require(
        handoff["shell_k3s_cilium_chart_version"] == chart["version"],
        "Cilium chart version changed",
    )
    require(
        handoff["shell_k3s_cilium_chart_sha256"] == chart["sha256"],
        "Cilium chart checksum changed",
    )
    require(
        chart_path.stat().st_size == chart["size"],
        "staged Cilium chart size changed",
    )
    require(
        _sha256(chart_path) == handoff["shell_k3s_cilium_chart_sha256"],
        "staged Cilium chart checksum does not match TAR",
    )
    require(
        handoff["shell_k3s_cilium_images"] == lock["cilium_images"],
        "Cilium image handoff changed",
    )
    require(
        handoff["shell_k3s_cilium_configuration"] == lock["cilium_configuration"],
        "Cilium configuration handoff changed",
    )
    return {
        "shell_k3s_helm_version": handoff["shell_k3s_helm_version"],
        "shell_k3s_helm_path": str(helm_path),
        "shell_k3s_helm_sha256": handoff["shell_k3s_helm_sha256"],
        "shell_k3s_cilium_chart_path": str(chart_path),
        "shell_k3s_cilium_chart_sha256": handoff["shell_k3s_cilium_chart_sha256"],
        "shell_k3s_cilium_chart_version": handoff["shell_k3s_cilium_chart_version"],
        "shell_k3s_cilium_images": handoff["shell_k3s_cilium_images"],
        "shell_k3s_cilium_configuration": handoff["shell_k3s_cilium_configuration"],
    }


def build_extra_vars(
    cluster: str,
    endpoint: str,
    api_host: str,
    supply: dict[str, str],
    network: dict[str, Any],
    runtime: dict[str, str],
) -> dict[str, Any]:
    contract = _cluster_contract(cluster)
    return {
        "shell_k3s_cluster_name": cluster,
        "shell_k3s_target_group": contract["target_group"],
        "shell_k3s_api_endpoint": endpoint,
        "shell_k3s_api_host": api_host,
        "shell_k3s_api_vip_enabled": contract["vip_enabled"],
        "shell_k3s_api_vip_address": "10.66.0.200",
        **supply,
        **network,
        **runtime,
    }


def _write_temporary_variables(
    values: dict[str, Any], temporary_directory: Path, repository_root: Path
) -> Path:
    _require_private_directory(
        temporary_directory, repository_root, "K3s temporary directory"
    )
    descriptor, name = tempfile.mkstemp(
        prefix=".runtime-", suffix=".json", dir=temporary_directory
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
    cluster: str,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    run_process: Callable[..., Any] = subprocess.run,
    check: bool = False,
) -> int:
    require(action in {"configure", "verify"}, "action must be configure or verify")
    repository_root = repository_root.resolve(strict=True)
    _cluster_contract(cluster)
    paths = _paths(repository_root, cluster)
    _require_private_file(
        paths["connection"], "private Ansible connection inventory", repository_root
    )
    endpoint, api_host = load_inventory(paths["inventory"], cluster, repository_root)
    validate_connection_inventory(
        paths["inventory"],
        paths["connection"],
        cluster,
        repository_root,
        run_process,
    )
    supply = load_supply(paths["supply"], paths["lock"], repository_root)
    network = load_network_supply(
        paths["network_supply"], paths["network_lock"], repository_root
    )
    runtime = load_runtime_vars(paths["runtime"], cluster, repository_root)
    values = build_extra_vars(cluster, endpoint, api_host, supply, network, runtime)
    temporary = _write_temporary_variables(values, paths["temporary"], repository_root)
    command = [
        "ansible-playbook",
        "--inventory",
        str(paths["inventory"]),
        "--inventory",
        str(paths["connection"]),
        "--extra-vars",
        f"@{temporary}",
    ]
    if action == "configure" and check:
        command.append("--check")
    command.append(
        str(paths["configure"] if action == "configure" else paths["verify"])
    )
    try:
        completed = run_process(command, cwd=str(repository_root), check=False)
        return int(completed.returncode)
    finally:
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    configure = actions.add_parser("configure", help="configure one K3s cluster")
    configure.add_argument("--cluster", choices=tuple(CLUSTERS), required=True)
    configure.add_argument(
        "--check", action="store_true", help="validate configuration without connecting"
    )
    verify = actions.add_parser("verify", help="verify one existing K3s cluster")
    verify.add_argument("--cluster", choices=tuple(CLUSTERS), required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return execute(
            args.action,
            args.cluster,
            check=bool(getattr(args, "check", False)),
        )
    except (OSError, RuntimeLauncherError, network_supply.NetworkSupplyError) as error:
        print(f"K3s runtime launcher failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
