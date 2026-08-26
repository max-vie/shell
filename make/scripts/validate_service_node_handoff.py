#!/usr/bin/env python3
"""Validate MAKE's source-only delivery-node consumer contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPOSITORY_ROOT / "make/contracts/service-node-handoff-requirements.json"
EXPECTED_SOURCE_CONTRACTS = {
    "identity_profile": "sudo/access/freeipa-host-profile.json",
    "delivery_profile": "sudo/access/delivery-host-profile.json",
    "delivery_inputs": "sudo/secrets/delivery-input-contract.json",
    "artifact_supply": "tar/manifests/delivery-supply.json",
}
EXPECTED_PACKAGES = [
    "buildah",
    "ca-certificates",
    "dbus-user-session",
    "fuse-overlayfs",
    "podman",
    "podman-compose",
    "skopeo",
    "slirp4netns",
    "uidmap",
]
EXPECTED_IMAGES = ["forgejo", "forgejo_runner", "caddy", "node"]
EXPECTED_EXCLUDED_FIELDS = [
    "ip_address",
    "vcpus",
    "memory_mib",
    "disk_gib",
    "credential_values",
    "private_keys",
    "tokens",
]


class ServiceHandoffError(ValueError):
    """A MAKE service-node handoff is invalid or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ServiceHandoffError(message)


def require_object(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(dict[str, Any], value)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    for component in (path, *path.parents):
        require(not component.is_symlink(), f"unsafe symlinked {label}: {component}")
    require(path.is_file(), f"missing regular {label}: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ServiceHandoffError(f"invalid JSON file: {path}") from error
    return require_object(value, label)


def read_reference(
    value: Any,
    *,
    expected: str,
    repository_root: Path,
    label: str,
) -> dict[str, Any]:
    require(value == expected, f"{label} reference changed")
    relative = Path(expected)
    require(
        not relative.is_absolute() and ".." not in relative.parts,
        f"unsafe {label} reference",
    )
    path = repository_root / relative
    document = read_json_object(path, label)
    try:
        resolved_root = repository_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ServiceHandoffError(f"missing regular {label}: {path}") from error
    require(
        resolved_path.is_relative_to(resolved_root),
        f"unsafe {label}: outside repository",
    )
    return document


def validate_source_contracts(
    contract: dict[str, Any], repository_root: Path
) -> None:
    source_contracts = require_object(
        contract.get("source_contracts"), "source contracts"
    )
    require(
        source_contracts == EXPECTED_SOURCE_CONTRACTS,
        "service source contracts changed",
    )
    references = {
        name: read_reference(
            source_contracts.get(name),
            expected=relative,
            repository_root=repository_root,
            label=name.replace("_", " "),
        )
        for name, relative in EXPECTED_SOURCE_CONTRACTS.items()
    }

    identity = references["identity_profile"]
    require(
        identity.get("contract_id") == "freeipa-host-profile",
        "identity profile ID changed",
    )
    require(
        identity.get("policy_owner") == "sudo",
        "SUDO must own the identity profile",
    )
    require(
        identity.get("proof_status") == "source-only",
        "identity profile proof changed",
    )
    identity_host = require_object(identity.get("host"), "identity host")

    delivery = references["delivery_profile"]
    require(
        delivery.get("contract_id") == "delivery-host-profile",
        "delivery profile ID changed",
    )
    require(
        delivery.get("policy_owner") == "sudo",
        "SUDO must own the delivery profile",
    )
    require(
        delivery.get("proof_status") == "source-only",
        "delivery profile proof changed",
    )
    delivery_host = require_object(delivery.get("host"), "delivery host")
    delivery_trust = require_object(delivery.get("trust"), "delivery trust")
    delivery_service = require_object(delivery.get("service"), "delivery service")

    delivery_inputs = references["delivery_inputs"]
    require(
        delivery_inputs.get("contract_id") == "delivery-input-contract",
        "delivery input contract ID changed",
    )
    require(
        delivery_inputs.get("policy_owner") == "sudo",
        "SUDO must own delivery inputs",
    )
    require(
        delivery_inputs.get("proof_status") == "source-only",
        "delivery input proof changed",
    )
    require(
        delivery_inputs.get("repository_policy")
        == {"contract_tracked": True, "private_values_tracked": False},
        "delivery input repository policy changed",
    )
    input_classes = require_object(
        delivery_inputs.get("classes"), "delivery input classes"
    )
    tls_input = require_object(
        input_classes.get("forgejo_public_tls"), "Forgejo TLS input"
    )

    supply = references["artifact_supply"]
    require(
        supply.get("contract_id") == "delivery-supply",
        "artifact supply ID changed",
    )
    require(
        supply.get("policy_owner") == "tar",
        "TAR must own artifact supply",
    )
    require(
        supply.get("proof_status") == "source-reference-only",
        "artifact supply proof changed",
    )

    required_identity = require_object(
        contract.get("required_identity"), "required identity"
    )
    required_os = require_object(
        required_identity.get("os"), "required operating system"
    )
    required_service = require_object(
        contract.get("required_service"), "required service"
    )
    required_artifacts = require_object(
        contract.get("required_artifacts"), "required artifacts"
    )

    require(
        required_identity.get("service_node_id") == delivery_host.get("name"),
        "delivery host name mismatch",
    )
    require(
        f"{required_os.get('name')}-{required_os.get('major_version')}"
        == delivery_host.get("operating_system"),
        "delivery operating system mismatch",
    )
    require(
        required_identity.get("trust_domain") == delivery_trust.get("domain"),
        "delivery trust domain mismatch",
    )
    require(
        contract["trust"]["dns_server"] == identity_host.get("ip_address"),
        "identity DNS address mismatch",
    )
    require(
        contract["trust"]["dns_server"] == delivery_trust.get("dns_server"),
        "delivery DNS address mismatch",
    )
    require(
        required_service.get("name") == delivery_service.get("name"),
        "delivery service name mismatch",
    )
    require(
        required_service.get("fqdn") == delivery_service.get("fqdn"),
        "delivery service FQDN mismatch",
    )
    require(
        required_service.get("port") == delivery_service.get("port"),
        "delivery service port mismatch",
    )
    require(
        required_service.get("transport") == delivery_service.get("transport"),
        "delivery transport mismatch",
    )
    require(
        required_service.get("tls_dns_sans")
        == delivery_service.get("certificate_dns_sans")
        == tls_input.get("dns_sans"),
        "delivery TLS names mismatch",
    )
    require(
        tls_input.get("issuer") == "sudo",
        "SUDO must issue the public TLS input",
    )
    require(
        tls_input.get("deployment_target") == delivery_host.get("name"),
        "delivery TLS target mismatch",
    )
    require(
        contract["trust"]["forgejo_host"] == required_service.get("fqdn"),
        "Forgejo trust host mismatch",
    )
    require(
        required_artifacts.get("platform") == supply.get("runtime_image_platform"),
        "artifact platform mismatch",
    )
    require(
        required_artifacts.get("images") == supply.get("required_images"),
        "required artifact set mismatch",
    )

    dns_records = identity.get("managed_dns_records")
    require(isinstance(dns_records, list), "identity DNS records must be a list")
    dns_record_list = cast(list[Any], dns_records)
    require(
        any(
            isinstance(record, dict)
            and record.get("fqdn") == required_service.get("fqdn")
            and record.get("address") == delivery_host.get("ip_address")
            and record.get("service_owner") == "make"
            for record in dns_record_list
        ),
        "Forgejo DNS record mismatch",
    )


def validate_contract(
    path: Path = CONTRACT_PATH,
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    """Validate the delivery-node requirements and referenced public contracts."""

    contract = read_json_object(path, "service handoff")
    require(
        set(contract)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "producer_owner",
            "consumer_owners",
            "proof_status",
            "source_contracts",
            "required_identity",
            "required_rootless_packages",
            "trust",
            "required_service",
            "required_artifacts",
            "excluded_fields",
        },
        "service handoff shape changed",
    )
    require(contract["schema_version"] == "1.0", "service handoff schema changed")
    require(
        contract["contract_version"] == "1.0.0",
        "service handoff version changed",
    )
    require(
        contract["contract_id"] == "service-node-handoff-requirements",
        "service handoff ID changed",
    )
    require(
        contract["policy_owner"] == "make",
        "MAKE must own service requirements",
    )
    require(
        contract["producer_owner"] == "init",
        "INIT must produce service handoff",
    )
    require(contract["consumer_owners"] == ["make"], "service consumers changed")
    require(
        contract["proof_status"] == "source-only",
        "service handoff must remain source-only",
    )
    require(
        contract["required_identity"]
        == {
            "service_node_id": "delivery-01",
            "role": "delivery",
            "os": {"name": "debian", "major_version": 13},
            "trust_domain": "shell.internal",
        },
        "service identity requirements changed",
    )
    require(
        contract["required_rootless_packages"] == EXPECTED_PACKAGES,
        "rootless package requirements changed",
    )
    require(
        contract["trust"]
        == {
            "dns_server": "10.77.0.210",
            "forgejo_host": "forgejo.shell.internal",
        },
        "service trust requirements changed",
    )
    require(
        contract["required_service"]
        == {
            "name": "forgejo",
            "fqdn": "forgejo.shell.internal",
            "port": 443,
            "transport": "https",
            "tls_dns_sans": ["forgejo.shell.internal"],
        },
        "service endpoint requirements changed",
    )
    require(
        contract["required_artifacts"]
        == {"platform": "linux/amd64", "images": EXPECTED_IMAGES},
        "service artifact requirements changed",
    )
    require(
        contract["excluded_fields"] == EXPECTED_EXCLUDED_FIELDS,
        "service producer boundary changed",
    )
    validate_source_contracts(contract, repository_root)
    return contract


def main() -> int:
    try:
        validate_contract()
    except ServiceHandoffError as error:
        print(f"service handoff validation failed: {error}", file=sys.stderr)
        return 2
    print("validated service-node handoff requirements and source contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
