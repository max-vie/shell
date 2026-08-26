#!/usr/bin/env python3
"""Validate and render the path-only MAKE delivery handoff.

The handoff binds the public SUDO, TAR, and INIT contracts to the fixed local
paths that a later Forgejo deployment may consume. It contains no credential,
certificate, key, or token values and never reads the private handoffs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPOSITORY_ROOT / ".local/make/delivery-ansible-vars.json"
PRIVATE_ROOT = ".local/sudo/delivery"
PRIVATE_INPUTS = {
    "bootstrap": f"{PRIVATE_ROOT}/bootstrap.sops.json",
    "forgejo_public_tls": f"{PRIVATE_ROOT}/forgejo-public-tls.sops.json",
    "age_key": f"{PRIVATE_ROOT}/age-key.txt",
}
PUBLIC_PATHS = {
    "sudo_profile": "sudo/access/delivery-host-profile.json",
    "sudo_input_contract": "sudo/secrets/delivery-input-contract.json",
    "tar_supply": "tar/manifests/delivery-supply.json",
    "service_contract": "make/contracts/service-node-handoff-requirements.json",
    "init_delivery_preview": "init/ansible/playbooks/configure-delivery-node.yml",
    "init_inventory": ".local/ansible/inventory.json",
    "init_connection_inventory": ".local/ansible/connection-inventory.yml",
    "root_ca": "sudo/pki/shell-offline-root.crt.pem",
}
HANDOFF_FIELDS = {
    "proof_status",
    "sudo_profile_path",
    "sudo_delivery_input_contract_path",
    "sudo_delivery_bootstrap_path",
    "sudo_forgejo_tls_path",
    "age_key_path",
    "tar_delivery_supply_path",
    "service_contract_path",
    "init_delivery_preview_path",
    "init_inventory_path",
    "init_connection_inventory_path",
    "service_node_id",
    "service_dns_domain",
    "service_dns_server",
    "service_fqdn",
    "service_port",
    "service_transport",
    "service_ca_path",
    "service_ca_sha256",
    "service_contract_digest",
}
MAX_PUBLIC_FILE_SIZE = 1024 * 1024


class DeliveryHandoffError(ValueError):
    """The public delivery handoff cannot safely be consumed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DeliveryHandoffError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    require(nofollow != 0 and directory != 0, "platform lacks safe directory flags")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | directory


def _file_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    require(nofollow != 0 and nonblock != 0, "platform lacks safe file flags")
    return os.O_RDONLY | os.O_CLOEXEC | nofollow | nonblock


def read_regular_file(path: Path, label: str) -> bytes:
    """Read one regular file without following any path-component symlink."""

    path = Path(os.path.abspath(path))
    parts = path.parts
    require(bool(parts) and parts[0] == os.sep, f"{label} must be absolute")
    require(".." not in parts, f"{label} contains parent traversal")
    try:
        current = os.open(os.sep, _directory_flags())
    except OSError as error:
        raise DeliveryHandoffError("cannot open the filesystem root safely") from error
    descriptor: int | None = None
    try:
        for component in parts[1:-1]:
            following = os.open(component, _directory_flags(), dir_fd=current)
            os.close(current)
            current = following
        descriptor = os.open(parts[-1], _file_flags(), dir_fd=current)
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
        require(
            metadata.st_size <= MAX_PUBLIC_FILE_SIZE,
            f"{label} exceeds the public file size limit",
        )
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            contents = stream.read(MAX_PUBLIC_FILE_SIZE + 1)
        require(
            len(contents) <= MAX_PUBLIC_FILE_SIZE,
            f"{label} exceeds the public file size limit",
        )
        return contents
    except OSError as error:
        raise DeliveryHandoffError(f"cannot read regular {label}: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(current)


def read_public_file(
    repository_root: Path, relative: str, label: str
) -> tuple[Path, bytes]:
    root = Path(os.path.abspath(repository_root))
    relative_path = Path(relative)
    require(
        not relative_path.is_absolute()
        and bool(relative_path.parts)
        and ".." not in relative_path.parts,
        f"{label} escaped the repository",
    )
    path = root / relative_path
    return path, read_regular_file(path, label)


def read_json(path: Path, label: str) -> dict[str, Any]:
    return read_json_bytes(read_regular_file(path, label), label)


def read_json_bytes(contents: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            contents.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeliveryHandoffError(f"invalid JSON for {label}") from error
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    return cast(dict[str, Any], value)


def require_no_symlinked_output(path: Path, label: str) -> None:
    """Refuse output paths that can redirect through a symlinked parent."""

    for component in (path, *path.parents):
        require(not component.is_symlink(), f"{label} contains a symlink")


def load_module(path: Path, name: str, source: bytes) -> ModuleType:
    module = ModuleType(name)
    module.__file__ = str(path)
    try:
        code = compile(source.decode("utf-8"), str(path), "exec")
        exec(code, module.__dict__)  # nosec B102
    except (OSError, UnicodeError, SyntaxError) as error:
        raise DeliveryHandoffError(f"cannot load {name}: {path}") from error
    return module


def validate_init_preview(source: str) -> None:
    required_fragments = (
        "hosts: delivery_nodes",
        "sudo/scripts/validate_access_contracts.py",
        "tar/scripts/validate_delivery_supply.py",
        "make/scripts/validate_service_node_handoff.py",
        "Refuse delivery mutation",
        "when: not ansible_check_mode",
    )
    for fragment in required_fragments:
        require(fragment in source, f"INIT delivery preview is missing: {fragment}")


def validate_public(repository_root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    """Validate public owner contracts and return path-only handoff data."""

    root = Path(os.path.abspath(repository_root))
    public_files = {
        name: read_public_file(root, relative, name.replace("_", " "))
        for name, relative in PUBLIC_PATHS.items()
        if not relative.startswith(".local/")
    }
    paths = {name: value[0] for name, value in public_files.items()}
    contents = {name: value[1] for name, value in public_files.items()}
    try:
        init_preview = contents["init_delivery_preview"].decode("utf-8")
    except UnicodeError as error:
        raise DeliveryHandoffError("INIT delivery preview is unreadable") from error
    validate_init_preview(init_preview)

    access_validator_path, access_validator_source = read_public_file(
        root,
        "sudo/scripts/validate_access_contracts.py",
        "SUDO access validator",
    )
    access_validator = load_module(
        access_validator_path,
        "delivery_access_validator",
        access_validator_source,
    )
    profile = read_json_bytes(contents["sudo_profile"], "SUDO delivery profile")
    access_validator.validate_delivery(profile, root)
    access_validator.validate_delivery_input_contract(root)

    service_validator_path, service_validator_source = read_public_file(
        root,
        "make/scripts/validate_service_node_handoff.py",
        "MAKE service validator",
    )
    service_validator = load_module(
        service_validator_path,
        "delivery_service_validator",
        service_validator_source,
    )
    service_contract = service_validator.validate_contract(
        paths["service_contract"], repository_root=root
    )

    supply_validator_path, supply_validator_source = read_public_file(
        root,
        "tar/scripts/validate_delivery_supply.py",
        "TAR delivery validator",
    )
    supply_validator = load_module(
        supply_validator_path,
        "delivery_supply_validator",
        supply_validator_source,
    )
    supply = supply_validator.validate_lock(paths["tar_supply"])

    try:
        root_contents = contents["root_ca"].decode("ascii")
    except UnicodeError as error:
        raise DeliveryHandoffError("SUDO public root CA is unreadable") from error
    require(
        root_contents.startswith("-----BEGIN CERTIFICATE-----")
        and root_contents.rstrip().endswith("-----END CERTIFICATE-----")
        and "PRIVATE KEY" not in root_contents,
        "SUDO public root CA is not public PEM data",
    )

    delivery_inputs = read_json_bytes(
        contents["sudo_input_contract"], "SUDO delivery input contract"
    )
    private_inputs = delivery_inputs["private_inputs"]
    require(
        private_inputs["bootstrap"]["path"] == PRIVATE_INPUTS["bootstrap"]
        and private_inputs["bootstrap"]["storage"] == "sops-age"
        and private_inputs["forgejo_public_tls"]["path"]
        == PRIVATE_INPUTS["forgejo_public_tls"]
        and private_inputs["forgejo_public_tls"]["storage"] == "sops-age"
        and private_inputs["age_key"]["path"] == PRIVATE_INPUTS["age_key"]
        and private_inputs["age_key"]["storage"] == "plaintext-age-identity"
        and private_inputs["age_key"]["consumer"] == "SOPS_AGE_KEY_FILE"
        and private_inputs["age_key"]["file_mode"] == "0600"
        and private_inputs["runtime"]["storage"]
        == "service-generated-private-state"
        and private_inputs["runtime"]["producer"] == "forgejo-after-bootstrap"
        and private_inputs["runtime"]["directory_mode"] == "0700",
        "SUDO delivery private paths changed",
    )

    delivery_host = profile["host"]
    delivery_trust = profile["trust"]
    delivery_service = profile["service"]
    required_identity = service_contract["required_identity"]
    required_service = service_contract["required_service"]
    required_artifacts = service_contract["required_artifacts"]
    require(
        required_identity["service_node_id"] == delivery_host["name"]
        and required_service["fqdn"] == delivery_service["fqdn"]
        and required_service["port"] == delivery_service["port"]
        and required_service["transport"] == delivery_service["transport"]
        and required_artifacts["platform"] == supply["runtime_image_platform"]
        and required_artifacts["images"] == supply["required_images"],
        "delivery handoff owner contracts do not agree",
    )

    handoff = {
        "proof_status": "source-only",
        "sudo_profile_path": str(paths["sudo_profile"]),
        "sudo_delivery_input_contract_path": str(paths["sudo_input_contract"]),
        "sudo_delivery_bootstrap_path": str(root / PRIVATE_INPUTS["bootstrap"]),
        "sudo_forgejo_tls_path": str(root / PRIVATE_INPUTS["forgejo_public_tls"]),
        "age_key_path": str(root / PRIVATE_INPUTS["age_key"]),
        "tar_delivery_supply_path": str(paths["tar_supply"]),
        "service_contract_path": str(paths["service_contract"]),
        "init_delivery_preview_path": str(paths["init_delivery_preview"]),
        "init_inventory_path": str(root / PUBLIC_PATHS["init_inventory"]),
        "init_connection_inventory_path": str(
            root / PUBLIC_PATHS["init_connection_inventory"]
        ),
        "service_node_id": required_identity["service_node_id"],
        "service_dns_domain": required_identity["trust_domain"],
        "service_dns_server": delivery_trust["dns_server"],
        "service_fqdn": required_service["fqdn"],
        "service_port": required_service["port"],
        "service_transport": required_service["transport"],
        "service_ca_path": str(paths["root_ca"]),
        "service_ca_sha256": hashlib.sha256(contents["root_ca"]).hexdigest(),
        "service_contract_digest": hashlib.sha256(
            contents["service_contract"]
        ).hexdigest(),
    }
    require(set(handoff) == HANDOFF_FIELDS, "delivery handoff shape changed")
    return handoff


def validate_handoff(
    path: Path, repository_root: Path = REPOSITORY_ROOT
) -> dict[str, Any]:
    """Validate a rendered path-only handoff without reading private paths."""

    require_no_symlinked_output(path, "delivery handoff")
    document = read_json(path, "delivery handoff")
    expected = validate_public(repository_root)
    require(set(document) == HANDOFF_FIELDS, "delivery handoff shape changed")
    require(document == expected, "delivery handoff does not match public contracts")
    require(
        all(isinstance(value, (str, int)) and value != "" for value in document.values()),
        "delivery handoff contains an empty value",
    )
    return document


def write_handoff(
    output: Path = DEFAULT_OUTPUT, repository_root: Path = REPOSITORY_ROOT
) -> dict[str, Any]:
    """Atomically write a mode-0600 path-only handoff."""

    data = validate_public(repository_root)
    output = Path(os.path.abspath(output))
    require_no_symlinked_output(output, "delivery handoff")
    private_root = Path(os.path.abspath(repository_root)) / ".local"
    try:
        output.relative_to(private_root)
    except ValueError:
        pass
    else:
        require(private_root.is_dir(), "private local root must be a directory")
        require(
            private_root.stat().st_uid == os.geteuid()
            and stat.S_IMODE(private_root.stat().st_mode) == 0o700,
            "private local root must be owner-only mode 0700",
        )
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        output.chmod(0o600)
        directory = os.open(
            output.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return data
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="validate public inputs without writing the handoff",
    )
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT, help="handoff output path"
    )
    parser.add_argument(
        "--validate", action="store_true", help="validate an existing handoff"
    )
    args = parser.parse_args()
    try:
        if args.validate:
            validate_handoff(args.output)
            print(f"validated MAKE delivery handoff: {args.output}")
        elif args.check_only:
            validate_public()
            print("validated MAKE delivery public contracts")
        else:
            write_handoff(args.output)
            print(f"rendered MAKE delivery handoff: {args.output}")
        return 0
    except (DeliveryHandoffError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"MAKE delivery handoff failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
