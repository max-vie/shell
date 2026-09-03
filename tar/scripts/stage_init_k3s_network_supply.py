#!/usr/bin/env python3
"""Stage verified Cilium network inputs for INIT."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import stage_init_supply as trusted_stage  # noqa: E402
from validate_init_k3s_network_supply import (  # noqa: E402
    NetworkSupplyError,
    validate_public,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPOSITORY_ROOT / "tar/manifests/init-k3s-network-supply.json"
NETWORK_ROOT = Path(".local/tar/init-k3s-network")
HELM_STAGE_PATH = NETWORK_ROOT / "helm"
CILIUM_CHART_STAGE_PATH = NETWORK_ROOT / "charts/cilium-1.18.2.tgz"
HANDOFF_PATH = Path(".local/ansible/k3s-network-supply.json")


class NetworkStageError(RuntimeError):
    """A Cilium network input could not be staged safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NetworkStageError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stage(
    helm_binary: Path,
    cilium_chart: Path,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    lock_path: Path = LOCK_PATH,
) -> tuple[Path, Path, Path]:
    """Stage the pinned Helm binary and Cilium chart with a private handoff."""

    repository_root = repository_root.resolve(strict=True)
    lock = validate_public(lock_path)
    artifacts = (
        (
            helm_binary,
            repository_root / HELM_STAGE_PATH,
            cast(dict[str, Any], lock["helm_binary"]),
            "Helm source binary",
        ),
        (
            cilium_chart,
            repository_root / CILIUM_CHART_STAGE_PATH,
            cast(dict[str, Any], lock["cilium_chart"]),
            "Cilium source chart",
        ),
    )

    sources: list[tuple[int, os.stat_result]] = []
    parents: list[int] = []
    try:
        for source, _, expected, label in artifacts:
            descriptor, metadata = trusted_stage._open_regular(source, label)
            sources.append((descriptor, metadata))
            require(
                metadata.st_size == expected["size"],
                f"{label} size does not match the lock",
            )

        handoff_path = repository_root / HANDOFF_PATH
        handoff = {
            "shell_k3s_helm_version": lock["helm_binary"]["version"],
            "shell_k3s_helm_path": str(repository_root / HELM_STAGE_PATH),
            "shell_k3s_helm_sha256": lock["helm_binary"]["sha256"],
            "shell_k3s_cilium_chart_path": str(
                repository_root / CILIUM_CHART_STAGE_PATH
            ),
            "shell_k3s_cilium_chart_sha256": lock["cilium_chart"]["sha256"],
            "shell_k3s_cilium_chart_version": lock["cilium_chart"]["version"],
            "shell_k3s_cilium_images": lock["cilium_images"],
            "shell_k3s_cilium_configuration": lock["cilium_configuration"],
        }
        rendered = (json.dumps(handoff, indent=2) + "\n").encode()

        handoff_parent = trusted_stage._open_private_directory(
            handoff_path.parent,
            repository_root,
        )
        parents.append(handoff_parent)
        handoff_exists = trusted_stage._verify_existing(
            handoff_parent,
            handoff_path.name,
            handoff_path,
            hashlib.sha256(rendered).hexdigest(),
            len(rendered),
        )

        output_data: list[tuple[int, Path, dict[str, Any], str]] = []
        for (_, output, expected, label), (_, metadata) in zip(
            artifacts, sources, strict=True
        ):
            parent = trusted_stage._open_private_directory(
                output.parent, repository_root
            )
            parents.append(parent)
            output_data.append((parent, output, expected, label))
            exists = trusted_stage._verify_existing(
                parent,
                output.name,
                output,
                cast(str, expected["sha256"]),
                cast(int, expected["size"]),
                metadata,
            )
            if handoff_exists:
                require(
                    exists,
                    f"private handoff exists while staged {label.lower()} is missing",
                )

        for (parent, output, expected, label), (descriptor, metadata) in zip(
            output_data, sources, strict=True
        ):
            trusted_stage._stage_binary(
                descriptor,
                metadata,
                parent,
                output.name,
                output,
                cast(str, expected["sha256"]),
                cast(int, expected["size"]),
                label,
            )

        trusted_stage._publish_bytes(
            handoff_parent,
            handoff_path.name,
            handoff_path,
            rendered,
        )
        return (
            repository_root / HELM_STAGE_PATH,
            repository_root / CILIUM_CHART_STAGE_PATH,
            handoff_path,
        )
    finally:
        for descriptor in parents:
            os.close(descriptor)
        for descriptor, _ in sources:
            os.close(descriptor)


def main(
    argv: list[str] | None = None,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    lock_path: Path = LOCK_PATH,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--helm-binary", type=Path, metavar="ABSOLUTE_PATH")
    parser.add_argument("--cilium-chart", type=Path, metavar="ABSOLUTE_PATH")
    args = parser.parse_args(argv)
    try:
        if args.validate_only:
            validate_public(lock_path)
            print("validated TAR Cilium network supply lock")
            return 0
        require(
            args.helm_binary is not None and args.cilium_chart is not None,
            "staging requires --helm-binary and --cilium-chart",
        )
        helm, chart, handoff = stage(
            args.helm_binary,
            args.cilium_chart,
            repository_root=repository_root,
            lock_path=lock_path,
        )
        print(f"staged verified Helm binary: {helm}")
        print(f"staged verified Cilium chart: {chart}")
        print(f"published private INIT network handoff: {handoff}")
        return 0
    except (
        NetworkStageError,
        NetworkSupplyError,
        trusted_stage.SupplyError,
        OSError,
    ) as error:
        print(f"TAR Cilium network staging failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
