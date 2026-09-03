#!/usr/bin/env python3
"""Stage checksum-locked Kubernetes admission inputs for MAKE."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_kubernetes_supply import (  # noqa: E402
    SupplyError,
    _check_no_symlink_components,
    sha256_file,
    validate_public,
)


PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
EXECUTABLE_FILE_MODE = 0o700
CHUNK_SIZE = 1024 * 1024


class StageError(RuntimeError):
    """A Kubernetes supply artifact could not be staged safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StageError(message)


def safe_path(path: Path, label: str) -> Path:
    try:
        return _check_no_symlink_components(path, label)
    except SupplyError as error:
        raise StageError(str(error)) from error


def ensure_directory(path: Path, label: str) -> Path:
    path = safe_path(path, label)
    require(not path.is_symlink(), f"{label} must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIRECTORY_MODE)
    require(path.is_dir() and not path.is_symlink(), f"{label} must be a directory")
    path.chmod(PRIVATE_DIRECTORY_MODE)
    return path


def artifact_hash(path: Path, size: int) -> str:
    require(path.stat().st_size == size, "staged artifact size changed")
    return sha256_file(path)


def stage_download(
    target: Path,
    metadata: dict[str, Any],
    *,
    label: str,
    opener: Callable[..., Any],
    executable: bool = False,
) -> Path:
    target = safe_path(target, label)
    mode = EXECUTABLE_FILE_MODE if executable else PRIVATE_FILE_MODE
    expected_sha256 = metadata.get("sha256") or metadata["source_sha256"]
    if target.exists():
        require(not target.is_symlink() and target.is_file(), f"existing {label} is not regular")
        require(stat.S_IMODE(target.stat().st_mode) == mode, f"existing {label} mode changed")
        require(target.stat().st_size == metadata["size"], f"existing {label} size changed")
        require(artifact_hash(target, metadata["size"]) == expected_sha256, f"existing {label} checksum changed")
        return target

    source = urllib.parse.urlsplit(metadata["source"])
    require(source.scheme == "https", f"{label} source must use HTTPS")
    allowed_hosts = {source.netloc, *metadata["redirect_hosts"]}
    request = urllib.request.Request(
        metadata["source"],
        headers={"User-Agent": "shell-kubernetes-supply/1"},
    )
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", dir=target.parent
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output, opener(
            request, timeout=180
        ) as response:
            final = urllib.parse.urlsplit(response.geturl())
            require(
                final.scheme == "https" and final.netloc in allowed_hosts,
                f"{label} redirected outside its approved HTTPS hosts",
            )
            total = 0
            while True:
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= metadata["max_bytes"], f"{label} exceeds its size ceiling")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        require(total == metadata["size"], f"{label} size does not match the lock")
        require(
            artifact_hash(temporary, metadata["size"]) == expected_sha256,
            f"{label} checksum does not match the lock",
        )
        os.replace(temporary, target)
        target.chmod(mode)
        directory = os.open(
            target.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return target
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def stage(
    local_root: Path,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> tuple[Path, ...]:
    """Stage all declared charts and the Cosign binary."""

    lock = validate_public()
    local_root = ensure_directory(local_root, "Kubernetes local root")
    chart_root = ensure_directory(local_root / "charts", "Kubernetes chart directory")
    staged: list[Path] = []
    for name, chart_value in lock["charts"].items():
        chart = dict(chart_value)
        staged.append(
            stage_download(
                chart_root / f"{chart['name']}-{chart['version']}.tgz",
                chart,
                label=f"{name} chart",
                opener=opener,
            )
        )
    tool_root = ensure_directory(local_root / "tools", "Kubernetes tool directory")
    tool = dict(lock["tools"]["cosign"])
    staged.append(
        stage_download(
            tool_root / tool["file_name"],
            tool,
            label="Cosign binary",
            opener=opener,
            executable=True,
        )
    )
    return tuple(staged)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-root", type=Path, default=Path(".local/tar/kubernetes"))
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.validate_only:
            validate_public()
            print("validated Kubernetes and admission supply contract")
            return 0
        paths = stage(args.local_root)
    except (OSError, SupplyError, StageError) as error:
        print(f"Kubernetes supply staging failed: {error}", file=sys.stderr)
        return 2
    print(f"staged {len(paths)} Kubernetes admission inputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
