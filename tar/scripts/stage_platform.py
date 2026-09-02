#!/usr/bin/env python3
"""Stage verified platform charts under ignored TAR state."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

import validate_platform_supply as supply


class PlatformStageError(RuntimeError):
    """Platform chart staging failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlatformStageError(message)


def safe_path(path: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    current = Path(value.anchor)
    for component in value.parts[1:]:
        current /= component
        require(not current.is_symlink(), f"unsafe symlinked {label}: {current}")
    return value


def private_root(path: Path) -> Path:
    value = safe_path(path, "platform local root")
    if value.exists():
        require(
            not value.is_symlink() and value.is_dir(), "platform local root is unsafe"
        )
        require(
            stat.S_IMODE(value.stat().st_mode) == 0o700,
            "platform local root must be mode 0700",
        )
    else:
        value.mkdir(parents=True, mode=0o700)
    chart_root = safe_path(value / "charts", "platform chart root")
    if chart_root.exists():
        require(
            not chart_root.is_symlink() and chart_root.is_dir(),
            "platform chart root is unsafe",
        )
        require(
            stat.S_IMODE(chart_root.stat().st_mode) == 0o700,
            "platform chart root must be mode 0700",
        )
    else:
        chart_root.mkdir(mode=0o700)
    return value


def charts() -> list[dict[str, Any]]:
    return list(supply.validate_platform()["charts"].values())


def stage(
    local_root: Path,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> list[Path]:
    root = private_root(local_root)
    output: list[Path] = []
    for chart in charts():
        path = safe_path(
            root / "charts" / f"{chart['name']}-{chart['version']}.tgz",
            f"{chart['name']} chart",
        )
        if path.exists() or path.is_symlink():
            require(
                not path.is_symlink() and path.is_file(),
                f"existing chart is unsafe: {path.name}",
            )
            require(
                stat.S_IMODE(path.stat().st_mode) == 0o600,
                f"existing chart has unsafe mode: {path.name}",
            )
            require(
                path.stat().st_size <= chart["max_bytes"],
                f"existing chart exceeds size ceiling: {path.name}",
            )
            require(
                hashlib.sha256(path.read_bytes()).hexdigest() == chart["sha256"],
                f"existing chart differs: {path.name}",
            )
            output.append(path)
            continue
        source = urllib.parse.urlsplit(chart["source"])
        require(
            source.scheme == "https" and bool(source.netloc),
            f"chart source is not approved: {path.name}",
        )
        request = urllib.request.Request(
            chart["source"], headers={"User-Agent": "shell-platform-supply/1"}
        )
        temporary: Path | None = None
        try:
            with opener(request, timeout=180) as response:
                final = urllib.parse.urlsplit(response.geturl())
                require(
                    final.scheme == "https"
                    and final.netloc in chart["redirect_hosts"],
                    f"chart redirect left approved host: {path.name}",
                )
                fd, temporary_name = tempfile.mkstemp(
                    prefix=f".{path.name}.", dir=path.parent
                )
                temporary = Path(temporary_name)
                os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
                digest = hashlib.sha256()
                size = 0
                with os.fdopen(fd, "wb") as stream:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        require(
                            size <= chart["max_bytes"],
                            f"download exceeds size ceiling: {path.name}",
                        )
                        digest.update(chunk)
                        stream.write(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
                require(
                    digest.hexdigest() == chart["sha256"],
                    f"checksum mismatch: {path.name}",
                )
            os.replace(temporary, path)
            temporary = None
            path.chmod(0o600)
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        output.append(path)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--local-root", type=Path, default=Path(".local/tar/platform-addons")
    )
    args = parser.parse_args(argv)
    try:
        files = stage(args.local_root)
    except (OSError, PlatformStageError, supply.PlatformSupplyError) as error:
        print(f"TAR platform staging failed: {error}", file=sys.stderr)
        return 2
    print(f"staged {len(files)} platform charts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
