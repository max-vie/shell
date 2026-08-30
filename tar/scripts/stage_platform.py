#!/usr/bin/env python3
"""Stage verified platform charts under ignored TAR state."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

import validate_platform_supply as supply


class PlatformStageError(RuntimeError):
    """Platform chart staging failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlatformStageError(message)


def private_root(path: Path) -> Path:
    value = Path(os.path.abspath(path))
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
    chart_root = value / "charts"
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
    platform = supply.validate_platform()
    services = supply.validate_services()
    return [*platform["charts"].values(), *services["charts"].values()]


def stage(local_root: Path, *, opener: Any = urllib.request.urlopen) -> list[Path]:
    raise PlatformStageError(
        "platform staging is blocked until size pins and no-follow publication are implemented"
    )
    root = private_root(local_root)
    output: list[Path] = []
    for chart in charts():
        path = root / "charts" / f"{chart['name']}-{chart['version']}.tgz"
        if path.exists() or path.is_symlink():
            require(
                not path.is_symlink() and path.is_file(),
                f"existing chart is unsafe: {path.name}",
            )
            require(
                hashlib.sha256(path.read_bytes()).hexdigest() == chart["sha256"],
                f"existing chart differs: {path.name}",
            )
            output.append(path)
            continue
        try:
            with opener(chart["source"], timeout=60) as response:
                data = response.read()
        except (OSError, ValueError) as error:
            raise PlatformStageError(f"could not fetch {path.name}") from error
        require(
            hashlib.sha256(data).hexdigest() == chart["sha256"],
            f"checksum mismatch: {path.name}",
        )
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
        output.append(path)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        files = stage(args.local_root)
    except (OSError, PlatformStageError, supply.PlatformSupplyError) as error:
        print(f"TAR platform staging failed: {error}")
        return 2
    print(f"staged {len(files)} platform charts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
