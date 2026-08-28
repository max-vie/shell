#!/usr/bin/env python3
"""Stage the checksum-locked Loki and Alloy charts for MAKE."""

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

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stage_kubernetes_supply import (  # noqa: E402
    CHUNK_SIZE,
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    StageError as SharedStageError,
    ensure_directory,
    safe_path,
)
from validate_watch_logs import WatchLogsSupplyError, validate_public  # noqa: E402


class WatchLogsStageError(RuntimeError):
    """The WATCH logs charts could not be staged safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WatchLogsStageError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def approved_source(url: str) -> urllib.parse.SplitResult:
    source = urllib.parse.urlsplit(url)
    require(
        source.scheme == "https" and source.netloc == "github.com",
        "WATCH logs chart source is not approved",
    )
    return source


def approved_redirect(url: str) -> None:
    final = urllib.parse.urlsplit(url)
    require(final.scheme == "https", "WATCH logs chart redirected away from HTTPS")
    require(
        final.netloc == "github.com" or final.netloc.endswith(".githubusercontent.com"),
        "WATCH logs chart redirected outside approved hosts",
    )


def stage_chart(
    chart: dict[str, Any],
    chart_root: Path,
    *,
    opener: Callable[..., Any],
) -> Path:
    target = safe_path(
        chart_root / f"{chart['name']}-{chart['version']}.tgz",
        f"{chart['name']} chart",
    )
    if target.exists():
        require(
            not target.is_symlink() and target.is_file(),
            f"existing {chart['name']} chart is not a regular file",
        )
        require(
            stat.S_IMODE(target.stat().st_mode) == PRIVATE_FILE_MODE,
            f"existing {chart['name']} chart must be mode 0600",
        )
        require(
            target.stat().st_size == chart["size_bytes"],
            f"existing {chart['name']} chart size differs from the lock",
        )
        require(
            sha256_file(target) == chart["sha256"],
            f"existing {chart['name']} chart differs from the lock",
        )
        return target

    approved_source(chart["source"])
    request = urllib.request.Request(
        chart["source"],
        headers={"User-Agent": "shell-watch-logs-supply/1"},
    )
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            dir=chart_root,
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        with (
            os.fdopen(descriptor, "wb") as output,
            opener(request, timeout=180) as response,
        ):
            approved_redirect(response.geturl())
            downloaded = 0
            while chunk := response.read(CHUNK_SIZE):
                downloaded += len(chunk)
                require(
                    downloaded <= chart["size_bytes"],
                    f"downloaded {chart['name']} chart exceeds the locked size",
                )
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        require(
            downloaded == chart["size_bytes"],
            f"downloaded {chart['name']} chart size does not match the lock",
        )
        require(
            sha256_file(temporary) == chart["sha256"],
            f"downloaded {chart['name']} chart checksum does not match the lock",
        )
        os.replace(temporary, target)
        target.chmod(PRIVATE_FILE_MODE)
        directory = os.open(chart_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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
) -> list[Path]:
    lock = validate_public()
    local_root = ensure_directory(local_root, "WATCH logs local root")
    require(
        stat.S_IMODE(local_root.stat().st_mode) == PRIVATE_DIRECTORY_MODE,
        "WATCH logs local root must be mode 0700",
    )
    chart_root = ensure_directory(local_root / "charts", "WATCH logs chart directory")
    return [
        stage_chart(lock["charts"][name], chart_root, opener=opener)
        for name in ("loki", "alloy")
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-root", type=Path, default=Path(".local/tar/watch"))
    args = parser.parse_args(argv)
    try:
        paths = stage(args.local_root)
    except (
        OSError,
        SharedStageError,
        WatchLogsStageError,
        WatchLogsSupplyError,
    ) as error:
        print(f"WATCH logs supply staging failed: {error}", file=sys.stderr)
        return 2
    print(
        "staged verified WATCH logs charts: " + ", ".join(str(path) for path in paths)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
