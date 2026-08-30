#!/usr/bin/env python3
"""Validate the Harbor supply subset of the platform service lock."""

from __future__ import annotations

import sys

from validate_platform_supply import PlatformSupplyError, validate_harbor


def main() -> int:
    try:
        lock = validate_harbor()
    except (OSError, PlatformSupplyError) as error:
        print(f"TAR Harbor validation failed: {error}", file=sys.stderr)
        return 2
    print(f"validated Harbor supply {lock['chart']['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
