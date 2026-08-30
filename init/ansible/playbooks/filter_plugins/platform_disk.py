"""Validate the dedicated Longhorn disk topology."""

from __future__ import annotations

from typing import Any


def safe_disk_topology(value: Any, filesystem_rc: int, target: str) -> bool:
    if not isinstance(value, dict) or set(value) != {"blockdevices"}:
        return False
    devices = value["blockdevices"]
    if not isinstance(devices, list) or len(devices) != 1:
        return False
    device = devices[0]
    if not isinstance(device, dict) or device.get("type") != "disk":
        return False
    if device.get("children", []) not in (None, []):
        return False
    raw_mounts = device.get("mountpoints", [])
    if not isinstance(raw_mounts, list) or any(
        mount is not None and not isinstance(mount, str) for mount in raw_mounts
    ):
        return False
    mounts = [mount for mount in raw_mounts if isinstance(mount, str)]
    if filesystem_rc == 2:
        return not mounts
    return filesystem_rc == 0 and mounts in ([], [target])


class FilterModule:
    """Expose INIT disk validation to Ansible."""

    def filters(self) -> dict[str, object]:
        return {"shell_platform_safe_disk_topology": safe_disk_topology}
