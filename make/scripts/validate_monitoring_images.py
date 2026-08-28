#!/usr/bin/env python3
"""Validate rendered or running monitoring images against the TAR lock."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, cast


IMAGE_LINE_RE = re.compile(r"^\s*(?:-\s*)?image:\s*[\"']?([^\"'\s#]+)")
RELOADER_RE = re.compile(r"--prometheus-config-reloader=([^\"'\s]+)")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class MonitoringImageError(ValueError):
    """Monitoring images do not match the verified TAR supply."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MonitoringImageError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in document, f"duplicate JSON key: {key}")
        document[key] = value
    return document


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing regular {label}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MonitoringImageError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return cast(dict[str, Any], value)


def canonical_image(image: str) -> str:
    name, separator, digest = image.rpartition("@")
    if not separator:
        return image
    require(
        DIGEST_RE.fullmatch(digest) is not None,
        "monitoring image digest is invalid",
    )
    tag_separator = name.rfind(":")
    if tag_separator > name.rfind("/"):
        name = name[:tag_separator]
    return f"{name}@{digest}"


def expected_images(
    lock: dict[str, Any], include_images: set[str] | None = None
) -> tuple[set[str], set[str]]:
    digests_value = lock.get("runtime_image_digests")
    required_value = lock.get("required_runtime_images")
    persistent_value = lock.get("persistent_runtime_images")
    require(isinstance(digests_value, dict), "TAR runtime image digests are missing")
    require(isinstance(required_value, list), "TAR required runtime images are missing")
    require(
        isinstance(persistent_value, list),
        "TAR persistent runtime images are missing",
    )
    digests = cast(dict[str, Any], digests_value)
    required = cast(list[Any], required_value)
    persistent = cast(list[Any], persistent_value)
    require(
        all(isinstance(image, str) for image in required),
        "TAR required runtime image is invalid",
    )
    require(
        all(isinstance(image, str) for image in persistent),
        "TAR persistent runtime image is invalid",
    )
    require(set(digests) == set(required), "TAR runtime image sets disagree")
    require(set(persistent) <= set(required), "TAR persistent image set is invalid")
    selected = set(required) if include_images is None else include_images
    if not selected:
        raise MonitoringImageError("selected monitoring image set is empty")
    require(selected <= set(required), "selected monitoring image is not in TAR")
    for digest in digests.values():
        require(
            isinstance(digest, str) and DIGEST_RE.fullmatch(digest) is not None,
            "TAR runtime image digest is invalid",
        )
    rendered = {canonical_image(f"{image}@{digests[image]}") for image in selected}
    running = {
        canonical_image(f"{image}@{digests[image]}")
        for image in persistent
        if image in selected
    }
    require(len(rendered) == len(selected), "TAR monitoring image identities overlap")
    return rendered, running


def rendered_images(path: Path) -> set[str]:
    require(path.is_file() and not path.is_symlink(), "rendered manifest is missing")
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise MonitoringImageError("rendered manifest cannot be read") from error
    images: set[str] = set()
    for line in source.splitlines():
        image_match = IMAGE_LINE_RE.match(line)
        if image_match:
            images.add(canonical_image(image_match.group(1)))
        images.update(canonical_image(image) for image in RELOADER_RE.findall(line))
    require(bool(images), "rendered manifest contains no runtime images")
    return images


def running_images(path: Path) -> set[str]:
    document = read_json(path, "running pod document")
    items_value = document.get("items")
    require(isinstance(items_value, list), "running pod document has no items")
    items = cast(list[Any], items_value)
    images: set[str] = set()
    for item in items:
        require(isinstance(item, dict), "running pod item is invalid")
        metadata_value = item.get("metadata", {})
        status_value = item.get("status", {})
        require(isinstance(metadata_value, dict), "running pod metadata is invalid")
        require(isinstance(status_value, dict), "running pod status is invalid")
        metadata = cast(dict[str, Any], metadata_value)
        status = cast(dict[str, Any], status_value)
        if metadata.get("deletionTimestamp") or status.get("phase") in {
            "Succeeded",
            "Failed",
        }:
            continue
        spec_value = item.get("spec")
        require(isinstance(spec_value, dict), "running pod spec is invalid")
        spec = cast(dict[str, Any], spec_value)
        for field in ("initContainers", "containers", "ephemeralContainers"):
            containers_value = spec.get(field, [])
            require(
                isinstance(containers_value, list),
                f"running pod {field} is invalid",
            )
            containers = cast(list[Any], containers_value)
            for container in containers:
                require(isinstance(container, dict), "running pod container is invalid")
                image_value = container.get("image")
                require(
                    isinstance(image_value, str) and bool(image_value),
                    "running pod image is invalid",
                )
                image = cast(str, image_value)
                images.add(canonical_image(image))
    require(bool(images), "running pod document contains no active images")
    return images


def validate_rendered(
    rendered_path: Path,
    lock_path: Path,
    include_images: set[str] | None = None,
) -> set[str]:
    expected, _ = expected_images(
        read_json(lock_path, "TAR WATCH supply lock"), include_images
    )
    actual = rendered_images(rendered_path)
    require(actual == expected, "rendered monitoring image set does not match TAR")
    return actual


def validate_running(pods_path: Path, lock_path: Path) -> set[str]:
    allowed, persistent = expected_images(read_json(lock_path, "TAR WATCH supply lock"))
    actual = running_images(pods_path)
    require(actual <= allowed, "running monitoring image is not pinned by TAR")
    require(persistent <= actual, "persistent monitoring image is not running")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument(
        "--include-image",
        action="append",
        default=None,
        help="limit rendered-image validation to one or more locked images",
    )
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--rendered", type=Path)
    inputs.add_argument("--running-pods", type=Path)
    args = parser.parse_args()
    try:
        if args.rendered is not None:
            selected = set(args.include_image) if args.include_image else None
            validate_rendered(args.rendered, args.lock, selected)
            print("validated rendered monitoring image pins")
        else:
            validate_running(args.running_pods, args.lock)
            print("validated running monitoring image pins")
        return 0
    except (MonitoringImageError, OSError) as error:
        print(f"monitoring image validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
