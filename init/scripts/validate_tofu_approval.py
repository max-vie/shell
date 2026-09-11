#!/usr/bin/env python3
"""Validate one private approval record for one saved OpenTofu plan."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


class ApprovalError(ValueError):
    """A private OpenTofu approval record is invalid."""


EXPECTED_FIELDS = {
    "schema_version",
    "status",
    "project_id",
    "root",
    "commit",
    "approval",
    "plan_sha256",
    "approved_at",
}
ROOT_APPROVALS = {
    "bootstrap": "environment-gcp/init/tofu/bootstrap",
    "network": "environment-gcp/init/tofu/network",
    "shared-nodes": "environment-gcp/init/tofu/shared-nodes",
}


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ApprovalError(f"duplicate field: {key}")
        document[key] = value
    return document


def load_record(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ApprovalError("approval record must be a regular file")
    if path.stat().st_mode & 0o777 != 0o600:
        raise ApprovalError("approval record must have mode 0600")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ApprovalError("approval record is not valid JSON") from error
    if not isinstance(value, dict):
        raise ApprovalError("approval record must be a JSON object")
    if set(value) != EXPECTED_FIELDS:
        raise ApprovalError("approval record fields changed")
    return value


def validate_record(
    record: dict[str, Any],
    *,
    project_id: str,
    root: str,
    commit: str,
    approval: str,
    digest: str,
) -> None:
    if record["schema_version"] != "1.0" or record["status"] != "approved":
        raise ApprovalError("approval record status or schema changed")
    if record["project_id"] != project_id:
        raise ApprovalError("approval project does not match")
    if record["root"] != root:
        raise ApprovalError("approval root does not match")
    if record["commit"] != commit or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ApprovalError("approval commit does not match")
    if record["approval"] != approval or ROOT_APPROVALS.get(root) != approval:
        raise ApprovalError("approval string does not match")
    if record["plan_sha256"] != digest or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ApprovalError("approval plan digest does not match")
    if not isinstance(record["approved_at"], str) or not record["approved_at"].strip():
        raise ApprovalError("approval timestamp is missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--digest", required=True)
    args = parser.parse_args()
    try:
        validate_record(
            load_record(args.record),
            project_id=args.project,
            root=args.root,
            commit=args.commit,
            approval=args.approval,
            digest=args.digest,
        )
    except ApprovalError as error:
        print(f"tofu approval refused: {error}", file=sys.stderr)
        return 2
    print("validated OpenTofu approval record")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
