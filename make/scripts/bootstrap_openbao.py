#!/usr/bin/env python3
"""Initialize and configure OpenBao for release-feed after explicit approval."""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import stat
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import sops_helpers
import validate_openbao


ROOT = Path(__file__).resolve().parents[2]
TOKEN_HANDOFF = ROOT / ".local/sudo/release-feed/input-set/release-feed.sops.json"
AGE_KEY = ROOT / ".local/sudo/release-feed/age-key.txt"
DEFAULT_OUTPUT = ROOT / ".local/sudo/openbao/bootstrap.sops.json"
APPROVAL = "environment-gcp/make/openbao-bootstrap"
DIGEST = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class OpenBaoBootstrapError(RuntimeError):
    """OpenBao bootstrap was refused or failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OpenBaoBootstrapError(message)


class OpenBaoClient:
    def __init__(self, base_url: str, ca_file: Path) -> None:
        require(base_url.startswith("https://"), "OpenBao URL must use HTTPS")
        require(
            ca_file.is_file() and not ca_file.is_symlink(), "OpenBao CA file is missing"
        )
        self.base_url = base_url.rstrip("/")
        self.context = ssl.create_default_context(cafile=str(ca_file))

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        require(path.startswith("/v1/"), "OpenBao API path is invalid")
        body = None
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["X-Vault-Token"] = token
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, context=self.context, timeout=30) as response:  # nosec B310
                raw = response.read()
        except (HTTPError, URLError, OSError) as error:
            status = getattr(error, "code", "unavailable")
            raise OpenBaoBootstrapError(
                f"OpenBao API request failed: {status}"
            ) from error
        try:
            value = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise OpenBaoBootstrapError("OpenBao API returned invalid JSON") from error
        require(isinstance(value, dict), "OpenBao API response is not an object")
        return value


def policy() -> str:
    return 'path "secret/data/release-feed" {\n  capabilities = ["read"]\n}\n'


def role() -> dict[str, Any]:
    return {
        "bound_service_account_names": ["release-feed"],
        "bound_service_account_namespaces": ["release-feed"],
        "policies": ["release-feed"],
        "audience": "openbao",
        "token_ttl": "10m",
        "token_max_ttl": "30m",
    }


def private_text(path: Path, label: str) -> str:
    value = sops_helpers.private_file(path, label)
    try:
        return value.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise OpenBaoBootstrapError(f"{label} is unreadable") from error


def encrypt_custody(document: dict[str, Any], output: Path, age_key: Path) -> None:
    require(
        output.is_relative_to(ROOT),
        "OpenBao custody output must stay in the repository",
    )
    require(
        not output.exists() and not output.is_symlink(),
        "refusing to replace existing OpenBao custody",
    )
    directory = output.parent
    require(
        directory.is_dir() and not directory.is_symlink(),
        "OpenBao custody directory is missing",
    )
    require(
        stat.S_IMODE(directory.stat().st_mode) == 0o700,
        "OpenBao custody directory must be mode 0700",
    )
    key = sops_helpers.private_file(age_key, "SOPS age key")
    try:
        recipient = subprocess.run(  # nosec B603
            ["age-keygen", "-y", str(key)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OpenBaoBootstrapError("age recipient derivation failed") from error
    require(
        recipient.returncode == 0 and recipient.stdout.strip().startswith("age1"),
        "age recipient is invalid",
    )
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=directory,
        prefix=f".{output.name}.",
        delete=False,
    ) as plaintext:
        os.fchmod(plaintext.fileno(), stat.S_IRUSR | stat.S_IWUSR)
        json.dump(document, plaintext, indent=2)
        plaintext.write("\n")
        plaintext.flush()
        os.fsync(plaintext.fileno())
        plaintext_path = Path(plaintext.name)
    try:
        try:
            result = subprocess.run(  # nosec B603
                [
                    "sops",
                    "--encrypt",
                    "--age",
                    recipient.stdout.strip(),
                    "--input-type",
                    "json",
                    "--output-type",
                    "json",
                    "--output",
                    str(output),
                    str(plaintext_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OpenBaoBootstrapError("OpenBao custody encryption failed") from error
        require(result.returncode == 0, "OpenBao custody encryption failed")
        output.chmod(0o600)
        sops_helpers.private_file(output, "OpenBao custody")
    finally:
        plaintext_path.unlink(missing_ok=True)


def bootstrap(
    client: OpenBaoClient,
    *,
    output: Path,
    age_key: Path,
    kubernetes_host: str,
    reviewer_jwt_file: Path,
    kubernetes_ca_file: Path,
) -> Path:
    validate_openbao.validate()
    tokens = sops_helpers.decrypt_json(TOKEN_HANDOFF, age_key)
    read_token = tokens.get("read_token")
    write_token = tokens.get("write_token")
    require(
        isinstance(read_token, str)
        and isinstance(write_token, str)
        and len(read_token) >= 20
        and len(write_token) >= 20,
        "release-feed token handoff is incomplete",
    )
    initialized = client.request(
        "POST",
        "/v1/sys/init",
        payload={"secret_shares": 5, "secret_threshold": 3},
    )
    init_data = initialized.get("keys_base64")
    root_token = initialized.get("root_token")
    require(
        isinstance(init_data, list)
        and len(init_data) == 5
        and all(isinstance(value, str) for value in init_data)
        and isinstance(root_token, str)
        and bool(root_token),
        "OpenBao initialization response is incomplete",
    )
    init_data = cast(list[str], init_data)
    root_token = cast(str, root_token)
    for share in init_data[:3]:
        client.request("PUT", "/v1/sys/unseal", payload={"key": share})
    client.request(
        "POST",
        "/v1/sys/mounts/secret",
        payload={"type": "kv", "options": {"version": "2"}},
        token=root_token,
    )
    client.request(
        "PUT",
        "/v1/sys/policies/acl/release-feed",
        payload={"policy": policy()},
        token=root_token,
    )
    client.request(
        "POST",
        "/v1/sys/auth/kubernetes",
        payload={"type": "kubernetes"},
        token=root_token,
    )
    require(
        kubernetes_ca_file.is_file() and not kubernetes_ca_file.is_symlink(),
        "Kubernetes CA certificate is missing",
    )
    ca_certificate = kubernetes_ca_file.read_text(encoding="ascii")
    require(
        ca_certificate.startswith("-----BEGIN CERTIFICATE-----")
        and "PRIVATE KEY" not in ca_certificate,
        "Kubernetes CA certificate is not public PEM data",
    )
    reviewer_jwt = private_text(reviewer_jwt_file, "Kubernetes reviewer JWT")
    require(
        20 <= len(reviewer_jwt) <= 4096
        and all(ord(char) > 32 for char in reviewer_jwt),
        "Kubernetes reviewer JWT has an invalid shape",
    )
    client.request(
        "POST",
        "/v1/auth/kubernetes/config",
        payload={
            "kubernetes_host": kubernetes_host,
            "kubernetes_ca_cert": ca_certificate,
            "token_reviewer_jwt": reviewer_jwt,
        },
        token=root_token,
    )
    client.request(
        "POST",
        "/v1/auth/kubernetes/role/release-feed",
        payload=role(),
        token=root_token,
    )
    client.request(
        "POST",
        "/v1/secret/data/release-feed",
        payload={"data": {"read_token": read_token, "write_token": write_token}},
        token=root_token,
    )
    custody = {
        "schema_version": "1.0",
        "contract_id": "openbao-bootstrap-contract",
        "cluster": "gcp",
        "root_token": root_token,
        "unseal_shares": init_data,
        "release_feed_role": role(),
    }
    encrypt_custody(custody, output, age_key)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--age-key", type=Path, default=AGE_KEY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--kubernetes-host")
    parser.add_argument("--reviewer-jwt-file", type=Path)
    parser.add_argument("--kubernetes-ca-file", type=Path)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_openbao.validate()
        if args.check_only:
            print("validated OpenBao bootstrap source")
            return 0
        raise OpenBaoBootstrapError(
            "OpenBao bootstrap is blocked until K3s API trust and split custody handoffs exist"
        )
        require(args.approval == APPROVAL, f"approval must be {APPROVAL}")
        require(
            isinstance(args.kubernetes_host, str)
            and args.kubernetes_host.startswith("https://"),
            "Kubernetes auth host is required",
        )
        require(
            args.reviewer_jwt_file is not None,
            "Kubernetes reviewer JWT file is required",
        )
        require(
            args.kubernetes_ca_file is not None,
            "Kubernetes CA file is required",
        )
        output = bootstrap(
            OpenBaoClient(args.url, args.ca_file),
            output=args.output,
            age_key=args.age_key,
            kubernetes_host=args.kubernetes_host,
            reviewer_jwt_file=args.reviewer_jwt_file,
            kubernetes_ca_file=args.kubernetes_ca_file,
        )
        print(f"created {output.relative_to(ROOT)}")
    except (
        OSError,
        OpenBaoBootstrapError,
        sops_helpers.SopsError,
        validate_openbao.OpenBaoValidationError,
    ) as error:
        print(f"MAKE OpenBao bootstrap refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
