"""Authenticated durable release metadata feed."""

from __future__ import annotations

import hmac
import json
import os
import re
import signal
import sqlite3
import ssl
import sys
import threading
import time
from collections.abc import Mapping
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


SERVICE = "release-feed"
API_SCHEMA = "v3"
DATABASE = Path(os.environ.get("DATABASE_PATH", "/data/releases.db"))
READ_TOKEN_PATH = Path(os.environ.get("READ_TOKEN_PATH", "/run/secrets/read-token"))
WRITE_TOKEN_PATH = Path(os.environ.get("WRITE_TOKEN_PATH", "/run/secrets/write-token"))
TLS_CERT_PATH = Path(os.environ.get("TLS_CERT_PATH", "/tls/tls.crt"))
TLS_KEY_PATH = Path(os.environ.get("TLS_KEY_PATH", "/tls/tls.key"))
APP_VERSION = os.environ.get("APP_VERSION", "dev")
MAX_BODY = 4096
MAX_RELEASES = 1000
CAPACITY_WARNING_REMAINING = 100
MAX_THREADS = 32
REQUEST_TIMEOUT = 10
FIELD_LIMITS = {"version": 128, "artifact": 256, "digest": 71}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9._+/-]{1,128}$")
COUNTERS = {"requests": 0, "errors": 0}
COUNTERS_LOCK = threading.Lock()


class ReleaseFeedError(ValueError):
    """A release record or runtime input failed validation."""


class ReleaseFeedCapacityError(ReleaseFeedError):
    """The durable release record quota is exhausted."""


def _read_secret(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ReleaseFeedError("required secret is unavailable") from error
    if len(value) < 20 or any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ReleaseFeedError("required secret has an invalid shape")
    return value


def connect(path: Path = DATABASE) -> sqlite3.Connection:
    """Open SQLite with WAL and a single durable release table."""

    path.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(path, timeout=10)
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA journal_mode=WAL")
    database.execute(
        """
        CREATE TABLE IF NOT EXISTS releases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            artifact TEXT NOT NULL,
            digest TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL
        )
        """
    )
    database.commit()
    try:
        path.chmod(0o600)
    except OSError as error:
        database.close()
        raise ReleaseFeedError(
            "database permissions could not be restricted"
        ) from error
    return database


def list_releases(path: Path = DATABASE) -> list[dict[str, Any]]:
    with closing(connect(path)) as database:
        rows = database.execute(
            "SELECT version, artifact, digest, created_at FROM releases ORDER BY id DESC LIMIT ?",
            (MAX_RELEASES,),
        ).fetchall()
    return [dict(row) for row in rows]


def release_count(path: Path = DATABASE) -> int:
    with closing(connect(path)) as database:
        row = database.execute("SELECT COUNT(*) FROM releases").fetchone()
    if row is None:
        raise ReleaseFeedError("release count is unavailable")
    return int(row[0])


def validate_release(document: object) -> dict[str, str]:
    if not isinstance(document, dict) or set(document) != set(FIELD_LIMITS):
        raise ReleaseFeedError("expected exactly version, artifact, and digest")
    values: dict[str, str] = {}
    for field, limit in FIELD_LIMITS.items():
        value = document.get(field)
        if not isinstance(value, str) or not value or len(value) > limit:
            raise ReleaseFeedError("release fields have invalid lengths")
        values[field] = value
    if not SAFE_VERSION.fullmatch(values["version"]):
        raise ReleaseFeedError("version has an invalid shape")
    if not DIGEST.fullmatch(values["digest"]):
        raise ReleaseFeedError("digest must be an immutable sha256 identity")
    return values


def add_release(document: object, path: Path = DATABASE) -> dict[str, Any]:
    values = validate_release(document)
    created_at = int(time.time())
    try:
        with closing(connect(path)) as database, database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute("SELECT COUNT(*) FROM releases").fetchone()
            if row is None or int(row[0]) >= MAX_RELEASES:
                raise ReleaseFeedCapacityError("release limit reached")
            database.execute(
                "INSERT INTO releases(version, artifact, digest, created_at) VALUES(?,?,?,?)",
                (values["version"], values["artifact"], values["digest"], created_at),
            )
            database.commit()
    except sqlite3.IntegrityError as error:
        raise ReleaseFeedError("release digest already exists") from error
    return {**values, "created_at": created_at}


def authorization_status(
    headers: Mapping[str, str], method: str, read_token: str, write_token: str
) -> int | None:
    """Return None only for the token allowed by the requested method."""

    authorization = headers.get("Authorization", "")
    supplied = authorization[7:].strip() if authorization.startswith("Bearer ") else ""
    expected = read_token if method == "GET" else write_token
    if hmac.compare_digest(supplied, expected):
        return None
    if method == "POST" and hmac.compare_digest(supplied, read_token):
        return 403
    return 401


def requires_auth(method: str, path: str) -> bool:
    return not (method == "GET" and path in {"/healthz", "/metrics"})


def metrics_body(records: int, requests: int, errors: int, version: str) -> bytes:
    remaining = max(MAX_RELEASES - records, 0)
    return (
        "# HELP release_feed_records Durable release records.\n"
        "# TYPE release_feed_records gauge\n"
        f"release_feed_records {records}\n"
        "# HELP release_feed_capacity_remaining Available release record slots.\n"
        "# TYPE release_feed_capacity_remaining gauge\n"
        f"release_feed_capacity_remaining {remaining}\n"
        "# HELP release_feed_http_requests_total HTTP requests.\n"
        "# TYPE release_feed_http_requests_total counter\n"
        f"release_feed_http_requests_total {requests}\n"
        "# HELP release_feed_http_errors_total HTTP errors.\n"
        "# TYPE release_feed_http_errors_total counter\n"
        f"release_feed_http_errors_total {errors}\n"
        "# HELP release_feed_build_info Release identity.\n"
        "# TYPE release_feed_build_info gauge\n"
        f'release_feed_build_info{{version="{version}"}} 1\n'
    ).encode()


def release_error_response(error: Exception) -> tuple[int, dict[str, str]]:
    if isinstance(error, ReleaseFeedCapacityError):
        return 507, {"status": "capacity-exhausted"}
    return 400, {"status": "invalid"}


class Config:
    def __init__(
        self, database: Path, read_token: str, write_token: str, app_version: str
    ) -> None:
        self.database = database
        self.read_token = read_token
        self.write_token = write_token
        self.app_version = app_version


class Handler(BaseHTTPRequestHandler):
    server_version = SERVICE

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT)

    @property
    def config(self) -> Config:
        return self.server.config  # type: ignore[attr-defined]

    def _send_json(self, status: int, document: Any) -> None:
        body = (json.dumps(document, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        self.end_headers()
        self.wfile.write(body)

    def _authorize(self, method: str) -> bool:
        status = authorization_status(
            dict(self.headers.items()),
            method,
            self.config.read_token,
            self.config.write_token,
        )
        if status is None:
            return True
        self._send_json(
            status,
            {"status": "unauthorized" if status == 401 else "forbidden"},
        )
        return False

    def _record_request(self, status: int, started: float) -> None:
        with COUNTERS_LOCK:
            COUNTERS["requests"] += 1
            if status >= 400:
                COUNTERS["errors"] += 1
        print(
            json.dumps(
                {
                    "service": SERVICE,
                    "method": self.command,
                    "path": urlsplit(self.path).path,
                    "status": status,
                    "duration_ms": round((time.monotonic() - started) * 1000, 2),
                },
                sort_keys=True,
            ),
            flush=True,
        )

    def do_GET(self) -> None:
        started = time.monotonic()
        status = 200
        try:
            path = urlsplit(self.path).path
            if requires_auth("GET", path) and not self._authorize("GET"):
                status = 401
                return
            if path == "/":
                self._send_json(
                    status,
                    {
                        "service": SERVICE,
                        "purpose": "authenticated immutable release metadata feed",
                        "endpoints": ["/healthz", "/releases", "/metrics"],
                    },
                )
            elif path == "/healthz":
                self._send_json(
                    status,
                    {
                        "api_schema": API_SCHEMA,
                        "service": SERVICE,
                        "status": "ok",
                        "version": self.config.app_version,
                        "records": release_count(self.config.database),
                    },
                )
            elif path == "/releases":
                self._send_json(
                    status,
                    {"releases": list_releases(self.config.database)},
                )
            elif path == "/metrics":
                records = release_count(self.config.database)
                with COUNTERS_LOCK:
                    requests = COUNTERS["requests"]
                    errors = COUNTERS["errors"]
                body = metrics_body(
                    records, requests, errors, self.config.app_version
                )
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            else:
                status = 404
                self._send_json(status, {"status": "not-found"})
        except (OSError, sqlite3.Error, ValueError):
            status = 500
            self._send_json(status, {"status": "error"})
        finally:
            self._record_request(status, started)

    def do_POST(self) -> None:
        started = time.monotonic()
        status = 201
        try:
            if not self._authorize("POST"):
                authorization = authorization_status(
                    dict(self.headers.items()),
                    "POST",
                    self.config.read_token,
                    self.config.write_token,
                )
                status = 403 if authorization == 403 else 401
                return
            if urlsplit(self.path).path != "/releases":
                status = 404
                self._send_json(status, {"status": "not-found"})
                return
            if self.headers.get("Transfer-Encoding"):
                raise ReleaseFeedError("transfer encoding is not supported")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length < 2 or length > MAX_BODY:
                raise ReleaseFeedError("invalid request size")
            document = json.loads(self.rfile.read(length))
            self._send_json(status, add_release(document, self.config.database))
        except (ReleaseFeedError, ValueError, json.JSONDecodeError) as error:
            status, response = release_error_response(error)
            self._send_json(status, response)
        except (OSError, sqlite3.Error):
            status = 500
            self._send_json(status, {"status": "error"})
        finally:
            self._record_request(status, started)

    def log_message(self, *_args: Any) -> None:
        return


def check_database() -> None:
    with closing(connect()) as database:
        database.execute("SELECT 1").fetchone()


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(MAX_THREADS)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def main() -> None:
    os.umask(0o077)
    if len(sys.argv) == 2 and sys.argv[1] == "check":
        check_database()
        return
    config = Config(
        DATABASE,
        _read_secret(READ_TOKEN_PATH),
        _read_secret(WRITE_TOKEN_PATH),
        APP_VERSION,
    )
    with closing(connect(config.database)):
        pass
    server = BoundedThreadingHTTPServer(("0.0.0.0", 8443), Handler)  # nosec B104
    server.daemon_threads = False
    server.config = config  # type: ignore[attr-defined]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(TLS_CERT_PATH, TLS_KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    def stop(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
