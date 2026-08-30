"""Test release-feed validation and authorization with temporary SQLite files."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "release_feed_app", ROOT / "make/apps/release-feed/app.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release-feed app")
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)


class ReleaseFeedAppTests(unittest.TestCase):
    def test_valid_release_is_durable_and_duplicate_digest_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releases.db"
            record = {
                "version": "2026.08.29",
                "artifact": "registry.shell.internal/shell/release-feed",
                "digest": "sha256:" + "a" * 64,
            }
            result = app.add_release(record, path)
            self.assertEqual(result["digest"], record["digest"])
            self.assertEqual(app.list_releases(path), [result])
            with self.assertRaisesRegex(app.ReleaseFeedError, "already exists"):
                app.add_release(record, path)

    def test_authentication_is_method_scoped(self) -> None:
        headers = {"Authorization": "Bearer read-secret"}
        self.assertIsNone(
            app.authorization_status(headers, "GET", "read-secret", "write-secret")
        )
        self.assertEqual(
            app.authorization_status(headers, "POST", "read-secret", "write-secret"),
            403,
        )
        self.assertEqual(
            app.authorization_status(
                {"Authorization": "Bearer write-secret"},
                "GET",
                "read-secret",
                "write-secret",
            ),
            401,
        )

    def test_invalid_digest_and_extra_fields_fail(self) -> None:
        with self.assertRaisesRegex(app.ReleaseFeedError, "exactly"):
            app.validate_release(
                {
                    "version": "1",
                    "artifact": "a",
                    "digest": "sha256:" + "a" * 64,
                    "extra": "no",
                }
            )
        with self.assertRaisesRegex(app.ReleaseFeedError, "immutable"):
            app.validate_release({"version": "1", "artifact": "a", "digest": "latest"})

    def test_release_count_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releases.db"
            with mock.patch.object(app, "MAX_RELEASES", 1):
                app.add_release(
                    {
                        "version": "1",
                        "artifact": "a",
                        "digest": "sha256:" + "a" * 64,
                    },
                    path,
                )
                with self.assertRaisesRegex(
                    app.ReleaseFeedCapacityError, "limit reached"
                ) as raised:
                    app.add_release(
                        {
                            "version": "2",
                            "artifact": "b",
                            "digest": "sha256:" + "b" * 64,
                        },
                        path,
                    )
                self.assertEqual(
                    app.release_error_response(raised.exception),
                    (507, {"status": "capacity-exhausted"}),
                )

    def test_capacity_contract_and_metrics_match_runtime(self) -> None:
        make_contract = json.loads(
            (ROOT / "make/contracts/release-feed-secret-contract.json").read_text(
                encoding="utf-8"
            )
        )
        watch_contract = json.loads(
            (ROOT / "watch/contracts/release-feed-requirements.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(make_contract["application"]["max_records"], app.MAX_RELEASES)
        self.assertEqual(
            make_contract["application"]["capacity_warning_remaining"],
            app.CAPACITY_WARNING_REMAINING,
        )
        self.assertEqual(watch_contract["workload"]["max_records"], app.MAX_RELEASES)
        metrics = app.metrics_body(app.MAX_RELEASES - 25, 1, 0, "test").decode()
        self.assertIn("release_feed_capacity_remaining 25", metrics)

    def test_sqlite_files_are_private_under_service_umask(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "releases.db"
            previous = os.umask(0o077)
            try:
                with closing(app.connect(path)):
                    for suffix in ("", "-wal", "-shm"):
                        sidecar = Path(f"{path}{suffix}")
                        self.assertTrue(sidecar.is_file())
                        self.assertEqual(sidecar.stat().st_mode & 0o777, 0o600)
            finally:
                os.umask(previous)

    def test_main_closes_the_server_after_termination(self) -> None:
        server = mock.MagicMock()
        server.serve_forever.side_effect = KeyboardInterrupt
        database = mock.MagicMock()
        with (
            mock.patch.object(app.sys, "argv", ["app.py"]),
            mock.patch.object(app, "_read_secret", return_value="x" * 32),
            mock.patch.object(app, "connect", return_value=database),
            mock.patch.object(
                app, "BoundedThreadingHTTPServer", return_value=server
            ),
            mock.patch.object(app.ssl, "SSLContext"),
            mock.patch.object(app.signal, "signal") as signal,
            mock.patch.object(app.os, "umask") as umask,
        ):
            app.main()
        umask.assert_called_once_with(0o077)
        signal.assert_called_once()
        self.assertFalse(server.daemon_threads)
        server.server_close.assert_called_once_with()
        database.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
