"""Regression tests for the three issues fixed in audit pass v2:

1.1. ``ClipboardSession.clear`` clobbered user content if they copied
     something else after ``copy()``.
1.2. ``cli.run`` printed exception messages verbatim on stderr, which could
     leak credentials embedded in a diagnostic ``raise``.
1.3. ``PasswordManager.import_from_json`` silently dropped malformed and
     duplicate entries; callers had no way to surface that to the user.

Each test is adversarial: revert the fix and the test fails with the exact
symptom the user would see.
"""

from __future__ import annotations

import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from password_manager import cli, clipboard
from password_manager.manager import ImportResult, PasswordManager


# ---------- 1.1 clipboard ownership preservation ----------


class _StatefulClipboardRunner:
    """Fake ``subprocess.run`` that simulates a real clipboard.

    Distinguishes write calls (have ``input=...``) from read calls (have
    ``capture_output=True``). Tracks the current clipboard content so reads
    return what was last written by either us or an external write.
    """

    def __init__(self) -> None:
        self.content: str = ""
        self.calls: list[tuple[tuple[str, ...], dict]] = []

    def write_external(self, text: str) -> None:
        """Simulate the user copying something else outside of our session."""
        self.content = text

    def __call__(self, argv, **kw):
        self.calls.append((tuple(argv), dict(kw)))
        if "input" in kw:
            self.content = kw["input"]
            return subprocess.CompletedProcess(argv, 0)
        if kw.get("capture_output"):
            return subprocess.CompletedProcess(
                argv, 0, stdout=self.content, stderr=""
            )
        return subprocess.CompletedProcess(argv, 0)


def _make_xclip_session(runner):
    """Build a ClipboardSession bound to a fake xclip-like backend."""
    backend = clipboard._Backend(
        name="fake-xclip",
        argv=("fake-clip", "-w"),
        read_argv=("fake-clip", "-r"),
    )
    return clipboard.ClipboardSession(
        backend,
        runner=runner,
        timer_factory=lambda s, f: _NoOpTimer(),
    )


class _NoOpTimer:
    def start(self) -> None:  # pragma: no cover - trivial
        pass

    def cancel(self) -> None:  # pragma: no cover - trivial
        pass


class ClipboardOwnershipTests(unittest.TestCase):
    def test_clear_does_not_clobber_user_content(self) -> None:
        """The core regression test: simulate the audit scenario."""
        runner = _StatefulClipboardRunner()
        session = _make_xclip_session(runner)

        session.copy("SECRET")
        self.assertEqual(runner.content, "SECRET")

        # User copies their own content externally.
        runner.write_external("shopping list")
        self.assertEqual(runner.content, "shopping list")

        # Timer fires (or atexit runs).
        session.clear()

        # KEY ASSERTION: clipboard is still "shopping list" — we did NOT
        # overwrite the user's data.
        self.assertEqual(runner.content, "shopping list")

    def test_clear_does_wipe_when_we_still_own_the_clipboard(self) -> None:
        """Happy path: clipboard still contains our text → wipe it."""
        runner = _StatefulClipboardRunner()
        session = _make_xclip_session(runner)

        session.copy("SECRET")
        session.clear()

        # Clipboard wiped to empty string.
        self.assertEqual(runner.content, "")

    def test_clear_tolerates_trailing_newline_from_read_tool(self) -> None:
        """PowerShell Get-Clipboard adds \\r\\n; wl-paste without -n adds \\n.

        We must still recognise the clipboard as ours.
        """
        for suffix in ("\n", "\r\n"):
            with self.subTest(suffix=repr(suffix)):
                runner = _StatefulClipboardRunner()
                session = _make_xclip_session(runner)
                session.copy("SECRET")
                # Simulate read tool appending a trailing newline.
                runner.content = "SECRET" + suffix
                session.clear()
                self.assertEqual(runner.content, "")

    def test_clear_falls_back_to_wipe_when_read_unavailable(self) -> None:
        """Backend without read_argv keeps the legacy unconditional-wipe path."""
        backend = clipboard._Backend(
            name="legacy-no-read", argv=("fake-clip",), read_argv=None,
        )
        runner = _StatefulClipboardRunner()
        session = clipboard.ClipboardSession(
            backend, runner=runner,
            timer_factory=lambda s, f: _NoOpTimer(),
        )
        session.copy("SECRET")
        runner.write_external("user content")
        session.clear()
        # Without a read tool we can't verify ownership, so we wipe — this is
        # the documented fallback. Not great, but no worse than before.
        self.assertEqual(runner.content, "")

    def test_clear_skips_wipe_if_read_returns_empty(self) -> None:
        """If something else wiped the clipboard already, we don't re-wipe."""
        runner = _StatefulClipboardRunner()
        session = _make_xclip_session(runner)
        session.copy("SECRET")
        runner.content = ""  # external clear
        session.clear()
        # We didn't see our content; the existing empty content is fine.
        # We DID NOT call _run("") again because ownership check failed.
        write_calls = [c for c in runner.calls if "input" in c[1]]
        # Only the original copy write; no second wipe write.
        self.assertEqual(len(write_calls), 1)


class ClipboardBackendDetectionRegressionTests(unittest.TestCase):
    """Ensure read_argv is populated for each detected backend on Linux."""

    def test_xclip_detection_includes_read_argv(self) -> None:
        with mock.patch.object(
            clipboard.platform, "system", return_value="Linux"
        ), mock.patch.object(
            clipboard, "_is_wsl", return_value=False
        ), mock.patch.object(
            clipboard.shutil, "which",
            side_effect=lambda b: f"/usr/bin/{b}" if b == "xclip" else None,
        ), mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": ""}):
            backend = clipboard._detect_backend()
        self.assertIsNotNone(backend)
        self.assertEqual(backend.name, "xclip")
        self.assertEqual(
            backend.read_argv, ("xclip", "-selection", "clipboard", "-o")
        )

    def test_xsel_detection_includes_read_argv(self) -> None:
        with mock.patch.object(
            clipboard.platform, "system", return_value="Linux"
        ), mock.patch.object(
            clipboard, "_is_wsl", return_value=False
        ), mock.patch.object(
            clipboard.shutil, "which",
            side_effect=lambda b: f"/usr/bin/{b}" if b == "xsel" else None,
        ), mock.patch.dict(os.environ, {"WAYLAND_DISPLAY": ""}):
            backend = clipboard._detect_backend()
        self.assertIsNotNone(backend)
        self.assertEqual(backend.name, "xsel")
        self.assertEqual(
            backend.read_argv, ("xsel", "--clipboard", "--output")
        )


# ---------- 1.2 stderr leak hardening ----------


class StderrLeakHardeningTests(unittest.TestCase):
    """Exception messages must NOT appear on stderr verbatim."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        self.log_path = os.path.join(self.tmp.name, "error.log")
        os.environ["PM_ERROR_LOG_PATH"] = self.log_path
        os.environ["PM_AUTO_LOCK_SECONDS"] = "0"
        # Reset module-level logger state (file handler from a previous test).
        cli._logger_initialised = False
        cli._logger.handlers.clear()
        # Initialise the manager with a master password we control.
        manager = PasswordManager(self.db_path)
        manager.set_master_password("master-1")
        # Hijack ACTIONS to inject a misbehaving handler that includes a
        # would-be-secret in its exception message.
        self._saved_actions = cli.ACTIONS.copy()
        cli.ACTIONS["7"] = self._boom

    def tearDown(self) -> None:
        cli.ACTIONS.clear()
        cli.ACTIONS.update(self._saved_actions)
        os.environ.pop("PM_ERROR_LOG_PATH", None)
        os.environ.pop("PM_AUTO_LOCK_SECONDS", None)
        cli._logger_initialised = False
        # Close FileHandlers before clearing so the underlying file descriptor
        # is released (otherwise unittest emits a ResourceWarning).
        for h in list(cli._logger.handlers):
            h.close()
        cli._logger.handlers.clear()
        self.tmp.cleanup()

    @staticmethod
    def _boom(_manager: PasswordManager) -> None:
        raise RuntimeError("ULTRA_SECRET_TOKEN=abc123-do-not-leak")

    def _run_cli_with_inputs(self, password_inputs, prompt_inputs):
        """Drive `cli.run` with scripted password / prompt inputs."""
        password_iter = iter(password_inputs)
        prompt_iter = iter(prompt_inputs)
        with mock.patch.object(
            cli, "_prompt_password", side_effect=lambda _t: next(password_iter)
        ), mock.patch.object(
            cli, "_prompt", side_effect=lambda _t: next(prompt_iter)
        ):
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                rc = cli.run(self.db_path, auto_lock_seconds=0)
            return rc, stdout_buf.getvalue(), stderr_buf.getvalue()

    def test_exception_message_never_reaches_stderr(self) -> None:
        rc, _stdout, stderr = self._run_cli_with_inputs(
            password_inputs=["master-1"],
            prompt_inputs=["7", "9"],
        )
        self.assertEqual(rc, 0)
        self.assertNotIn("ULTRA_SECRET_TOKEN", stderr)
        self.assertNotIn("abc123", stderr)
        # We DID print a generic notice mentioning the log path.
        self.assertIn("Несподівана помилка", stderr)
        self.assertIn(self.log_path, stderr)

    def test_full_traceback_logged_to_private_file(self) -> None:
        """The traceback must end up in the log file with mode 0o600."""
        self._run_cli_with_inputs(
            password_inputs=["master-1"],
            prompt_inputs=["7", "9"],
        )
        self.assertTrue(os.path.exists(self.log_path))
        with open(self.log_path, "r", encoding="utf-8") as fh:
            log_content = fh.read()
        # The actual traceback (with the secret) lives only in this file.
        self.assertIn("ULTRA_SECRET_TOKEN=abc123", log_content)
        self.assertIn("RuntimeError", log_content)

        if os.name == "posix":
            mode = os.stat(self.log_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)
            self.assertFalse(mode & stat.S_IROTH)
            self.assertFalse(mode & stat.S_IRGRP)


# ---------- 1.3 import_from_json reports skipped counts ----------


class ImportResultBackwardCompatTests(unittest.TestCase):
    """Existing callers compare ``inserted == 2`` and call ``int(inserted)``."""

    def test_import_result_equals_int(self) -> None:
        r = ImportResult(inserted=2, skipped_invalid=1, skipped_duplicates=0)
        self.assertEqual(r, 2)
        self.assertEqual(int(r), 2)

    def test_import_result_total_skipped(self) -> None:
        r = ImportResult(inserted=2, skipped_invalid=1, skipped_duplicates=3)
        self.assertEqual(r.total_skipped, 4)

    def test_import_result_hash_matches_int(self) -> None:
        """Python data-model invariant: ``a == b`` implies ``hash(a) == hash(b)``.

        ImportResult(N) compares equal to int(N), so its hash MUST match
        ``hash(N)``. Otherwise hash-based lookups silently fail:
        ``{2: "x"}[ImportResult(2)]`` would raise KeyError.
        """
        r = ImportResult(inserted=2, skipped_invalid=99, skipped_duplicates=99)
        self.assertEqual(hash(r), hash(2))
        # The skipped counters must NOT influence the hash, otherwise the
        # invariant breaks for any non-zero skipped count.
        self.assertEqual(
            hash(ImportResult(inserted=5)),
            hash(ImportResult(inserted=5, skipped_invalid=10)),
        )
        # End-to-end: dict lookup with int key must find ImportResult value.
        d = {2: "x"}
        self.assertEqual(d[ImportResult(2)], "x")


class ImportFromJsonReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        self.manager = PasswordManager(self.db_path)
        self.manager.set_master_password("master-1")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_json(self, payload) -> str:
        path = os.path.join(self.tmp.name, "import.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        return path

    def test_reports_invalid_entries(self) -> None:
        path = self._write_json([
            {"login": "alice", "email": "a@x", "password": "p1"},
            "garbage",                              # non-dict
            {"login": "", "email": "x", "password": "p"},  # empty login
            {"login": "bob", "password": 123},      # password not a string
            {"login": "carol", "email": "c@x", "password": "p2"},
        ])
        result = self.manager.import_from_json(path)
        self.assertEqual(result.inserted, 2)
        self.assertEqual(result.skipped_invalid, 3)
        self.assertEqual(result.skipped_duplicates, 0)

    def test_reports_duplicates_separately(self) -> None:
        self.manager.create_user("alice", "a@x", "p0")
        path = self._write_json([
            {"login": "alice", "email": "a@x", "password": "p1"},  # duplicate
            {"login": "bob", "email": "b@x", "password": "p2"},
        ])
        result = self.manager.import_from_json(path)
        self.assertEqual(result.inserted, 1)
        self.assertEqual(result.skipped_invalid, 0)
        self.assertEqual(result.skipped_duplicates, 1)


class ImportCliReportingTests(unittest.TestCase):
    """The CLI must surface skipped counts to the user."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        self.manager = PasswordManager(self.db_path)
        self.manager.set_master_password("master-1")
        self.path = os.path.join(self.tmp.name, "import.json")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(
                [
                    {"login": "alice", "email": "a@x", "password": "p1"},
                    "junk",
                    {"login": "bob", "email": "b@x", "password": "p2"},
                ],
                fh,
            )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_cli_prints_invalid_count(self) -> None:
        with mock.patch.object(cli, "_prompt", side_effect=[self.path]):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli._import_json(self.manager)
        out = buf.getvalue()
        self.assertIn("Імпортовано 2", out)
        # Skipped count must appear so the user knows the file wasn't whole.
        self.assertTrue(re.search(r"1\s+невалідн", out), out)
        # Cosmetic regression guard: the inserted-count clause must end in
        # a period before the "Пропущено:" clause begins. (Earlier draft
        # joined without a separator, producing "акаунтів Пропущено:".)
        self.assertIn("акаунтів. Пропущено:", out)

    def test_cli_no_extras_line_when_zero_skipped(self) -> None:
        clean_path = os.path.join(self.tmp.name, "clean.json")
        with open(clean_path, "w", encoding="utf-8") as fh:
            json.dump(
                [{"login": "u", "email": "e", "password": "p"}], fh,
            )
        with mock.patch.object(cli, "_prompt", side_effect=[clean_path]):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli._import_json(self.manager)
        out = buf.getvalue()
        self.assertIn("Імпортовано 1", out)
        self.assertNotIn("Пропущено", out)


if __name__ == "__main__":
    unittest.main()
