"""Tests for the CLI auto-lock behavior.

The CLI itself is interactive (uses ``input`` / ``getpass``), so most of the
loop is covered by smoke tests. Here we unit-test the pieces that don't
require a TTY:

* ``_read_auto_lock_seconds`` (env-var parsing).
* ``_ensure_unlocked`` (the gate that runs before each DB-backed action).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from password_manager import cli
from password_manager.manager import PasswordManager


class ReadAutoLockSecondsTests(unittest.TestCase):
    """`_read_auto_lock_seconds()` parses ``PM_AUTO_LOCK_SECONDS``."""

    def _with_env(self, value):
        env = dict(os.environ)
        if value is None:
            env.pop(cli.AUTO_LOCK_ENV_VAR, None)
        else:
            env[cli.AUTO_LOCK_ENV_VAR] = value
        return patch.dict(os.environ, env, clear=True)

    def test_default_when_unset(self) -> None:
        with self._with_env(None):
            self.assertEqual(
                cli._read_auto_lock_seconds(), cli.DEFAULT_AUTO_LOCK_SECONDS
            )

    def test_default_on_empty_string(self) -> None:
        with self._with_env(""):
            self.assertEqual(
                cli._read_auto_lock_seconds(), cli.DEFAULT_AUTO_LOCK_SECONDS
            )

    def test_default_on_garbage(self) -> None:
        # Typo / invalid value MUST fall back to the secure default. We do not
        # want a typo to silently disable auto-lock.
        with self._with_env("five-hundred"):
            self.assertEqual(
                cli._read_auto_lock_seconds(), cli.DEFAULT_AUTO_LOCK_SECONDS
            )

    def test_default_on_negative(self) -> None:
        with self._with_env("-1"):
            self.assertEqual(
                cli._read_auto_lock_seconds(), cli.DEFAULT_AUTO_LOCK_SECONDS
            )

    def test_zero_disables(self) -> None:
        with self._with_env("0"):
            self.assertEqual(cli._read_auto_lock_seconds(), 0)

    def test_custom_value(self) -> None:
        with self._with_env("60"):
            self.assertEqual(cli._read_auto_lock_seconds(), 60)


class EnsureUnlockedTests(unittest.TestCase):
    """`_ensure_unlocked()` is the auto-lock gate run before each DB action."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        self.manager = PasswordManager(self.db_path)
        self.manager.set_master_password("master-1")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_within_window_does_not_lock(self) -> None:
        # 100s elapsed, timeout 300 → still unlocked, no _login call.
        with patch.object(cli, "_login") as login_mock:
            ok = cli._ensure_unlocked(
                self.manager, last_activity=0.0, timeout=300, now=100.0
            )
        self.assertTrue(ok)
        self.assertTrue(self.manager.is_unlocked)
        login_mock.assert_not_called()

    def test_exact_boundary_does_not_lock(self) -> None:
        # Exactly at timeout (now - last == timeout) → still unlocked.
        with patch.object(cli, "_login") as login_mock:
            ok = cli._ensure_unlocked(
                self.manager, last_activity=0.0, timeout=300, now=300.0
            )
        self.assertTrue(ok)
        self.assertTrue(self.manager.is_unlocked)
        login_mock.assert_not_called()

    def test_idle_beyond_window_locks_and_reauths(self) -> None:
        # 301s elapsed, timeout 300 → manager is locked, then _login is called.
        with patch.object(cli, "_login", return_value=True) as login_mock:
            ok = cli._ensure_unlocked(
                self.manager, last_activity=0.0, timeout=300, now=301.0
            )
        self.assertTrue(ok)
        login_mock.assert_called_once_with(self.manager)
        # Crucial: lock() was actually called BEFORE _login (verified
        # because _login is mocked and didn't actually re-unlock).
        self.assertFalse(self.manager.is_unlocked)

    def test_idle_beyond_window_failed_reauth_returns_false(self) -> None:
        # When user fails re-authentication (e.g. wrong master, or 5 misses),
        # _ensure_unlocked must propagate the failure so the caller exits.
        with patch.object(cli, "_login", return_value=False):
            ok = cli._ensure_unlocked(
                self.manager, last_activity=0.0, timeout=300, now=999.0
            )
        self.assertFalse(ok)
        self.assertFalse(self.manager.is_unlocked)

    def test_zero_timeout_disables_check(self) -> None:
        # timeout=0 means "auto-lock off" — never locks, no matter how much
        # time has passed.
        with patch.object(cli, "_login") as login_mock:
            ok = cli._ensure_unlocked(
                self.manager, last_activity=0.0, timeout=0, now=99999.0
            )
        self.assertTrue(ok)
        self.assertTrue(self.manager.is_unlocked)
        login_mock.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
