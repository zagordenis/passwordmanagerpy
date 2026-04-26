"""Tests for the CLI auto-lock behavior.

The CLI itself is interactive (uses ``input`` / ``getpass``), so most of the
loop is covered by smoke tests. Here we unit-test:

* ``_read_auto_lock_seconds`` (env-var parsing).
* ``_ensure_unlocked`` (the gate that runs before each DB-backed action).
* ``run()`` end-to-end with mocked I/O — driving the menu loop with a
  scripted clock + scripted stdin, to catch loop-level regressions
  (e.g. NO_AUTH_ACTIONS resetting the idle timer).
"""

from __future__ import annotations

import io
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
        # Capture stdout so the lock-prompt message printed by
        # ``_ensure_unlocked`` does not leak into the test runner output.
        self._stdout_patch = patch("sys.stdout", new=io.StringIO())
        self._stdout_patch.start()
        self.addCleanup(self._stdout_patch.stop)

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


class RunLoopAutoLockTests(unittest.TestCase):
    """Drive ``cli.run()`` with scripted clock + stdin to catch loop bugs.

    Specifically: NO_AUTH_ACTIONS (item 11) must NOT reset the idle timer.
    Otherwise an idle user could pick item 11 to extend their session past
    the timeout, then run a DB-backed action without re-authenticating.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        # Pre-create master + one record so we can test list_users(3).
        bootstrap = PasswordManager(self.db_path)
        bootstrap.set_master_password("master-1")
        bootstrap.create_user("alice", "alice@x.com", "p@ssw0rd!")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *, inputs, clock_values, timeout=2):
        """Run the CLI loop. ``inputs`` is fed to both ``input`` and
        ``getpass.getpass`` (they share the queue in order). ``clock_values``
        is consumed by the injected clock on each call."""
        in_iter = iter(inputs)
        clock_iter = iter(clock_values)

        def fake_input(_prompt=""):
            return next(in_iter)

        def fake_getpass(_prompt=""):
            return next(in_iter)

        def fake_clock():
            return next(clock_iter)

        out = io.StringIO()
        with patch("builtins.input", side_effect=fake_input), \
             patch("password_manager.cli.getpass.getpass",
                   side_effect=fake_getpass), \
             patch("sys.stdout", new=out):
            code = cli.run(
                self.db_path, clock=fake_clock, auto_lock_seconds=timeout,
            )
        return code, out.getvalue()

    def test_item_11_does_not_extend_session_past_timeout(self) -> None:
        """REGRESSION: idle past timeout → pick item 11 (no auth) → next
        DB-backed action MUST still trigger auto-lock.

        Pre-fix, item 11 reset ``last_activity``, silently extending the
        session and bypassing auto-lock entirely.
        """
        # Sequence of master prompts + menu choices + final inputs:
        #   master verify, "11", length="20", 4× "" for class defaults,
        #   "3" (list, must trigger lock), master re-auth, "9" (exit).
        inputs = [
            "master-1",  # initial _login
            "11",        # menu: standalone generator (NO_AUTH_ACTIONS)
            "20",        # generator: length
            "", "", "", "",  # generator: lower/upper/digits/symbols (default Y)
            "3",         # menu: list — MUST trigger auto-lock
            "master-1",  # _ensure_unlocked → _login re-auth
            "9",         # exit
        ]
        # Clock progression. Each entry is the value returned by the next
        # clock() call. The order of clock() calls in run() is:
        #   1. last_activity = clock()                  -> 0.0 (after _login)
        #   2. now=clock() in _ensure_unlocked for "11" — wait, NO_AUTH so skipped
        #   3. clock() at end of iter for "11" — also skipped now (the fix)
        #   4. now=clock() in _ensure_unlocked for "3" — at this point
        #      now - last_activity = 100 - 0 = 100 > 2 → MUST lock.
        #   5. last_activity = clock() at end of iter for "3"
        clock_values = [0.0, 100.0, 100.0, 200.0]

        code, output = self._run(
            inputs=inputs, clock_values=clock_values, timeout=2,
        )
        self.assertEqual(code, 0, f"unexpected exit code; output={output!r}")
        # The lock-and-reauth message MUST appear before the listing.
        lock_marker = "Сесію заблоковано через бездіяльність"
        self.assertIn(lock_marker, output)
        idx_lock = output.index(lock_marker)
        idx_listing = output.index("login='alice'")
        self.assertLess(
            idx_lock, idx_listing,
            "auto-lock message must precede the listing — item 11 must NOT "
            "reset the idle timer",
        )

    def test_item_11_within_window_does_not_lock(self) -> None:
        """Sanity: item 11 within the idle window does not spuriously lock,
        and a quick DB action right after also does not lock."""
        inputs = [
            "master-1",  # initial _login
            "11", "20", "", "", "", "",  # generator
            "3",                          # list (within window)
            "9",
        ]
        # clock(): last_activity=0; gate-for-3 at t=1 (within window of 2);
        # last_activity reset to t=1.5 after "3" runs.
        clock_values = [0.0, 1.0, 1.5]
        code, output = self._run(
            inputs=inputs, clock_values=clock_values, timeout=2,
        )
        self.assertEqual(code, 0)
        self.assertNotIn("Сесію заблоковано", output)
        self.assertIn("login='alice'", output)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
