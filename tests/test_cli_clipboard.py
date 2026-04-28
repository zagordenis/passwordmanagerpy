"""CLI integration tests for menu item 12 (clipboard copy).

Drives ``cli.run()`` end-to-end and asserts:

* When no clipboard backend is available, the CLI prints a clear error and
  does NOT leak the password to stdout.
* When a backend is available, the chosen account's plaintext password is
  passed to the backend's ``runner`` and an auto-clear timer is armed.
* The decrypted password is never printed to stdout when copying via 12.
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from unittest.mock import patch

from password_manager import cli, clipboard
from password_manager.manager import PasswordManager


class _FakeTimer:
    """Synchronous Timer stand-in: records but doesn't actually wait."""

    def __init__(self, seconds, fn):
        self.seconds = seconds
        self.fn = fn
        self.started = False

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:  # pragma: no cover - not exercised here
        pass


class _ClipboardCLIBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        m = PasswordManager(self.db_path)
        m.set_master_password("master-1")
        m.create_user("alice", "alice@x.com", "s3cret!")
        clipboard.reset_global_session_for_tests()

    def tearDown(self) -> None:
        clipboard.reset_global_session_for_tests()
        self.tmp.cleanup()

    def _run(self, *, inputs):
        it = iter(inputs)

        def fake_input(_p=""):
            return next(it)

        def fake_getpass(_p=""):
            return next(it)

        out = io.StringIO()
        with patch("builtins.input", side_effect=fake_input), \
             patch("password_manager.cli.getpass.getpass",
                   side_effect=fake_getpass), \
             patch("sys.stdout", new=out):
            code = cli.run(
                self.db_path,
                clock=lambda: 0.0,
                auto_lock_seconds=0,
            )
        return code, out.getvalue()


class ClipboardUnavailableTests(_ClipboardCLIBase):
    """When no clipboard tool is installed, item 12 must fail gracefully."""

    def test_prints_clear_error_and_does_not_leak_password(self):
        with patch.object(clipboard, "_detect_backend", return_value=None):
            code, out = self._run(inputs=[
                "master-1",  # initial login
                "12",        # menu: clipboard copy
                "9",         # exit
            ])
        self.assertEqual(code, 0)
        self.assertIn("Буфер обміну недоступний", out)
        # Decrypted password must NEVER appear on stdout in this flow.
        self.assertNotIn("s3cret!", out)


class ClipboardAvailableTests(_ClipboardCLIBase):
    """When a backend is available, item 12 copies + arms the auto-clear timer."""

    def _patched_session(self, runner, timer_factory):
        backend = clipboard._Backend(name="fake", argv=("fake-clip",))
        session = clipboard.ClipboardSession(
            backend, runner=runner, timer_factory=timer_factory,
        )
        return session

    def test_copies_password_and_schedules_clear(self):
        runner_calls: list[dict] = []

        def runner(*args, **kwargs):
            runner_calls.append({"args": args, "kwargs": kwargs})

        timers: list[_FakeTimer] = []

        def timer_factory(seconds, fn):
            t = _FakeTimer(seconds, fn)
            timers.append(t)
            return t

        session = self._patched_session(runner, timer_factory)

        # Force PM_CLIPBOARD_CLEAR_SECONDS=10 deterministically.
        env = dict(os.environ)
        env[clipboard.CLIPBOARD_CLEAR_ENV_VAR] = "10"

        with patch.object(clipboard, "get_session", return_value=session), \
             patch.dict(os.environ, env, clear=False):
            code, out = self._run(inputs=[
                "master-1",
                "12",
                "alice",
                "9",
            ])

        self.assertEqual(code, 0)
        # Backend was invoked with the decrypted password.
        self.assertTrue(runner_calls, "runner was never called")
        self.assertEqual(runner_calls[0]["kwargs"]["input"], "s3cret!")
        # Timer armed with the configured timeout.
        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0].seconds, 10)
        self.assertTrue(timers[0].started)
        # Plaintext password must NOT appear on stdout — that's the whole
        # reason this menu item exists.
        self.assertNotIn("s3cret!", out)
        self.assertIn("Буде очищено через 10 с", out)

    def test_unknown_login_does_not_invoke_clipboard(self):
        runner_calls: list[dict] = []
        timers: list[_FakeTimer] = []

        def runner(*args, **kwargs):
            runner_calls.append(kwargs)

        def timer_factory(seconds, fn):
            t = _FakeTimer(seconds, fn)
            timers.append(t)
            return t

        session = self._patched_session(runner, timer_factory)
        with patch.object(clipboard, "get_session", return_value=session):
            code, out = self._run(inputs=[
                "master-1",
                "12",
                "ghost",   # no such login
                "9",
            ])

        self.assertEqual(code, 0)
        self.assertIn("Не знайдено", out)
        self.assertEqual(runner_calls, [])
        self.assertEqual(timers, [])

    def test_empty_login_input_is_rejected(self):
        runner_calls: list[dict] = []
        session = self._patched_session(
            runner=lambda *a, **kw: runner_calls.append(kw),
            timer_factory=lambda s, f: _FakeTimer(s, f),
        )
        with patch.object(clipboard, "get_session", return_value=session):
            code, out = self._run(inputs=[
                "master-1",
                "12",
                "",        # empty login
                "9",
            ])
        self.assertEqual(code, 0)
        self.assertIn("Login обов'язковий", out)
        self.assertEqual(runner_calls, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
