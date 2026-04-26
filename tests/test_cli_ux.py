"""CLI UX behaviour: delete confirmation + Ctrl+D (EOF) handling.

Drives ``cli.run()`` end-to-end with mocked ``input`` / ``getpass.getpass``
so the assertions cover the same code paths the user hits at the prompt.
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from unittest.mock import patch

from password_manager import cli
from password_manager.manager import PasswordManager


class _RunHarness(unittest.TestCase):
    """Shared harness: pre-create a master + one account, then drive run()."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        bootstrap = PasswordManager(self.db_path)
        bootstrap.set_master_password("master-1")
        bootstrap.create_user("alice", "alice@x.com", "p@ssw0rd!")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, *, inputs, timeout=0):
        """Run the CLI with a scripted input queue. timeout=0 disables auto-lock."""
        in_iter = iter(inputs)

        def fake_input(_prompt=""):
            return next(in_iter)

        def fake_getpass(_prompt=""):
            return next(in_iter)

        out = io.StringIO()
        with patch("builtins.input", side_effect=fake_input), \
             patch("password_manager.cli.getpass.getpass",
                   side_effect=fake_getpass), \
             patch("sys.stdout", new=out):
            code = cli.run(
                self.db_path,
                clock=lambda: 0.0,
                auto_lock_seconds=timeout,
            )
        return code, out.getvalue()


class DeleteConfirmationTests(_RunHarness):
    """Item 4 (Видалити акаунт) must require explicit y/yes/т/так."""

    def _assert_alice_present(self) -> None:
        m = PasswordManager(self.db_path)
        self.assertTrue(m.verify_master_password("master-1"))
        self.assertIsNotNone(m.get_user("alice"))

    def _assert_alice_absent(self) -> None:
        m = PasswordManager(self.db_path)
        self.assertTrue(m.verify_master_password("master-1"))
        self.assertIsNone(m.get_user("alice"))

    def test_default_no_keeps_account(self) -> None:
        """Empty answer on the [y/N] prompt (just Enter) must NOT delete."""
        inputs = [
            "master-1",   # _login
            "4",          # menu: delete
            "alice",      # login to delete
            "",           # confirm: empty → defaults to N
            "9",          # exit
        ]
        code, output = self._run(inputs=inputs)
        self.assertEqual(code, 0)
        self.assertIn("Скасовано", output)
        self.assertNotIn("Видалено", output)
        self._assert_alice_present()

    def test_explicit_n_keeps_account(self) -> None:
        inputs = ["master-1", "4", "alice", "n", "9"]
        code, output = self._run(inputs=inputs)
        self.assertEqual(code, 0)
        self.assertIn("Скасовано", output)
        self._assert_alice_present()

    def test_explicit_y_deletes_account(self) -> None:
        inputs = ["master-1", "4", "alice", "y", "9"]
        code, output = self._run(inputs=inputs)
        self.assertEqual(code, 0)
        self.assertIn("Видалено", output)
        self.assertNotIn("Скасовано", output)
        self._assert_alice_absent()

    def test_unknown_login_skips_confirmation(self) -> None:
        """Typing a non-existent login must give 'Не знайдено' and NOT prompt
        for confirmation (otherwise a typo could lead the user into the
        destructive prompt path with the wrong row name)."""
        inputs = ["master-1", "4", "no-such-user", "9"]
        # NB: no "y"/"n" between the login and "9" — confirmation is skipped.
        code, output = self._run(inputs=inputs)
        self.assertEqual(code, 0)
        self.assertIn("Не знайдено", output)
        # Confirmation prompt has the form "Видалити акаунт '<login>'?"
        # — distinct from the menu line "4)  Видалити акаунт".
        self.assertNotIn("Видалити акаунт '", output)
        self._assert_alice_present()

    def test_empty_login_rejected(self) -> None:
        inputs = ["master-1", "4", "", "9"]
        code, output = self._run(inputs=inputs)
        self.assertEqual(code, 0)
        self.assertIn("Login обов", output)
        self._assert_alice_present()


class EofHandlingTests(_RunHarness):
    """Ctrl+D / EOF at any prompt must exit cleanly (code 0), not crash."""

    def _run_with_eof(self, *, before_eof, eof_at, after_eof=None, timeout=0):
        """Run with a list of inputs that ends in EOFError at position
        ``eof_at`` (0-indexed). ``before_eof`` is fed first, then EOFError,
        then ``after_eof`` (any remaining inputs)."""
        before = list(before_eof)
        after = list(after_eof or [])

        # Use a counter to inject EOFError at the right call.
        call_idx = [0]
        all_inputs = before + after

        def fake_input(_prompt=""):
            i = call_idx[0]
            call_idx[0] += 1
            if i == eof_at:
                raise EOFError
            return all_inputs.pop(0) if all_inputs else ""

        def fake_getpass(_prompt=""):
            i = call_idx[0]
            call_idx[0] += 1
            if i == eof_at:
                raise EOFError
            return all_inputs.pop(0) if all_inputs else ""

        out = io.StringIO()
        with patch("builtins.input", side_effect=fake_input), \
             patch("password_manager.cli.getpass.getpass",
                   side_effect=fake_getpass), \
             patch("sys.stdout", new=out):
            code = cli.run(
                self.db_path,
                clock=lambda: 0.0,
                auto_lock_seconds=timeout,
            )
        return code, out.getvalue()

    def test_eof_at_initial_master_prompt_exits_zero(self) -> None:
        """Ctrl+D at the initial 'Master password:' prompt → exit 0,
        no traceback."""
        # First call is getpass for master password; raise EOF immediately.
        code, output = self._run_with_eof(
            before_eof=[], eof_at=0,
        )
        self.assertEqual(code, 0)
        self.assertIn("До побачення", output)

    def test_eof_at_menu_prompt_exits_zero(self) -> None:
        """Login OK, then Ctrl+D at menu prompt → clean exit."""
        # Calls: 1) getpass master = "master-1", 2) input menu = EOF
        code, output = self._run_with_eof(
            before_eof=["master-1"], eof_at=1,
        )
        self.assertEqual(code, 0)
        self.assertIn("До побачення", output)

    def test_eof_inside_action_returns_to_menu_then_exits(self) -> None:
        """Ctrl+D inside an action (e.g. while entering a login for delete)
        should abandon the action, NOT crash the CLI; user can still pick
        another menu item afterwards."""
        # Calls:
        #   0: getpass master = "master-1"
        #   1: input menu = "4"
        #   2: input "Login для видалення:" = EOF (abandon action)
        #   3: input menu = "9"  (exit cleanly)
        before = ["master-1", "4"]
        after = ["9"]
        code, output = self._run_with_eof(
            before_eof=before, eof_at=2, after_eof=after,
        )
        self.assertEqual(code, 0)
        # Normal exit message, not abort:
        self.assertIn("До побачення", output)
        # And alice survived (no destructive action ran):
        m = PasswordManager(self.db_path)
        self.assertTrue(m.verify_master_password("master-1"))
        self.assertIsNotNone(m.get_user("alice"))


class KeyboardInterruptHandlingTests(_RunHarness):
    """Ctrl+C at any prompt must exit cleanly (code 0) with 'Перервано.'
    instead of dumping a traceback."""

    def _run_with_sigint(self, *, before_sigint, sigint_at, timeout=0):
        before = list(before_sigint)
        call_idx = [0]
        remaining = list(before)

        def fake_input(_prompt=""):
            i = call_idx[0]
            call_idx[0] += 1
            if i == sigint_at:
                raise KeyboardInterrupt
            return remaining.pop(0) if remaining else ""

        def fake_getpass(_prompt=""):
            i = call_idx[0]
            call_idx[0] += 1
            if i == sigint_at:
                raise KeyboardInterrupt
            return remaining.pop(0) if remaining else ""

        out = io.StringIO()
        with patch("builtins.input", side_effect=fake_input), \
             patch("password_manager.cli.getpass.getpass",
                   side_effect=fake_getpass), \
             patch("sys.stdout", new=out):
            code = cli.run(
                self.db_path,
                clock=lambda: 0.0,
                auto_lock_seconds=timeout,
            )
        return code, out.getvalue()

    def test_sigint_at_menu_prompt_exits_zero(self) -> None:
        """Ctrl+C at the menu prompt 'Виберіть пункт:' → exit 0, no traceback."""
        # Calls: 0) getpass master = "master-1", 1) input menu = SIGINT
        code, output = self._run_with_sigint(
            before_sigint=["master-1"], sigint_at=1,
        )
        self.assertEqual(code, 0)
        self.assertIn("Перервано", output)

    def test_sigint_at_initial_master_prompt_exits_zero(self) -> None:
        """Ctrl+C at the very first password prompt → exit 0, no traceback."""
        code, output = self._run_with_sigint(
            before_sigint=[], sigint_at=0,
        )
        self.assertEqual(code, 0)
        self.assertIn("Перервано", output)

    def test_sigint_inside_action_exits_zero(self) -> None:
        """Ctrl+C while inside an action (e.g. on 'Login для видалення:')
        also exits cleanly with code 0 — same behaviour as before, but now
        survives the menu-loop change too."""
        # Calls: 0) master, 1) menu="4", 2) login prompt = SIGINT
        code, output = self._run_with_sigint(
            before_sigint=["master-1", "4"], sigint_at=2,
        )
        self.assertEqual(code, 0)
        self.assertIn("Перервано", output)
        # alice survived (no destructive action ran)
        m = PasswordManager(self.db_path)
        self.assertTrue(m.verify_master_password("master-1"))
        self.assertIsNotNone(m.get_user("alice"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
