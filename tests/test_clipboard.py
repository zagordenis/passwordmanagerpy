"""Unit tests for the clipboard helper.

These are platform-agnostic: we never invoke a real clipboard binary. Backend
detection is exercised by stubbing ``shutil.which`` / ``platform.system``,
and copy/clear operations route through an injected fake ``runner`` so the
test suite passes on machines without xclip/wl-copy/etc.
"""

from __future__ import annotations

import os
import subprocess
import unittest
from unittest import mock

from password_manager import clipboard


class _FakeTimer:
    """Synchronous stand-in for ``threading.Timer`` used in tests."""

    def __init__(self, seconds: float, fn):
        self.seconds = seconds
        self.fn = fn
        self.started = False
        self.cancelled = False

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True

    def fire(self) -> None:
        """Manually invoke the scheduled callback (simulates timeout)."""
        self.fn()


def _make_session(*, runner=None, timer_factory=None):
    backend = clipboard._Backend(name="fake", argv=("fake-clip",))
    return clipboard.ClipboardSession(
        backend,
        runner=runner or mock.MagicMock(),
        timer_factory=timer_factory or (lambda s, f: _FakeTimer(s, f)),
    )


class ReadClearSecondsTests(unittest.TestCase):
    """``read_clear_seconds`` is the env-var parser for the auto-clear timeout."""

    def setUp(self) -> None:
        self._saved = os.environ.pop(clipboard.CLIPBOARD_CLEAR_ENV_VAR, None)

    def tearDown(self) -> None:
        os.environ.pop(clipboard.CLIPBOARD_CLEAR_ENV_VAR, None)
        if self._saved is not None:
            os.environ[clipboard.CLIPBOARD_CLEAR_ENV_VAR] = self._saved

    def test_default_when_unset(self):
        self.assertEqual(
            clipboard.read_clear_seconds(),
            clipboard.DEFAULT_CLIPBOARD_CLEAR_SECONDS,
        )

    def test_explicit_zero_disables(self):
        os.environ[clipboard.CLIPBOARD_CLEAR_ENV_VAR] = "0"
        self.assertEqual(clipboard.read_clear_seconds(), 0)

    def test_positive_value_honored(self):
        os.environ[clipboard.CLIPBOARD_CLEAR_ENV_VAR] = "30"
        self.assertEqual(clipboard.read_clear_seconds(), 30)

    def test_invalid_value_falls_back_to_default(self):
        os.environ[clipboard.CLIPBOARD_CLEAR_ENV_VAR] = "abc"
        self.assertEqual(
            clipboard.read_clear_seconds(),
            clipboard.DEFAULT_CLIPBOARD_CLEAR_SECONDS,
        )

    def test_negative_value_falls_back_to_default(self):
        # A negative value must NOT disable auto-clear silently — that would
        # be a security footgun if a user mistypes the env var.
        os.environ[clipboard.CLIPBOARD_CLEAR_ENV_VAR] = "-5"
        self.assertEqual(
            clipboard.read_clear_seconds(),
            clipboard.DEFAULT_CLIPBOARD_CLEAR_SECONDS,
        )


class BackendDetectionTests(unittest.TestCase):
    """``_detect_backend`` picks the right tool per OS / display server."""

    def _detect(self, *, system, available, env=None, wsl=False):
        with mock.patch.object(clipboard.platform, "system", return_value=system), \
             mock.patch.object(clipboard, "_is_wsl", return_value=wsl), \
             mock.patch.object(
                 clipboard.shutil, "which",
                 side_effect=lambda b: f"/usr/bin/{b}" if b in available else None,
             ), \
             mock.patch.dict(os.environ, env or {}, clear=False):
            return clipboard._detect_backend()

    def test_macos_prefers_pbcopy(self):
        backend = self._detect(system="Darwin", available={"pbcopy"})
        self.assertIsNotNone(backend)
        self.assertEqual(backend.name, "pbcopy")

    def test_windows_uses_clip(self):
        backend = self._detect(system="Windows", available={"clip"})
        self.assertIsNotNone(backend)
        self.assertEqual(backend.name, "clip")

    def test_wsl_prefers_clip_exe(self):
        backend = self._detect(
            system="Linux", available={"clip.exe", "xclip"}, wsl=True
        )
        self.assertIsNotNone(backend)
        self.assertEqual(backend.name, "clip.exe")

    def test_linux_wayland_prefers_wl_copy(self):
        # When WAYLAND_DISPLAY is set AND wl-copy exists, wl-copy wins even
        # over xclip — Wayland clients can't drive the X11 selection.
        backend = self._detect(
            system="Linux",
            available={"wl-copy", "xclip"},
            env={"WAYLAND_DISPLAY": "wayland-0"},
        )
        self.assertIsNotNone(backend)
        self.assertEqual(backend.name, "wl-copy")

    def test_linux_x11_prefers_xclip_over_xsel(self):
        # On a pure X11 box without Wayland, xclip is the priority binary.
        env = {k: "" for k in ("WAYLAND_DISPLAY",)}
        backend = self._detect(
            system="Linux", available={"xclip", "xsel"}, env=env,
        )
        self.assertIsNotNone(backend)
        self.assertEqual(backend.name, "xclip")

    def test_linux_falls_back_to_xsel(self):
        env = {"WAYLAND_DISPLAY": ""}
        backend = self._detect(
            system="Linux", available={"xsel"}, env=env,
        )
        self.assertIsNotNone(backend)
        self.assertEqual(backend.name, "xsel")

    def test_returns_none_when_nothing_installed(self):
        env = {"WAYLAND_DISPLAY": ""}
        backend = self._detect(system="Linux", available=set(), env=env)
        self.assertIsNone(backend)


class ClipboardSessionTests(unittest.TestCase):
    """Behavior of the stateful ``ClipboardSession`` wrapper."""

    def test_copy_invokes_backend_with_text(self):
        runner = mock.MagicMock()
        session = _make_session(runner=runner)

        session.copy("hunter2")

        runner.assert_called_once()
        args, kwargs = runner.call_args
        self.assertEqual(args[0], ["fake-clip"])
        self.assertEqual(kwargs["input"], "hunter2")
        self.assertTrue(kwargs["check"])
        self.assertTrue(kwargs["text"])

    def test_clear_after_copy_runs_backend_with_empty_string(self):
        runner = mock.MagicMock()
        session = _make_session(runner=runner)

        session.copy("hunter2")
        session.clear()

        # Two calls total: copy("hunter2") then clear via copy("").
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(runner.call_args_list[1].kwargs["input"], "")

    def test_clear_is_idempotent(self):
        # After the first clear we mark the clipboard as wiped; subsequent
        # clears must not run the backend again — otherwise we could
        # overwrite something the user copied by hand later.
        runner = mock.MagicMock()
        session = _make_session(runner=runner)
        session.copy("x")
        session.clear()
        session.clear()
        session.clear()
        self.assertEqual(runner.call_count, 2)  # copy + first clear only

    def test_clear_swallows_backend_failure(self):
        # If the clipboard tool fails during clear (e.g. xclip dies), we
        # must not propagate the exception — callers (atexit, timer) have
        # nothing useful to do with it.
        def runner(*a, **kw):
            if kw.get("input") == "":
                raise subprocess.CalledProcessError(1, a[0])
            return mock.DEFAULT

        session = _make_session(runner=mock.MagicMock(side_effect=runner))
        session.copy("x")
        session.clear()  # must not raise

    def test_schedule_clear_arms_timer_and_fires_clear(self):
        runner = mock.MagicMock()
        timers: list[_FakeTimer] = []

        def factory(seconds, fn):
            t = _FakeTimer(seconds, fn)
            timers.append(t)
            return t

        session = _make_session(runner=runner, timer_factory=factory)
        session.copy("hunter2")
        session.schedule_clear(15)

        self.assertEqual(len(timers), 1)
        self.assertEqual(timers[0].seconds, 15)
        self.assertTrue(timers[0].started)
        timers[0].fire()  # simulate timer expiry
        self.assertEqual(runner.call_args_list[-1].kwargs["input"], "")

    def test_schedule_clear_cancels_previous_timer(self):
        # Copying a second password before the first timer fires must
        # cancel the old one — otherwise the first timer might wipe the
        # second password too early.
        timers: list[_FakeTimer] = []

        def factory(seconds, fn):
            t = _FakeTimer(seconds, fn)
            timers.append(t)
            return t

        session = _make_session(timer_factory=factory)
        session.copy("a")
        session.schedule_clear(15)
        session.copy("b")
        session.schedule_clear(15)
        self.assertEqual(len(timers), 2)
        self.assertTrue(timers[0].cancelled)
        self.assertFalse(timers[1].cancelled)

    def test_schedule_clear_with_zero_or_negative_skips_timer(self):
        timers: list[_FakeTimer] = []
        session = _make_session(
            timer_factory=lambda s, f: timers.append(_FakeTimer(s, f)) or timers[-1]
        )
        session.copy("x")
        session.schedule_clear(0)
        self.assertEqual(timers, [])  # no timer scheduled

    def test_copy_with_auto_clear_does_both(self):
        timers: list[_FakeTimer] = []

        def factory(seconds, fn):
            t = _FakeTimer(seconds, fn)
            timers.append(t)
            return t

        runner = mock.MagicMock()
        session = _make_session(runner=runner, timer_factory=factory)
        session.copy_with_auto_clear("hunter2", 5)

        self.assertEqual(runner.call_args_list[0].kwargs["input"], "hunter2")
        self.assertEqual(timers[0].seconds, 5)
        self.assertTrue(timers[0].started)


class GetSessionTests(unittest.TestCase):
    """Module-level singleton behavior."""

    def setUp(self) -> None:
        clipboard.reset_global_session_for_tests()

    def tearDown(self) -> None:
        clipboard.reset_global_session_for_tests()

    def test_returns_none_when_no_backend(self):
        with mock.patch.object(clipboard, "_detect_backend", return_value=None):
            self.assertIsNone(clipboard.get_session())

    def test_caches_session_and_registers_atexit(self):
        backend = clipboard._Backend("fake", ("fake-clip",))
        with mock.patch.object(
            clipboard, "_detect_backend", return_value=backend,
        ), mock.patch.object(clipboard.atexit, "register") as register:
            first = clipboard.get_session()
            second = clipboard.get_session()
        self.assertIsNotNone(first)
        self.assertIs(first, second)  # cached
        register.assert_called_once_with(first.clear)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
