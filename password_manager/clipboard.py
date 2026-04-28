"""Cross-platform clipboard helper with auto-clear.

The CLI uses this to put a decrypted password on the system clipboard so the
user can paste it into a login form, then automatically wipe the clipboard a
few seconds later so the password doesn't linger in plaintext.

Backends are autodetected in priority order:

* macOS:        ``pbcopy``
* Windows:      ``clip``
* WSL:          ``clip.exe`` (Windows clipboard from inside WSL)
* Linux Wayland: ``wl-copy`` (when ``WAYLAND_DISPLAY`` is set)
* Linux X11:    ``xclip`` → ``xsel`` (whichever is installed first)

If no backend is available, ``get_session()`` returns ``None`` and the CLI
falls back to a clear error message — we never leak the password to stdout
when the user explicitly asked for clipboard mode.

The auto-clear is implemented with a daemon ``threading.Timer`` plus an
``atexit`` hook, so:

* If the timer fires (program still running): clipboard is wiped after N
  seconds.
* If the program exits normally before the timer fires (e.g. user picks
  "Вихід"): the ``atexit`` hook wipes the clipboard.
* If the program is killed with ``SIGKILL`` or the machine loses power, the
  clipboard is left untouched — this is an inherent limitation of any
  in-process auto-clear and is documented for the user.
"""

from __future__ import annotations

import atexit
import os
import platform
import shutil
import subprocess
import threading
from dataclasses import dataclass
from typing import Callable, Optional


# Default countdown before the clipboard is wiped, in seconds. Tuned to be
# long enough to switch windows and paste once, short enough that walking
# away from the desk doesn't leave a password on the clipboard.
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 15
CLIPBOARD_CLEAR_ENV_VAR = "PM_CLIPBOARD_CLEAR_SECONDS"


@dataclass(frozen=True)
class _Backend:
    """An installed clipboard binary and the argv to feed it text on stdin.

    ``read_argv`` is the argv to invoke the matching read tool (e.g.
    ``pbpaste`` for ``pbcopy``); ``None`` means "this backend has no
    available read tool, fall back to best-effort wipe".
    """

    name: str
    argv: tuple[str, ...]
    read_argv: Optional[tuple[str, ...]] = None


def _is_wsl() -> bool:
    """True when running inside Windows Subsystem for Linux."""
    if platform.system() != "Linux":
        return False
    release = platform.release().lower()
    if "microsoft" in release or "wsl" in release:
        return True
    # Some kernels report the marker only in /proc/version.
    try:
        with open("/proc/version", "r", encoding="utf-8") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _powershell_read_argv(binary: str) -> tuple[str, ...]:
    return (binary, "-NoProfile", "-Command", "Get-Clipboard")


def _detect_backend() -> Optional[_Backend]:
    """Return the best-available backend for this OS, or ``None``.

    Each match also tries to attach a read tool so ``ClipboardSession.clear``
    can verify ownership before wiping (see issue 1.1 in the audit). When no
    read tool is available, ``read_argv`` stays ``None`` and clear falls back
    to the legacy unconditional wipe.
    """
    system = platform.system()
    if _is_wsl() and shutil.which("clip.exe"):
        read_argv: Optional[tuple[str, ...]] = (
            _powershell_read_argv("powershell.exe")
            if shutil.which("powershell.exe") else None
        )
        return _Backend("clip.exe", ("clip.exe",), read_argv)
    if system == "Darwin" and shutil.which("pbcopy"):
        read_argv = ("pbpaste",) if shutil.which("pbpaste") else None
        return _Backend("pbcopy", ("pbcopy",), read_argv)
    if system == "Windows" and shutil.which("clip"):
        read_argv = (
            _powershell_read_argv("powershell")
            if shutil.which("powershell") else None
        )
        return _Backend("clip", ("clip",), read_argv)
    if system == "Linux":
        if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
            # ``-n`` strips the trailing newline that wl-paste adds by default.
            read_argv = ("wl-paste", "-n") if shutil.which("wl-paste") else None
            return _Backend("wl-copy", ("wl-copy",), read_argv)
        if shutil.which("xclip"):
            return _Backend(
                "xclip",
                ("xclip", "-selection", "clipboard"),
                ("xclip", "-selection", "clipboard", "-o"),
            )
        if shutil.which("xsel"):
            return _Backend(
                "xsel",
                ("xsel", "--clipboard", "--input"),
                ("xsel", "--clipboard", "--output"),
            )
    return None


def read_clear_seconds() -> int:
    """Parse ``PM_CLIPBOARD_CLEAR_SECONDS`` (default 15, 0 disables auto-clear).

    Invalid / negative values fall back to the default — a typo in the env var
    must NOT silently disable the security feature.
    """
    raw = os.environ.get(CLIPBOARD_CLEAR_ENV_VAR)
    if raw is None or raw.strip() == "":
        return DEFAULT_CLIPBOARD_CLEAR_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_CLIPBOARD_CLEAR_SECONDS
    if value < 0:
        return DEFAULT_CLIPBOARD_CLEAR_SECONDS
    return value


# Type alias for an injectable timer factory: ``(seconds, callback) -> Timer``
# where the returned object exposes ``.start()`` and ``.cancel()``. This lets
# tests substitute a synchronous fake.
TimerFactory = Callable[[float, Callable[[], None]], "_TimerLike"]


class _TimerLike:  # pragma: no cover - structural type only
    def start(self) -> None: ...
    def cancel(self) -> None: ...


def _default_timer(seconds: float, fn: Callable[[], None]) -> threading.Timer:
    t = threading.Timer(seconds, fn)
    t.daemon = True
    return t


class ClipboardSession:
    """Stateful clipboard helper.

    A single session tracks the most recent copy so that ``clear()`` is a
    no-op once the clipboard has already been wiped (avoids overwriting
    something the user copied later by hand).
    """

    def __init__(
        self,
        backend: _Backend,
        *,
        timer_factory: TimerFactory = _default_timer,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ):
        self._backend = backend
        self._timer_factory = timer_factory
        self._runner = runner
        self._lock = threading.Lock()
        self._timer: Optional[_TimerLike] = None
        # ``True`` once the clipboard contains either nothing we put there or
        # has been explicitly cleared by us.
        self._cleared = True
        # Last text we wrote — used by ``clear`` to verify clipboard ownership
        # before wiping. Cleared (set to None) once we've wiped or relinquished.
        self._last_text: Optional[str] = None

    @property
    def backend_name(self) -> str:
        return self._backend.name

    def _run(self, text: str) -> None:
        self._runner(
            list(self._backend.argv),
            input=text,
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _read(self) -> Optional[str]:
        """Return current clipboard text, or ``None`` if read isn't supported
        (or the read tool failed).
        """
        read_argv = self._backend.read_argv
        if read_argv is None:
            return None
        try:
            result = self._runner(
                list(read_argv),
                capture_output=True,
                text=True,
                check=True,
            )
        except Exception:  # noqa: BLE001 - best-effort verification
            return None
        stdout = getattr(result, "stdout", None)
        if not isinstance(stdout, str):
            return None
        return stdout

    @staticmethod
    def _matches_owned(read_value: str, expected: str) -> bool:
        """Return True iff the read clipboard value is the text we wrote.

        Some clipboard tools append a trailing newline (notably PowerShell
        ``Get-Clipboard`` adds ``\\r\\n``). We tolerate that — passwords
        themselves never end with ``\\n``, so trimming a single trailing
        newline is unambiguous.
        """
        if read_value == expected:
            return True
        if read_value.endswith("\r\n") and read_value[:-2] == expected:
            return True
        if read_value.endswith("\n") and read_value[:-1] == expected:
            return True
        return False

    def copy(self, text: str) -> None:
        """Place ``text`` on the system clipboard. Raises on backend failure."""
        self._run(text)
        with self._lock:
            self._cleared = False
            self._last_text = text

    def clear(self) -> None:
        """Wipe our text from the clipboard, but only if we still own it.

        If the read tool reports the clipboard now contains something else
        (the user copied unrelated content after our ``copy``), we mark the
        session as no longer owning the clipboard and skip the wipe — better
        to leave the user's data alone than to clobber it with an empty
        string.

        Idempotent: a second ``clear()`` does nothing. Backend failures during
        clear are swallowed — there is nothing useful for the caller to do
        with them, and we don't want to crash the process at exit time.
        """
        with self._lock:
            if self._cleared:
                return
            current = self._read()
            expected = self._last_text
            if current is not None and expected is not None and \
                    not self._matches_owned(current, expected):
                # User copied something else after our copy — don't clobber.
                self._cleared = True
                self._last_text = None
                return
            try:
                self._run("")
            except Exception:  # noqa: BLE001 - best-effort cleanup
                return
            self._cleared = True
            self._last_text = None

    def schedule_clear(self, timeout: float) -> None:
        """Arm a one-shot timer that calls ``clear()`` after ``timeout`` seconds.

        ``timeout <= 0`` cancels any existing timer and skips scheduling — the
        caller is opting out of auto-clear (e.g. tests, or a user who set the
        env var to ``0``).
        """
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if timeout <= 0:
                return
            t = self._timer_factory(timeout, self.clear)
            self._timer = t
        t.start()

    def copy_with_auto_clear(self, text: str, timeout: float) -> None:
        """Copy ``text`` and schedule the auto-clear in one call."""
        self.copy(text)
        self.schedule_clear(timeout)


# Module-level cached session — created lazily on first use, so importing the
# module on a machine without any clipboard backend does NOT register an
# atexit hook that would silently no-op.
_global_session: Optional[ClipboardSession] = None
_global_session_lock = threading.Lock()


def get_session() -> Optional[ClipboardSession]:
    """Return the process-wide ``ClipboardSession``, or ``None`` if unavailable.

    The session's ``clear()`` is registered with ``atexit`` so that a normal
    program exit wipes any password we left on the clipboard, even if the
    auto-clear timer hasn't fired yet.
    """
    global _global_session
    with _global_session_lock:
        if _global_session is not None:
            return _global_session
        backend = _detect_backend()
        if backend is None:
            return None
        _global_session = ClipboardSession(backend)
        atexit.register(_global_session.clear)
        return _global_session


def reset_global_session_for_tests() -> None:
    """Drop the cached session. Tests use this to isolate runs."""
    global _global_session
    with _global_session_lock:
        _global_session = None
