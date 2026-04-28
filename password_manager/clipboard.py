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
    """An installed clipboard binary and the argv to feed it text on stdin."""

    name: str
    argv: tuple[str, ...]


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


def _detect_backend() -> Optional[_Backend]:
    """Return the best-available backend for this OS, or ``None``."""
    system = platform.system()
    if _is_wsl() and shutil.which("clip.exe"):
        return _Backend("clip.exe", ("clip.exe",))
    if system == "Darwin" and shutil.which("pbcopy"):
        return _Backend("pbcopy", ("pbcopy",))
    if system == "Windows" and shutil.which("clip"):
        return _Backend("clip", ("clip",))
    if system == "Linux":
        if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
            return _Backend("wl-copy", ("wl-copy",))
        if shutil.which("xclip"):
            return _Backend("xclip", ("xclip", "-selection", "clipboard"))
        if shutil.which("xsel"):
            return _Backend("xsel", ("xsel", "--clipboard", "--input"))
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

    def copy(self, text: str) -> None:
        """Place ``text`` on the system clipboard. Raises on backend failure."""
        self._run(text)
        with self._lock:
            self._cleared = False

    def clear(self) -> None:
        """Wipe our text from the clipboard if we still own it.

        Idempotent: a second ``clear()`` does nothing. Backend failures during
        clear are swallowed — there is nothing useful for the caller to do
        with them, and we don't want to crash the process at exit time.
        """
        with self._lock:
            if self._cleared:
                return
            try:
                self._run("")
            except Exception:  # noqa: BLE001 - best-effort cleanup
                return
            self._cleared = True

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
