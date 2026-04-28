# Testing the password manager CLI

This is a single-binary Ukrainian-language CLI app (`python main.py`). E2E
testing is best done with `pexpect` against a real subprocess — there is no
web UI, no API, no screenshots needed.

## Quick reference

- Entry point: `python main.py` (must be invoked with absolute path if `cwd`
  is set to a tmp dir).
- Master-prompt text: **`Master password: `** (NOT `Введіть master password:` —
  that string only appears as the auto-lock notice). When the DB is empty,
  the first prompt is `Новий master password: ` instead.
- Menu prompt: `Виберіть пункт: `
- Exit message: `До побачення.` (printed on `9`, on Ctrl+D at the menu, and on
  KeyboardInterrupt as `Перервано.`).
- Auto-lock env: `PM_AUTO_LOCK_SECONDS=0` disables the timer; set it for any
  test that doesn't specifically exercise auto-lock, otherwise the 300 s
  default may bite intermittently.
- Clipboard env: `PM_CLIPBOARD_CLEAR_SECONDS` (default 15, 0 disables
  auto-clear). Invalid / negative values fall back to the default.
- DB lives at `./users.db` in the cwd of the process. Use a `tempfile.mkdtemp`
  per test and pass `cwd=tmp` to `pexpect.spawn`.

## Bootstrap pattern

```python
import tempfile, os, sys
sys.path.insert(0, "/home/ubuntu/repos/passwordmanagerpy")
from password_manager.manager import PasswordManager

tmp = tempfile.mkdtemp()
mgr = PasswordManager(os.path.join(tmp, "users.db"))
mgr.set_master_password("master-1")
mgr.create_user("alice", "alice@example.com", "p1")
del mgr  # close DB before spawning the CLI
```

## Spawn pattern

```python
import pexpect
env = os.environ.copy()
env["PM_AUTO_LOCK_SECONDS"] = "0"
env["PYTHONUNBUFFERED"] = "1"  # avoids stdout buffering hiding prompts
child = pexpect.spawn(
    sys.executable,
    ["/home/ubuntu/repos/passwordmanagerpy/main.py"],  # absolute path
    cwd=tmp, env=env, encoding="utf-8", timeout=10,
)
child.logfile_read = open(os.path.join(tmp, "transcript.log"), "w")
child.expect_exact("Master password:")
child.sendline("master-1")
child.expect_exact("Виберіть пункт:")
```

## Menu items (current)

1. Додати акаунт   2. Знайти акаунт   3. Показати всі
4. Видалити акаунт (asks `Видалити акаунт 'X'? [y/N]:` since PR #8)
5. Оновити пароль   6. Експорт у JSON   7. Імпорт з JSON
8. Пошук   9. Вихід   10. Змінити master   11. Згенерувати пароль
12. Скопіювати пароль у буфер (since PR #16)

Items `9` and `11` are in `NO_AUTH_ACTIONS` — they neither trigger re-auth
nor reset the inactivity timer. Item `12` is **auth-gated** (it reads the
encrypted DB to decrypt the chosen account's password) and DOES reset the
inactivity timer like every other DB-backed action.

## Adversarial assertions

For any UX fix, ask: "would the test still pass if the fix were reverted?"
If yes, redesign. Concrete patterns that work here:

- For confirmation prompts: `expect_exact("Видалити акаунт 'alice'? [y/N]:")`
  with a TIMEOUT alternative — without `_prompt_yesno` the prompt never
  appears.
- For "this prompt should NOT appear" cases: use a two-alternative
  `child.expect([good_string, bad_string])` and assert `match_index == 0`.
- For Ctrl+D: assert all three of (a) the goodbye string, (b) exit code 0,
  (c) `"Traceback" not in transcript`. A naive fix might catch one but not
  all three.
- For DB-state changes: open a fresh `PasswordManager` after the CLI exits
  and call `verify_master_password` + `get_user` to confirm side effects.

## Clipboard testing (item 12)

The clipboard menu item routes through `password_manager.clipboard`, which
autodetects an OS-specific backend (`xclip`/`xsel` on Linux X11, `wl-copy`
on Wayland, `pbcopy` on macOS, `clip` on Windows, `clip.exe` on WSL). To
actually exercise it on a headless VM:

```bash
sudo apt-get install -y xclip               # backend
Xvfb :99 -screen 0 1024x768x16 &            # headless X server
export DISPLAY=:99
```

Then pass `DISPLAY=:99` into `pexpect.spawn`'s env. Verify pre-flight with
`xclip -selection clipboard <<< "x"` round-tripping via `xclip -o`.

### Reading / priming the clipboard from outside the CLI

```python
import subprocess
subprocess.run(["xclip", "-selection", "clipboard", "-o"],
               capture_output=True, text=True,
               env={"DISPLAY": ":99", "PATH": os.environ["PATH"]}).stdout
```

`xclip` exits non-zero on an empty clipboard on some builds — don't pass
`check=True`; treat empty stdout as the success signal.

### Adversarial patterns specific to clipboard

- **No-leak assertion**: after item 12, scan the *full* pexpect transcript
  for the plaintext password (`assert PASSWORD not in transcript`). The
  whole point of the menu item is that it does NOT echo to stdout.
- **"Backend missing" path**: the cheapest way to make `_detect_backend()`
  return `None` is to launch the CLI with `PATH` reduced to a tmp dir that
  contains only a `python3` symlink, plus `DISPLAY=""` and
  `WAYLAND_DISPLAY=""`. The CLI must detect the missing backend BEFORE
  asking for a login — if it asks for the login first, the password is
  decrypted before the failure path runs and could leak.
- **Timer fires**: set `PM_CLIPBOARD_CLEAR_SECONDS=2`, copy, sleep 4 s,
  read the clipboard. Empty == pass. Without the actual `clear()`
  invocation in the timer callback, the clipboard would still hold the
  password.
- **`atexit` cleanup**: set `PM_CLIPBOARD_CLEAR_SECONDS=600` (so the
  in-process timer cannot fire during the test), copy, exit via item 9,
  read clipboard — must be empty. This isolates the `atexit` codepath
  from the timer codepath. Allow ~1–1.5 s after `pexpect.EOF` for xclip's
  forked daemon to release the selection.
- **Sentinel preservation**: pre-seed clipboard with a sentinel, drive
  the CLI through item 12 with an unknown login — the sentinel must
  survive. A naive implementation that copies unconditionally (including
  when `record is None`) would either crash with `AttributeError` or
  overwrite the sentinel with an empty string. Both surface as a failure
  here.

## Recording

Don't record. This is shell-only — `pexpect` runs without a TTY visible in
the desktop and the recording would be idle. Provide the transcript file
(`pexpect.logfile_read`) as the artifact instead.

## Lint / unit

- `ruff check .` — must be clean before any PR.
- `python -m unittest discover -s tests -v` — should be silent after `OK`
  (no `Сесію заблоковано через бездіяльності...` lines leaking through).
  If you see them, a test forgot to patch `sys.stdout` around code that
  calls `_ensure_unlocked`.

## Devin Secrets Needed

None. The app is fully local — no API keys, no external services.
