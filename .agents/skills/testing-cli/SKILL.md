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
- Login sub-prompt (items 1, 2, 4-style): **`Login: `** (English, not `Логін:`).
- Exit message: `До побачення.` (printed on `9`, on Ctrl+D at the menu, and on
  KeyboardInterrupt as `Перервано.`).
- Auto-lock env: `PM_AUTO_LOCK_SECONDS=0` disables the timer; set it for any
  test that doesn't specifically exercise auto-lock, otherwise the 300 s
  default may bite intermittently.
- DB lives at `./users.db` in the cwd of the process. Use a `tempfile.mkdtemp`
  per test and pass `cwd=tmp` to `pexpect.spawn`.
- `PasswordManager` has no `close()` method — `del mgr` is the shutdown
  idiom before spawning the CLI subprocess against the same DB.

## Bootstrap pattern

```python
import tempfile, os, sys
sys.path.insert(0, "/home/ubuntu/repos/passwordmanagerpy")
from password_manager.manager import PasswordManager

tmp = tempfile.mkdtemp()
mgr = PasswordManager(os.path.join(tmp, "users.db"))
mgr.set_master_password("master-1")
mgr.create_user("alice", "alice@example.com", "p1")
del mgr  # release DB handle before spawning the CLI
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
# When using encoding="utf-8", logfile must be a text-mode file:
child.logfile = open(os.path.join(tmp, "transcript.log"), "w", encoding="utf-8")
child.expect_exact("Master password:")
child.sendline("master-1")
child.expect_exact("Виберіть пункт:")
```

## Menu items (current)

1. Додати акаунт   2. Знайти акаунт   3. Показати всі
4. Видалити акаунт (asks `Видалити акаунт 'X'? [y/N]:` since PR #8)
5. Оновити пароль   6. Експорт у JSON   7. Імпорт з JSON
8. Пошук   9. Вихід   10. Змінити master   11. Згенерувати пароль
12. Скопіювати пароль у буфер обміну (з авто-очищенням)

Items `9` and `11` (and the auto-lock prompt) are in `NO_AUTH_ACTIONS` —
they neither trigger re-auth nor reset the inactivity timer.

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

## PR #18 patterns (audit fixes: clipboard ownership, stderr leak, import warnings)

### Clipboard testing on `DISPLAY=:0`

This VM has a pre-existing X server on `:0` with `xclip` installed. Don't
spin up your own Xvfb — just `env["DISPLAY"] = ":0"` and verify a sanity
round-trip first:

```bash
printf '%s' 'sanity' | DISPLAY=:0 xclip -selection clipboard
DISPLAY=:0 xclip -selection clipboard -o   # → 'sanity'
```

If this VM ever loses `:0` (e.g. fresh container without an X server),
the fallback is `Xvfb :99 -screen 0 1024x768x24 &` + `DISPLAY=:99`.

**Ownership-preservation regression test** (the PR #18 1.1 scenario):

```python
env["PM_CLIPBOARD_CLEAR_SECONDS"] = "2"
# ... spawn CLI, login ...
child.sendline("12"); child.expect("Login: "); child.sendline("alice")
child.expect("Виберіть пункт: ")
assert _xclip_read() == "s3cret!"
_xclip_write("shopping list")            # simulate external user copy
time.sleep(4)                              # past the 2s timer
assert _xclip_read() == "shopping list"   # FAILS pre-PR (was "")
```

A broken `clear()` (no read-before-clear) wipes to `""` here.

### Hijacking actions to test exception paths

Don't patch production code — write a small driver that imports `cli`,
monkeypatches one entry in `cli.ACTIONS`, and calls `cli.run()`. This
proves the production exception handler works without modifying the real
`cli.py`:

```python
driver = '''
import sys
sys.path.insert(0, "/home/ubuntu/repos/passwordmanagerpy")
from password_manager import cli

def _hijacked(_manager):
    raise RuntimeError("ULTRA_SECRET_TOKEN_42")

cli.ACTIONS["8"] = _hijacked
sys.exit(cli.run())
'''
```

For stderr-leak testing, assert all five:
- generic line `"Несподівана помилка. Деталі у журналі:"` is on stderr
- log path printed (filename ends in `error.log`)
- the secret token is **absent** from the terminal transcript
- `os.stat(log).st_mode & 0o777 == 0o600`
- the secret token **is** in the log file (diagnostic preserved)

A regression to `print(f"...: {exc}")` would leak the token to stderr.

The error log defaults to `$XDG_STATE_HOME/passwordmanagerpy/error.log`
(or `~/.local/state/passwordmanagerpy/error.log`). Override with
`PM_ERROR_LOG_PATH=<tmp>/error.log` to keep tests hermetic.

### Import-summary literal assertion

Feed the CLI a JSON with a known mix of valid + duplicate + invalid
entries and assert the **exact** line. The period before `Пропущено:` is
load-bearing — Devin Review caught a missing period in this PR, so guard
it explicitly:

```python
expected = "Імпортовано 1 нових акаунтів. Пропущено: 1 дублікатів, 2 невалідних записів."
assert expected in transcript_text
assert "акаунтів. Пропущено:" in transcript_text  # period regression guard
```

A non-dict entry (`"this is junk"`) and a dict missing `login` both count
toward `skipped_invalid`; an entry with an existing login counts toward
`skipped_duplicates`.

## Recording

Don't record. This is shell-only — `pexpect` runs without a TTY visible in
the desktop and the recording would be idle. Provide the transcript file
(`pexpect.logfile`) as the artifact instead.

## Lint / unit

- `ruff check .` — must be clean before any PR.
- `python -m unittest discover -s tests -v` — should be silent after `OK`
  (no `Сесію заблоковано через бездіяльність...` lines leaking through).
  If you see them, a test forgot to patch `sys.stdout` around code that
  calls `_ensure_unlocked`.

## Devin Secrets Needed

None. The app is fully local — no API keys, no external services.
