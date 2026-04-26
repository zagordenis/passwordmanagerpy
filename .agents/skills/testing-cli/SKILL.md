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

## Recording

Don't record. This is shell-only — `pexpect` runs without a TTY visible in
the desktop and the recording would be idle. Provide the transcript file
(`pexpect.logfile_read`) as the artifact instead.

## Lint / unit

- `ruff check .` — must be clean before any PR.
- `python -m unittest discover -s tests -v` — should be silent after `OK`
  (no `Сесію заблоковано через бездіяльність...` lines leaking through).
  If you see them, a test forgot to patch `sys.stdout` around code that
  calls `_ensure_unlocked`.

## Devin Secrets Needed

None. The app is fully local — no API keys, no external services.
