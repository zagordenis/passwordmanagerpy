"""Interactive CLI for the password manager."""

from __future__ import annotations

import getpass
import logging
import os
import subprocess
import sys
import time
from typing import Callable

from . import clipboard as _clipboard
from .generator import (
    DEFAULT_LENGTH,
    MAX_LENGTH,
    MIN_LENGTH,
    PasswordPolicy,
    generate_password,
)
from .manager import DEFAULT_DB_PATH, PasswordManager, UserRecord


MENU = """
=== Password Manager ===
1)  Додати акаунт
2)  Знайти акаунт
3)  Показати всі акаунти
4)  Видалити акаунт
5)  Оновити пароль
6)  Експорт у JSON
7)  Імпорт з JSON
8)  Пошук по login/email
9)  Вихід
10) Змінити master password
11) Згенерувати пароль
12) Скопіювати пароль у буфер обміну (з авто-очищенням)
"""

DEFAULT_AUTO_LOCK_SECONDS = 300
AUTO_LOCK_ENV_VAR = "PM_AUTO_LOCK_SECONDS"
# Menu items that don't touch the encrypted DB and therefore don't require a
# fresh master password after an idle period ("9" already exits early before
# the auto-lock check runs).
NO_AUTH_ACTIONS = {"11"}

# Where unexpected-exception tracebacks are logged. Created lazily on first
# use with mode 0o600 — we never want to print exception messages directly
# on stderr, because a buggy ``raise RuntimeError(f"... {password}")`` would
# leak credentials into the user's terminal scrollback (see audit issue 1.2).
ERROR_LOG_ENV_VAR = "PM_ERROR_LOG_PATH"
_logger = logging.getLogger("password_manager.cli")
_logger_initialised = False


def _default_error_log_path() -> str:
    """Return the platform-appropriate default location for the error log."""
    override = os.environ.get(ERROR_LOG_ENV_VAR)
    if override:
        return os.path.abspath(os.path.expanduser(os.path.expandvars(override)))
    base = os.environ.get(
        "XDG_STATE_HOME",
        os.path.join(os.path.expanduser("~"), ".local", "state"),
    )
    return os.path.join(base, "passwordmanagerpy", "error.log")


def _ensure_error_logger() -> str:
    """Attach a FileHandler at ``_default_error_log_path`` (mode 0o600) once.

    Returns the resolved log path so the CLI can show it to the user.
    Idempotent across calls.
    """
    global _logger_initialised
    path = _default_error_log_path()
    if _logger_initialised:
        return path
    parent = os.path.dirname(path)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError:
            # Fall back to a NullHandler so errors are still swallowed cleanly.
            _logger.addHandler(logging.NullHandler())
            _logger_initialised = True
            return path
    # Create the file with 0o600 BEFORE writing to it, mirroring the export
    # helper, so a stale wide-open file from a previous run doesn't linger.
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(path, flags, 0o600)
        os.close(fd)
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - non-POSIX or read-only fs
            pass
        handler: logging.Handler = logging.FileHandler(
            path, mode="a", encoding="utf-8",
        )
    except OSError:
        # Filesystem unwritable — still register a handler so calls don't crash.
        handler = logging.NullHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    _logger.addHandler(handler)
    _logger.setLevel(logging.ERROR)
    _logger.propagate = False
    _logger_initialised = True
    return path


def _read_auto_lock_seconds() -> int:
    """Parse ``PM_AUTO_LOCK_SECONDS`` (default 300, 0 disables auto-lock).

    Invalid / negative values fall back to the default — we do NOT want a typo
    in the env var to silently disable the security feature.
    """
    raw = os.environ.get(AUTO_LOCK_ENV_VAR)
    if raw is None or raw.strip() == "":
        return DEFAULT_AUTO_LOCK_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_AUTO_LOCK_SECONDS
    if value < 0:
        return DEFAULT_AUTO_LOCK_SECONDS
    return value


class _UserAbort(Exception):
    """Raised on EOF (Ctrl+D) to unwind the menu loop into a clean exit."""


def _prompt(text: str) -> str:
    try:
        return input(text).strip()
    except EOFError:
        raise _UserAbort from None


def _prompt_password(text: str) -> str:
    """Read a password without echoing. Falls back to plain input on non-tty."""
    try:
        return getpass.getpass(text)
    except EOFError:
        raise _UserAbort from None
    except KeyboardInterrupt:
        raise
    except Exception:  # pragma: no cover - environment-specific fallback
        try:
            return input(text)
        except EOFError:
            raise _UserAbort from None


def _print_record(record: UserRecord, index: int | None = None) -> None:
    """Pretty-print one record.

    ``index`` (1-based) is the position in the surrounding listing — it
    renumbers from 1 every time, so deletions don't leave gaps.
    ``record.id`` is the stable database id (never reused after delete,
    by design — it's a primary key).
    """
    prefix = f"  [{index}] " if index is not None else "  "
    print(
        f"{prefix}id={record.id} "
        f"login={record.login!r} "
        f"email={record.email!r} "
        f"password={record.password!r} "
        f"created_at={record.created_at}"
    )


def _print_records(records: list[UserRecord]) -> None:
    if not records:
        print("  (порожньо)")
        return
    for i, r in enumerate(records, start=1):
        _print_record(r, index=i)


def _setup_master(manager: PasswordManager) -> None:
    print("Master password ще не задано. Створіть його зараз.")
    while True:
        first = _prompt_password("Новий master password: ")
        if not first:
            print("Master password не може бути порожнім.")
            continue
        second = _prompt_password("Підтвердіть master password: ")
        if first != second:
            print("Не співпадає, спробуйте ще раз.")
            continue
        manager.set_master_password(first)
        print("Master password встановлено.")
        return


def _login(manager: PasswordManager, *, max_attempts: int = 5) -> bool:
    for attempt in range(1, max_attempts + 1):
        master = _prompt_password("Master password: ")
        if manager.verify_master_password(master):
            if manager.is_legacy_kdf():
                print(
                    "Увага: ця БД використовує старий KDF (PBKDF2). "
                    "Змініть master password (пункт 10) щоб мігрувати на "
                    "Argon2id — нічого не доведеться вводити повторно.",
                )
            return True
        remaining = max_attempts - attempt
        if remaining:
            print(f"Невірний пароль. Залишилось спроб: {remaining}.")
    print("Перевищено кількість спроб.")
    return False


def _prompt_yesno(text: str, *, default: bool) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    raw = _prompt(text + suffix).lower()
    if not raw:
        return default
    return raw in ("y", "yes", "т", "так")


def _interactive_generate() -> str | None:
    """Ask the policy interactively, generate, and return the password.

    Returns ``None`` if the user typed an invalid value or the policy is
    impossible. Defaults: length 20, all four classes enabled.
    """
    raw_len = _prompt(f"Довжина [{DEFAULT_LENGTH}]: ") or str(DEFAULT_LENGTH)
    try:
        length = int(raw_len)
    except ValueError:
        print(f"Невірна довжина: {raw_len!r}.")
        return None

    policy = PasswordPolicy(
        length=length,
        use_lower=_prompt_yesno("Нижній регістр (a-z)?", default=True),
        use_upper=_prompt_yesno("Верхній регістр (A-Z)?", default=True),
        use_digits=_prompt_yesno("Цифри (0-9)?", default=True),
        use_symbols=_prompt_yesno("Символи (!@#…)?", default=True),
    )
    try:
        password = generate_password(policy)
    except ValueError as exc:
        print(f"Помилка генератора: {exc}")
        print(
            f"Підказка: довжина від {MIN_LENGTH} до {MAX_LENGTH}, хоча б один клас включений."
        )
        return None
    print(f"Згенеровано: {password}")
    return password


def _prompt_password_or_generate(prompt_text: str) -> str:
    """Read a password OR (if user types ``g``) generate one interactively.

    Re-prompts on empty input. Returning the literal string ``"g"`` from
    the user is impossible — it is treated as a "generate" command.
    """
    while True:
        raw = _prompt_password(prompt_text)
        if raw == "g":
            generated = _interactive_generate()
            if generated is not None:
                return generated
            continue
        if not raw:
            print(
                "Password не може бути порожнім "
                "(або введіть 'g' — згенерувати)."
            )
            continue
        return raw


def _generate_password(_manager: PasswordManager) -> None:
    """Standalone generator menu item: print a password to the screen."""
    _interactive_generate()


def _copy_password_to_clipboard(manager: PasswordManager) -> None:
    """Copy a stored account's password to the system clipboard.

    Auto-clears the clipboard after ``PM_CLIPBOARD_CLEAR_SECONDS`` seconds
    (default 15) so the password doesn't linger in plaintext.
    """
    session = _clipboard.get_session()
    if session is None:
        print(
            "Буфер обміну недоступний: не знайдено жодного з "
            "`xclip` / `xsel` / `wl-copy` / `pbcopy` / `clip` / `clip.exe`. "
            "Встановіть один із них і спробуйте знову."
        )
        return
    login = _prompt("Login: ")
    if not login:
        print("Login обов'язковий.")
        return
    record = manager.get_user(login)
    if record is None:
        print("Не знайдено.")
        return
    timeout = _clipboard.read_clear_seconds()
    try:
        session.copy_with_auto_clear(record.password, timeout)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Не вдалося скопіювати у буфер ({session.backend_name}): {exc}")
        return
    if timeout > 0:
        print(
            f"Пароль для {login!r} скопійовано у буфер обміну. "
            f"Буде очищено через {timeout} с."
        )
    else:
        print(
            f"Пароль для {login!r} скопійовано у буфер обміну. "
            "Авто-очищення вимкнено (PM_CLIPBOARD_CLEAR_SECONDS=0)."
        )


def _add_account(manager: PasswordManager) -> None:
    login = _prompt("Login: ")
    if not login:
        print("Login обов'язковий.")
        return
    email = _prompt("Email: ")
    password = _prompt_password_or_generate(
        "Password (або 'g' щоб згенерувати): "
    )
    try:
        record = manager.create_user(login, email, password)
    except ValueError as exc:
        print(f"Помилка: {exc}")
        return
    print("Створено:")
    _print_record(record)


def _find_account(manager: PasswordManager) -> None:
    login = _prompt("Login для пошуку: ")
    record = manager.get_user(login)
    if record is None:
        print("Не знайдено.")
    else:
        _print_record(record)


def _list_accounts(manager: PasswordManager) -> None:
    _print_records(manager.list_users())


def _delete_account(manager: PasswordManager) -> None:
    login = _prompt("Login для видалення: ")
    if not login:
        print("Login обов'язковий.")
        return
    # Pre-check the row exists before asking for confirmation, so that
    # typos give a clean "не знайдено" without a destructive prompt.
    if manager.get_user(login) is None:
        print("Не знайдено.")
        return
    if not _prompt_yesno(f"Видалити акаунт {login!r}?", default=False):
        print("Скасовано.")
        return
    if manager.delete_user(login):
        print("Видалено.")
    else:
        # Race: row vanished between get_user and delete_user.
        print("Не знайдено.")


def _update_password(manager: PasswordManager) -> None:
    login = _prompt("Login: ")
    if manager.get_user(login) is None:
        print("Не знайдено.")
        return
    new_password = _prompt_password_or_generate(
        "Новий password (або 'g' щоб згенерувати): "
    )
    if manager.update_password(login, new_password):
        print("Оновлено.")
    else:
        print("Не вдалося оновити (можливо, акаунт видалений).")


def _export_json(manager: PasswordManager) -> None:
    path = _prompt("Шлях до файлу експорту [export.json]: ") or "export.json"
    try:
        count = manager.export_to_json(path)
    except OSError as exc:
        print(f"Помилка експорту: {exc}")
        return
    print(f"Експортовано {count} акаунтів у {path}.")


def _import_json(manager: PasswordManager) -> None:
    path = _prompt("Шлях до файлу імпорту: ")
    if not path:
        print("Шлях обов'язковий.")
        return
    try:
        result = manager.import_from_json(path)
    except (OSError, ValueError) as exc:
        print(f"Помилка імпорту: {exc}")
        return
    # Always show the summary so a partially-malformed file isn't silently
    # truncated (audit fix 1.3). Only mention skipped categories when > 0
    # to keep the happy path quiet.
    parts = [f"Імпортовано {result.inserted} нових акаунтів."]
    extras: list[str] = []
    if result.skipped_duplicates:
        extras.append(f"{result.skipped_duplicates} дублікатів")
    if result.skipped_invalid:
        extras.append(f"{result.skipped_invalid} невалідних записів")
    if extras:
        parts.append("Пропущено: " + ", ".join(extras) + ".")
    print(" ".join(parts))


def _search(manager: PasswordManager) -> None:
    query = _prompt("Пошуковий запит: ")
    if not query:
        print("Запит обов'язковий.")
        return
    _print_records(manager.search(query))


def _ensure_unlocked(
    manager: PasswordManager,
    *,
    last_activity: float,
    timeout: int,
    now: float,
) -> bool:
    """If the idle window elapsed, lock the manager and re-prompt master.

    Returns ``True`` if the manager is unlocked after this call, ``False`` if
    the user failed re-authentication (caller should exit).
    """
    if timeout <= 0:
        return True
    if now - last_activity <= timeout:
        return True
    manager.lock()
    print(
        f"\nСесію заблоковано через бездіяльність (>{timeout} с). "
        "Введіть master password."
    )
    return _login(manager)


def _change_master(manager: PasswordManager) -> None:
    old = _prompt_password("Поточний master password: ")
    while True:
        new = _prompt_password("Новий master password: ")
        if not new:
            print("Новий master password не може бути порожнім.")
            return
        confirm = _prompt_password("Підтвердіть новий master password: ")
        if new != confirm:
            print("Не співпадає, спробуйте ще раз.")
            continue
        break
    try:
        count = manager.change_master_password(old, new)
    except ValueError as exc:
        print(f"Помилка: {exc}")
        return
    print(
        f"Master password змінено. Перешифровано {count} акаунтів під новим ключем."
    )


ACTIONS = {
    "1": _add_account,
    "2": _find_account,
    "3": _list_accounts,
    "4": _delete_account,
    "5": _update_password,
    "6": _export_json,
    "7": _import_json,
    "8": _search,
    "10": _change_master,
    "11": _generate_password,
    "12": _copy_password_to_clipboard,
}


def run(
    db_path: str = DEFAULT_DB_PATH,
    *,
    clock: Callable[[], float] = time.monotonic,
    auto_lock_seconds: int | None = None,
) -> int:
    """Run the interactive menu loop. Returns process exit code.

    ``auto_lock_seconds`` overrides the env var when given (used by tests).
    ``clock`` is injectable so tests can simulate elapsed time without sleeping.
    """
    manager = PasswordManager(db_path)
    timeout = (
        auto_lock_seconds if auto_lock_seconds is not None
        else _read_auto_lock_seconds()
    )

    try:
        if not manager.has_master_password():
            _setup_master(manager)
        else:
            if not _login(manager):
                return 1

        last_activity = clock()
        while True:
            print(MENU)
            choice = _prompt("Виберіть пункт: ")
            if choice == "9":
                print("До побачення.")
                return 0
            action = ACTIONS.get(choice)
            if action is None:
                print("Невірний пункт меню.")
                continue
            # Only DB-backed actions go through the auto-lock gate AND reset
            # the idle timer. NO_AUTH_ACTIONS (e.g. the standalone generator)
            # must NOT touch `last_activity`, otherwise an idle user could
            # pick item 11 to silently extend their session past the timeout
            # and then run a DB-backed action without re-authenticating.
            if choice not in NO_AUTH_ACTIONS:
                if not _ensure_unlocked(
                    manager,
                    last_activity=last_activity,
                    timeout=timeout,
                    now=clock(),
                ):
                    return 1
            try:
                action(manager)
            except _UserAbort:
                # Ctrl+D inside an action — abandon it and go back to menu.
                print()
            except Exception:  # noqa: BLE001 - keep CLI running
                # Log the full traceback to a private file (0o600); print only
                # a generic line on stderr so a sensitive substring inside the
                # exception message can never leak into the user's terminal
                # scrollback (audit fix 1.2).
                log_path = _ensure_error_logger()
                _logger.exception("unexpected error in action %r", choice)
                print(
                    f"Несподівана помилка. Деталі у журналі: {log_path}",
                    file=sys.stderr,
                )
            if choice not in NO_AUTH_ACTIONS:
                last_activity = clock()
    except _UserAbort:
        # Ctrl+D at the top level (menu prompt or initial login) — exit
        # cleanly with a newline so the next shell prompt isn't glued to
        # the password prompt.
        print("\nДо побачення.")
        return 0
    except KeyboardInterrupt:
        # Ctrl+C anywhere — including the menu prompt, initial login,
        # password setup, or inside an action — exits cleanly with code 0
        # instead of dumping a traceback.
        print("\nПерервано.")
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
