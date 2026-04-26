"""Interactive CLI for the password manager."""

from __future__ import annotations

import getpass
import sys

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
"""


def _prompt(text: str) -> str:
    return input(text).strip()


def _prompt_password(text: str) -> str:
    """Read a password without echoing. Falls back to plain input on non-tty."""
    try:
        return getpass.getpass(text)
    except (EOFError, KeyboardInterrupt):
        raise
    except Exception:  # pragma: no cover - environment-specific fallback
        return input(text)


def _print_record(record: UserRecord) -> None:
    print(
        f"  [{record.id}] login={record.login!r} "
        f"email={record.email!r} "
        f"password={record.password!r} "
        f"created_at={record.created_at}"
    )


def _print_records(records: list[UserRecord]) -> None:
    if not records:
        print("  (порожньо)")
        return
    for r in records:
        _print_record(r)


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
    if manager.delete_user(login):
        print("Видалено.")
    else:
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
        inserted = manager.import_from_json(path)
    except (OSError, ValueError) as exc:
        print(f"Помилка імпорту: {exc}")
        return
    print(f"Імпортовано {inserted} нових акаунтів (дублікати пропущено).")


def _search(manager: PasswordManager) -> None:
    query = _prompt("Пошуковий запит: ")
    if not query:
        print("Запит обов'язковий.")
        return
    _print_records(manager.search(query))


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
}


def run(db_path: str = DEFAULT_DB_PATH) -> int:
    """Run the interactive menu loop. Returns process exit code."""
    manager = PasswordManager(db_path)

    if not manager.has_master_password():
        _setup_master(manager)
    else:
        if not _login(manager):
            return 1

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
        try:
            action(manager)
        except KeyboardInterrupt:
            print("\nПерервано.")
            return 0
        except Exception as exc:  # noqa: BLE001 - we want CLI to keep running
            print(f"Несподівана помилка: {exc}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
