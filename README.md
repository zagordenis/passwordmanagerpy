# passwordmanagerpy

Невеликий менеджер паролів на Python 3 + SQLite + `cryptography` (Fernet).
Зберігає логін, email і пароль для багатьох акаунтів. Усі паролі шифруються
ключем, що деривується з master password через PBKDF2-HMAC-SHA256 + salt.
Master password підтверджується розшифруванням контрольного токена — сам
master password у БД не зберігається.

## Можливості

- Master password з PBKDF2 (480 000 ітерацій, унікальний salt).
- Fernet (AES-128-CBC + HMAC-SHA256) для шифрування паролів.
- SQLite (`users.db`) — без сторонніх ORM, лише `sqlite3`.
- CLI меню: додати / знайти / показати всі / видалити / оновити / пошук.
- Експорт та імпорт JSON (розшифровані дані).
- Зміна master password з атомарним перешифруванням усіх записів.
- Генератор сильних паролів (`secrets.SystemRandom`) з налаштуванням довжини та класів символів.
- Уникнення дублікатів login (UNIQUE), коректна обробка помилок.

## Встановлення

Потрібен Python 3.10+.

```bash
pip install -r requirements.txt
# або:
pip install cryptography
```

## Запуск

```bash
python main.py
```

При першому запуску попросить створити master password; далі — вимагатиме
його ввести перед доступом до меню.

> 📖 Повна інструкція з прикладами по кожному пункту меню, форматом
> JSON-експорту/імпорту та FAQ — у [USAGE.md](USAGE.md).

## Структура

```
.
├── main.py                      # точка входу
├── password_manager/
│   ├── __init__.py
│   ├── crypto.py                # PBKDF2 + Fernet хелпери
│   ├── db.py                    # SQLite схема й helpers
│   ├── manager.py               # API: PasswordManager
│   ├── generator.py             # генератор сильних паролів
│   └── cli.py                   # CLI меню
├── tests/test_password_manager.py
├── tests/test_generator.py
└── requirements.txt
```

## Програмний API

```python
from password_manager import PasswordManager

mgr = PasswordManager("users.db")
if not mgr.has_master_password():
    mgr.set_master_password("super-secret")
else:
    assert mgr.verify_master_password("super-secret")

mgr.create_user("alice", "alice@example.com", "p@ssw0rd!")
print(mgr.get_user("alice").password)
print([r.login for r in mgr.list_users()])
mgr.update_password("alice", "new-password")
mgr.delete_user("alice")

mgr.export_to_json("export.json")
mgr.import_from_json("export.json")

# Зміна master password — атомарно перешифровує всі записи
mgr.change_master_password("super-secret", "new-master-2025")

# Генератор паролів
from password_manager import PasswordPolicy, generate_password
strong = generate_password()                                  # 20 символів, всі класи
only_alnum = generate_password(PasswordPolicy(length=32, use_symbols=False))
```

## Тести

```bash
python -m unittest discover -s tests -v
```

## Безпека

- Master password не зберігається — у БД лежать тільки `salt` і
  зашифрований верифікаційний токен. Невірний master password не
  розшифровує токен → доступ заборонено.
- Якщо забути master password — відновити паролі неможливо.
- БД файл (`users.db`) і будь-які експорти JSON додані в `.gitignore`,
  щоб випадково не закомітити.
