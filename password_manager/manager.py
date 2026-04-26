"""High-level PasswordManager API used by the CLI and tests."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from typing import Iterable

from cryptography.fernet import Fernet

from . import crypto, db

DEFAULT_DB_PATH = "users.db"

META_SALT = "salt"
META_VERIFIER = "verifier"


@dataclass
class UserRecord:
    """Plain-text view of a stored account (password decrypted)."""

    id: int
    login: str
    email: str | None
    password: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "login": self.login,
            "email": self.email,
            "password": self.password,
            "created_at": self.created_at,
        }


class PasswordManager:
    """Encapsulates DB + crypto state. Construct once, call `unlock` before use."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self._fernet: Fernet | None = None
        db.init_db(db_path)

    # ---------- master password lifecycle ----------

    def has_master_password(self) -> bool:
        """True iff a master password has already been set on this DB."""
        with db.connect(self.db_path) as conn:
            return (
                db.get_meta(conn, META_SALT) is not None
                and db.get_meta(conn, META_VERIFIER) is not None
            )

    def set_master_password(self, master_password: str) -> None:
        """Initialise master password. Refuses if one is already set."""
        if self.has_master_password():
            raise RuntimeError("master password already set")
        if not master_password:
            raise ValueError("master password must not be empty")

        salt = crypto.generate_salt()
        key = crypto.derive_key(master_password, salt)
        fernet = Fernet(key)
        verifier = crypto.make_verifier(fernet)

        with db.connect(self.db_path) as conn:
            db.set_meta(conn, META_SALT, salt)
            db.set_meta(conn, META_VERIFIER, verifier)
        self._fernet = fernet

    def verify_master_password(self, master_password: str) -> bool:
        """Return True iff `master_password` matches; on success, unlocks the manager."""
        with db.connect(self.db_path) as conn:
            salt = db.get_meta(conn, META_SALT)
            verifier = db.get_meta(conn, META_VERIFIER)
        if salt is None or verifier is None:
            return False

        key = crypto.derive_key(master_password, salt)
        fernet = Fernet(key)
        if crypto.check_verifier(fernet, verifier):
            self._fernet = fernet
            return True
        return False

    def lock(self) -> None:
        """Forget the derived key (forces re-authentication)."""
        self._fernet = None

    @property
    def is_unlocked(self) -> bool:
        return self._fernet is not None

    def _require_unlocked(self) -> Fernet:
        if self._fernet is None:
            raise RuntimeError("manager is locked: verify master password first")
        return self._fernet

    # ---------- CRUD ----------

    def create_user(self, login: str, email: str, password: str) -> UserRecord:
        """Insert a new account. Raises ValueError on duplicate login."""
        if not login:
            raise ValueError("login must not be empty")
        fernet = self._require_unlocked()
        encrypted = crypto.encrypt_str(fernet, password)
        try:
            with db.connect(self.db_path) as conn:
                cur = conn.execute(
                    "INSERT INTO users(login, email, password_encrypted) VALUES (?, ?, ?)",
                    (login, email, encrypted),
                )
                user_id = cur.lastrowid
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"login {login!r} already exists") from exc
        return self._fetch_by_id(user_id)

    def get_user(self, login: str) -> UserRecord | None:
        """Return the account with the given login, or None."""
        fernet = self._require_unlocked()
        with db.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, login, email, password_encrypted, created_at "
                "FROM users WHERE login = ?",
                (login,),
            ).fetchone()
        return self._row_to_record(row, fernet) if row else None

    def list_users(self) -> list[UserRecord]:
        """Return all accounts, passwords decrypted, ordered by id."""
        fernet = self._require_unlocked()
        with db.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, login, email, password_encrypted, created_at "
                "FROM users ORDER BY id"
            ).fetchall()
        return [self._row_to_record(row, fernet) for row in rows]

    def delete_user(self, login: str) -> bool:
        """Delete the account by login. Returns True iff a row was removed."""
        with db.connect(self.db_path) as conn:
            cur = conn.execute("DELETE FROM users WHERE login = ?", (login,))
            return cur.rowcount > 0

    def update_password(self, login: str, new_password: str) -> bool:
        """Re-encrypt and store a new password for `login`. Returns True iff updated."""
        fernet = self._require_unlocked()
        encrypted = crypto.encrypt_str(fernet, new_password)
        with db.connect(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE users SET password_encrypted = ? WHERE login = ?",
                (encrypted, login),
            )
            return cur.rowcount > 0

    def search(self, query: str) -> list[UserRecord]:
        """Case-insensitive substring search over login + email."""
        fernet = self._require_unlocked()
        like = f"%{query}%"
        with db.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, login, email, password_encrypted, created_at "
                "FROM users WHERE login LIKE ? OR IFNULL(email,'') LIKE ? "
                "ORDER BY id",
                (like, like),
            ).fetchall()
        return [self._row_to_record(row, fernet) for row in rows]

    # ---------- import / export ----------

    def export_to_json(self, path: str) -> int:
        """Write all accounts (decrypted) to `path`. Returns count exported.

        `path` may contain `~` or `$VAR`; missing parent directories are created.
        """
        resolved = _resolve_path(path)
        parent = os.path.dirname(resolved)
        if parent:
            os.makedirs(parent, exist_ok=True)
        records = self.list_users()
        payload = [r.to_dict() for r in records]
        with open(resolved, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        return len(records)

    def import_from_json(self, path: str, *, skip_duplicates: bool = True) -> int:
        """Load accounts from a JSON file produced by `export_to_json`.

        Returns the number of newly inserted rows. Duplicates are skipped by default.
        `path` may contain `~` or `$VAR`.
        """
        resolved = _resolve_path(path)
        with open(resolved, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        if not isinstance(payload, list):
            raise ValueError("import file must contain a JSON array of objects")

        inserted = 0
        for entry in payload:
            login = entry.get("login")
            email = entry.get("email")
            password = entry.get("password")
            if not login or password is None:
                continue
            try:
                self.create_user(login, email or "", password)
                inserted += 1
            except ValueError:
                if not skip_duplicates:
                    raise
        return inserted

    # ---------- internals ----------

    def _fetch_by_id(self, user_id: int) -> UserRecord:
        fernet = self._require_unlocked()
        with db.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, login, email, password_encrypted, created_at "
                "FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is None:  # pragma: no cover - sanity guard
            raise RuntimeError(f"user id {user_id} not found after insert")
        return self._row_to_record(row, fernet)

    @staticmethod
    def _row_to_record(row: sqlite3.Row, fernet: Fernet) -> UserRecord:
        return UserRecord(
            id=row["id"],
            login=row["login"],
            email=row["email"],
            password=crypto.decrypt_str(fernet, row["password_encrypted"]),
            created_at=row["created_at"],
        )


def iter_records(records: Iterable[UserRecord]) -> Iterable[dict]:
    """Helper used by the CLI to render record lists."""
    for r in records:
        yield r.to_dict()


def _resolve_path(path: str) -> str:
    """Expand `~` and environment variables; return an absolute path."""
    if not path:
        raise ValueError("path must not be empty")
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
