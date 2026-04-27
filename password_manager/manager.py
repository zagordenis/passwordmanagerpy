"""High-level PasswordManager API used by the CLI and tests."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from typing import Iterable

from cryptography.fernet import Fernet, InvalidToken

from . import crypto, db

DEFAULT_DB_PATH = "users.db"

META_SALT = "salt"
META_VERIFIER = "verifier"
META_KDF = "kdf_version"


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
        """Initialise master password. Refuses if one is already set.

        New databases always use Argon2id (the only KDF written by this
        method). PBKDF2 paths exist solely to read databases produced by
        previous releases; those are migrated by ``change_master_password``.
        """
        if self.has_master_password():
            raise RuntimeError("master password already set")
        if not master_password:
            raise ValueError("master password must not be empty")

        salt = crypto.generate_salt()
        key = crypto.derive_key(
            master_password, salt, kdf_version=crypto.KDF_ARGON2ID_V1,
        )
        fernet = Fernet(key)
        verifier = crypto.make_verifier(fernet)

        with db.connect(self.db_path) as conn:
            db.set_meta(conn, META_SALT, salt)
            db.set_meta(conn, META_VERIFIER, verifier)
            db.set_meta(conn, META_KDF, crypto.KDF_ARGON2ID_V1.encode("utf-8"))
        self._fernet = fernet

    def _read_kdf_version(self, conn) -> str:
        """Return the KDF identifier stored for this DB.

        Old databases (pre-Argon2 release) have no ``kdf_version`` row at
        all — those are PBKDF2-legacy by definition.
        """
        raw = db.get_meta(conn, META_KDF)
        if raw is None:
            return crypto.KDF_PBKDF2_LEGACY
        return raw.decode("utf-8")

    def verify_master_password(self, master_password: str) -> bool:
        """Return True iff `master_password` matches; on success, unlocks the manager."""
        with db.connect(self.db_path) as conn:
            salt = db.get_meta(conn, META_SALT)
            verifier = db.get_meta(conn, META_VERIFIER)
            kdf_version = self._read_kdf_version(conn)
        if salt is None or verifier is None:
            return False

        try:
            key = crypto.derive_key(master_password, salt, kdf_version=kdf_version)
        except ValueError:
            return False
        fernet = Fernet(key)
        if crypto.check_verifier(fernet, verifier):
            self._fernet = fernet
            return True
        return False

    def is_legacy_kdf(self) -> bool:
        """True iff this DB still uses the PBKDF2 KDF.

        The CLI uses this to nudge the user to change their master password
        (which migrates the DB to Argon2id automatically).
        """
        with db.connect(self.db_path) as conn:
            return self._read_kdf_version(conn) == crypto.KDF_PBKDF2_LEGACY

    def change_master_password(
        self, old_master_password: str, new_master_password: str
    ) -> int:
        """Re-encrypt every stored password under a new master in one transaction.

        Verifies `old_master_password` first. Generates a fresh salt + key for
        the new master, decrypts each row with the old key, encrypts with the
        new key, and updates `salt` + `verifier` — all inside a single SQLite
        transaction. Either every row is migrated (and meta updated), or
        nothing is changed.

        Returns the number of rows re-encrypted. After success, the manager is
        unlocked under the new master.
        """
        if not new_master_password:
            raise ValueError("new master password must not be empty")
        if not self.verify_master_password(old_master_password):
            raise ValueError("old master password is incorrect")

        old_fernet = self._fernet  # set by verify_master_password above
        assert old_fernet is not None

        new_salt = crypto.generate_salt()
        # Always migrate to Argon2id on master change — this is the path
        # that takes legacy PBKDF2 databases off the legacy KDF.
        new_key = crypto.derive_key(
            new_master_password, new_salt, kdf_version=crypto.KDF_ARGON2ID_V1,
        )
        new_fernet = Fernet(new_key)
        new_verifier = crypto.make_verifier(new_fernet)

        # Single transaction: re-encrypt every row, then rotate meta. SQLite's
        # default isolation rolls back automatically on exception.
        try:
            with db.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT id, password_encrypted FROM users"
                ).fetchall()
                count = 0
                for row in rows:
                    plaintext = crypto.decrypt_str(
                        old_fernet, row["password_encrypted"]
                    )
                    reencrypted = crypto.encrypt_str(new_fernet, plaintext)
                    conn.execute(
                        "UPDATE users SET password_encrypted = ? WHERE id = ?",
                        (reencrypted, row["id"]),
                    )
                    count += 1
                db.set_meta(conn, META_SALT, new_salt)
                db.set_meta(conn, META_VERIFIER, new_verifier)
                db.set_meta(conn, META_KDF, crypto.KDF_ARGON2ID_V1.encode("utf-8"))
        except InvalidToken as exc:
            # A stored row failed to decrypt under the verified old master —
            # this means the DB was tampered with or corrupted. The transaction
            # rolls back automatically, leaving the DB on the old master.
            raise ValueError(
                "database appears corrupted: a stored password could not be "
                "decrypted under the current master. Aborted; nothing changed."
            ) from exc
        self._fernet = new_fernet
        return count

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
        """Delete the account by login. Returns True iff a row was removed.

        Requires the manager to be unlocked. Although deleting a row does not
        need the encryption key, this matches the contract of every other
        CRUD method (and prevents a destructive op from succeeding while the
        manager is locked, e.g. after auto-lock or an explicit ``lock()``).
        """
        self._require_unlocked()
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
        """Case-insensitive substring search over login + email.

        Filtering happens in Python (not SQL ``LIKE``) so that case-folding
        works correctly for non-ASCII text — SQLite's built-in ``LIKE`` and
        ``LOWER`` only handle ASCII, which silently breaks Cyrillic /
        Unicode logins. For a personal password store this O(N) scan is fine.
        """
        fernet = self._require_unlocked()
        needle = query.casefold()
        with db.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT id, login, email, password_encrypted, created_at "
                "FROM users ORDER BY id"
            ).fetchall()
        out: list[UserRecord] = []
        for row in rows:
            login = row["login"] or ""
            email = row["email"] or ""
            if needle in login.casefold() or needle in email.casefold():
                out.append(self._row_to_record(row, fernet))
        return out

    # ---------- import / export ----------

    def export_to_json(self, path: str) -> int:
        """Write all accounts (decrypted) to `path`. Returns count exported.

        `path` may contain `~` or `$VAR`; missing parent directories are created.
        On POSIX the file is created with mode ``0o600`` (owner read/write only)
        so that other local users cannot read the plaintext passwords.
        """
        resolved = _resolve_path(path)
        parent = os.path.dirname(resolved)
        if parent:
            os.makedirs(parent, exist_ok=True)
        records = self.list_users()
        payload = [r.to_dict() for r in records]
        # Open with restrictive perms BEFORE writing, so the plaintext is
        # never on disk with looser perms even momentarily.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(resolved, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        # Re-chmod in case the file already existed with looser perms (``os.open``
        # with ``O_CREAT`` does not change perms on an existing file).
        try:
            os.chmod(resolved, 0o600)
        except OSError:  # pragma: no cover - non-POSIX or read-only fs
            pass
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
            if not isinstance(entry, dict):
                # Tolerate junk entries instead of crashing mid-import.
                continue
            login = entry.get("login")
            email = entry.get("email")
            password = entry.get("password")
            if not isinstance(login, str) or not login:
                continue
            if not isinstance(password, str):
                continue
            if email is not None and not isinstance(email, str):
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
