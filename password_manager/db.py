"""SQLite schema + low-level access for the password manager."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    login              TEXT    UNIQUE NOT NULL,
    email              TEXT,
    password_encrypted TEXT    NOT NULL,
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
"""


def init_db(db_path: str) -> None:
    """Create the database file (if missing) and ensure tables/indexes exist."""
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def connect(db_path: str) -> Iterator[sqlite3.Connection]:
    """Context manager yielding a SQLite connection with row access by name."""
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------- meta helpers (salt + verifier token) ----------

def get_meta(conn: sqlite3.Connection, key: str) -> bytes | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else bytes(row["value"])


def set_meta(conn: sqlite3.Connection, key: str, value: bytes) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
