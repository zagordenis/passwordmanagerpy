"""Crypto helpers: derive a Fernet key from a master password.

Default KDF is Argon2id (winner of the 2015 Password Hashing Competition,
OWASP-recommended for 2024+). PBKDF2-HMAC-SHA256 is still supported for
backward compatibility with databases created by versions <= 0.x of this
project, and is auto-migrated to Argon2id on the next ``change_master_password``.
"""

from __future__ import annotations

import base64
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---- KDF identifiers stored in the database ----
KDF_ARGON2ID_V1 = "argon2id-v1"
KDF_PBKDF2_LEGACY = "pbkdf2-sha256-legacy"

# ---- Argon2id parameters (OWASP 2024 recommended minima) ----
# m=19 MiB, t=2, p=1 — comfortably above the OWASP floor on a typical desktop.
ARGON2_MEMORY_KIB = 19_456  # 19 MiB
ARGON2_TIME_COST = 2
ARGON2_PARALLELISM = 1

# ---- PBKDF2 parameters (legacy path only) ----
PBKDF2_ITERATIONS = 480_000

SALT_SIZE = 16
# Token encrypted at master-setup time; decrypting it on login verifies the password.
VERIFIER_PLAINTEXT = b"password_manager:verifier:v1"


def generate_salt() -> bytes:
    """Return a fresh cryptographically random salt."""
    return os.urandom(SALT_SIZE)


def _validate_inputs(master_password: str, salt: bytes) -> None:
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("master_password must be a non-empty string")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt must be at least 8 bytes")


def _derive_key_argon2id(master_password: str, salt: bytes) -> bytes:
    raw_key = hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=bytes(salt),
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )
    return base64.urlsafe_b64encode(raw_key)


def _derive_key_pbkdf2(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def derive_key(
    master_password: str,
    salt: bytes,
    kdf_version: str = KDF_ARGON2ID_V1,
) -> bytes:
    """Derive a url-safe base64 Fernet key from master password + salt.

    ``kdf_version`` selects the KDF — defaults to Argon2id. Pass
    ``KDF_PBKDF2_LEGACY`` only when verifying or migrating an old database.
    """
    _validate_inputs(master_password, salt)
    if kdf_version == KDF_ARGON2ID_V1:
        return _derive_key_argon2id(master_password, salt)
    if kdf_version == KDF_PBKDF2_LEGACY:
        return _derive_key_pbkdf2(master_password, salt)
    raise ValueError(f"unknown kdf_version: {kdf_version!r}")


def make_verifier(fernet: Fernet) -> bytes:
    """Encrypt the canonical verifier plaintext with `fernet`."""
    return fernet.encrypt(VERIFIER_PLAINTEXT)


def check_verifier(fernet: Fernet, token: bytes) -> bool:
    """Return True iff `fernet` decrypts `token` to the canonical plaintext."""
    try:
        return fernet.decrypt(token) == VERIFIER_PLAINTEXT
    except InvalidToken:
        return False


def encrypt_str(fernet: Fernet, plaintext: str) -> str:
    """Encrypt a string and return the token as utf-8 text suitable for SQLite TEXT."""
    token = fernet.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_str(fernet: Fernet, token: str) -> str:
    """Decrypt a token string previously produced by `encrypt_str`."""
    return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
