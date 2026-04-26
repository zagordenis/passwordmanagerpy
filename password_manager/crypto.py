"""Crypto helpers: derive a Fernet key from a master password using PBKDF2-HMAC-SHA256."""

from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Tunable PBKDF2 cost. 480_000 matches current OWASP guidance for SHA-256.
PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16
# Token encrypted at master-setup time; decrypting it on login verifies the password.
VERIFIER_PLAINTEXT = b"password_manager:verifier:v1"


def generate_salt() -> bytes:
    """Return a fresh cryptographically random salt."""
    return os.urandom(SALT_SIZE)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a url-safe base64 Fernet key from master password + salt."""
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("master_password must be a non-empty string")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("salt must be at least 8 bytes")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


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
