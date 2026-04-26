"""Password manager package: secure storage of credentials with Fernet + PBKDF2."""

from .manager import PasswordManager

__all__ = ["PasswordManager"]
