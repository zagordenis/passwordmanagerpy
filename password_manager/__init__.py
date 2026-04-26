"""Password manager package: secure storage of credentials with Fernet + PBKDF2."""

from .generator import PasswordPolicy, generate_password
from .manager import PasswordManager

__all__ = ["PasswordManager", "PasswordPolicy", "generate_password"]
