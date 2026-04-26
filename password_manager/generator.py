"""Cryptographically secure password generator.

Uses ``secrets.SystemRandom`` (i.e. OS CSPRNG via ``os.urandom``) — never
``random``. The default policy is "long enough that brute force is
infeasible regardless of the character classes":
20 characters, all four classes (lower / upper / digit / symbol) enabled.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass


# Reasonable, broadly compatible symbol set. Excludes whitespace, quotes, and
# backslash so the generated passwords copy/paste cleanly through shells and
# most web forms.
DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"

DEFAULT_LENGTH = 20
MIN_LENGTH = 4   # one of each class is impossible below this with all 4 on
MAX_LENGTH = 4096  # sanity cap — 4096 chars is already absurd entropy


@dataclass(frozen=True)
class PasswordPolicy:
    length: int = DEFAULT_LENGTH
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    symbols: str = DEFAULT_SYMBOLS

    def alphabet(self) -> str:
        """Return the full character pool for this policy."""
        parts: list[str] = []
        if self.use_lower:
            parts.append(string.ascii_lowercase)
        if self.use_upper:
            parts.append(string.ascii_uppercase)
        if self.use_digits:
            parts.append(string.digits)
        if self.use_symbols:
            parts.append(self.symbols)
        return "".join(parts)

    def required_classes(self) -> list[str]:
        """Return the per-class alphabets that the result MUST contain at
        least one character from."""
        classes: list[str] = []
        if self.use_lower:
            classes.append(string.ascii_lowercase)
        if self.use_upper:
            classes.append(string.ascii_uppercase)
        if self.use_digits:
            classes.append(string.digits)
        if self.use_symbols:
            classes.append(self.symbols)
        return classes


def generate_password(policy: PasswordPolicy | None = None) -> str:
    """Generate a single password matching the given policy.

    Algorithm:
    1. Validate the policy (length range, at least one class enabled).
    2. Pick exactly one character from each enabled class so the result
       provably satisfies the class requirements.
    3. Fill the remaining slots from the combined alphabet.
    4. Shuffle in place using ``SystemRandom``.

    All randomness comes from ``secrets`` / ``SystemRandom`` (OS CSPRNG).
    """
    p = policy or PasswordPolicy()

    if p.length < MIN_LENGTH or p.length > MAX_LENGTH:
        raise ValueError(
            f"length must be between {MIN_LENGTH} and {MAX_LENGTH}"
        )

    classes = p.required_classes()
    if not classes or any(c == "" for c in classes):
        raise ValueError("at least one character class must be enabled")
    if p.length < len(classes):
        # Not enough room to satisfy "one of each class".
        raise ValueError(
            f"length {p.length} is too short for {len(classes)} required classes"
        )

    alphabet = p.alphabet()
    rng = secrets.SystemRandom()

    # Step 2: one guaranteed char per enabled class.
    chars: list[str] = [secrets.choice(c) for c in classes]
    # Step 3: fill the rest from the combined alphabet.
    chars += [secrets.choice(alphabet) for _ in range(p.length - len(classes))]
    # Step 4: shuffle so the guaranteed chars aren't always at the start.
    rng.shuffle(chars)
    return "".join(chars)
