"""Tests for the password generator."""

from __future__ import annotations

import string
import unittest
from collections import Counter

from password_manager.generator import (
    DEFAULT_LENGTH,
    DEFAULT_SYMBOLS,
    MAX_LENGTH,
    MIN_LENGTH,
    PasswordPolicy,
    generate_password,
)


class GeneratorTests(unittest.TestCase):
    def test_default_policy_length(self) -> None:
        pw = generate_password()
        self.assertEqual(len(pw), DEFAULT_LENGTH)

    def test_custom_length_respected(self) -> None:
        for n in (4, 8, 32, 128):
            pw = generate_password(PasswordPolicy(length=n))
            self.assertEqual(len(pw), n, f"failed at length {n}")

    def test_default_policy_satisfies_all_four_classes(self) -> None:
        # Run many iterations: with all four classes enabled we GUARANTEE at
        # least one of each (not statistical), so every iteration must hold.
        for _ in range(200):
            pw = generate_password()
            self.assertTrue(any(c in string.ascii_lowercase for c in pw))
            self.assertTrue(any(c in string.ascii_uppercase for c in pw))
            self.assertTrue(any(c in string.digits for c in pw))
            self.assertTrue(any(c in DEFAULT_SYMBOLS for c in pw))

    def test_only_lowercase(self) -> None:
        policy = PasswordPolicy(
            length=32,
            use_lower=True,
            use_upper=False,
            use_digits=False,
            use_symbols=False,
        )
        for _ in range(50):
            pw = generate_password(policy)
            self.assertTrue(all(c in string.ascii_lowercase for c in pw))

    def test_only_digits(self) -> None:
        policy = PasswordPolicy(
            length=10,
            use_lower=False,
            use_upper=False,
            use_digits=True,
            use_symbols=False,
        )
        for _ in range(50):
            pw = generate_password(policy)
            self.assertTrue(pw.isdigit())

    def test_no_classes_enabled_rejected(self) -> None:
        policy = PasswordPolicy(
            length=20,
            use_lower=False,
            use_upper=False,
            use_digits=False,
            use_symbols=False,
        )
        with self.assertRaisesRegex(ValueError, "at least one character class"):
            generate_password(policy)

    def test_length_below_min_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "between"):
            generate_password(PasswordPolicy(length=MIN_LENGTH - 1))

    def test_length_above_max_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "between"):
            generate_password(PasswordPolicy(length=MAX_LENGTH + 1))

    def test_no_collisions_in_many_runs(self) -> None:
        """Sanity check: 1000 default-length passwords should all be unique.

        Probability of any collision with a 70-char alphabet at length 20 is
        astronomical; a duplicate would indicate a CSPRNG bug.
        """
        seen = {generate_password() for _ in range(1000)}
        self.assertEqual(len(seen), 1000)

    def test_distribution_is_not_obviously_biased(self) -> None:
        """Across 5000 chars from a uniform alphabet, no single char dominates.

        With a 26-char alphabet and 5000 samples, the expected count per char
        is ~192 and 4σ tolerance means no character should appear > 350 times.
        Loose threshold; only catches catastrophic bias (e.g. always 'a').
        """
        policy = PasswordPolicy(
            length=100,
            use_lower=True,
            use_upper=False,
            use_digits=False,
            use_symbols=False,
        )
        joined = "".join(generate_password(policy) for _ in range(50))
        counts = Counter(joined)
        self.assertGreaterEqual(len(counts), 20, "alphabet not well covered")
        self.assertLess(max(counts.values()), 400, "looks heavily biased")

    def test_symbols_customization(self) -> None:
        policy = PasswordPolicy(
            length=12,
            use_lower=False,
            use_upper=False,
            use_digits=False,
            use_symbols=True,
            symbols="!@",
        )
        for _ in range(20):
            pw = generate_password(policy)
            self.assertTrue(all(c in "!@" for c in pw))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
