"""Regression tests for the four bugs fixed in the audit:

1. ``export_to_json`` wrote a world-readable file (0o644).
2. ``import_from_json`` crashed on non-dict entries (AttributeError).
3. ``change_master_password`` leaked ``InvalidToken`` on a corrupted DB.
4. ``search`` was case-sensitive for non-ASCII (Cyrillic).

Each test is adversarial: revert the fix and the test fails with the exact
symptom the user would see.
"""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from password_manager.manager import PasswordManager


class _TmpDbCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        self.manager = PasswordManager(self.db_path)
        self.manager.set_master_password("master-1")

    def tearDown(self) -> None:
        self.tmp.cleanup()


class ExportFilePermissionsTests(_TmpDbCase):
    @unittest.skipUnless(
        os.name == "posix", "POSIX file permissions are not enforced on Windows"
    )
    def test_export_file_is_owner_readonly(self) -> None:
        self.manager.create_user("alice", "a@x.com", "very-secret")
        path = os.path.join(self.tmp.name, "export.json")
        self.manager.export_to_json(path)
        mode = os.stat(path).st_mode & 0o777
        self.assertEqual(
            mode, 0o600, f"expected 0o600, got {oct(mode)}"
        )
        # Adversarial: any "other" or "group" bit being set would be a
        # plaintext-leak vector on shared systems.
        self.assertFalse(mode & stat.S_IROTH, "world must not be able to read")
        self.assertFalse(mode & stat.S_IRGRP, "group must not be able to read")

    @unittest.skipUnless(os.name == "posix", "POSIX-only")
    def test_overwrite_existing_loose_file_tightens_perms(self) -> None:
        """If the export target already exists with 0o644, we must tighten it."""
        self.manager.create_user("alice", "a@x.com", "p1")
        path = os.path.join(self.tmp.name, "export.json")
        # Pre-create the file world-readable.
        with open(path, "w") as fh:
            fh.write("{}")
        os.chmod(path, 0o644)
        self.manager.export_to_json(path)
        mode = os.stat(path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class ImportRobustnessTests(_TmpDbCase):
    def test_import_skips_non_dict_entries_without_crash(self) -> None:
        """Mixed-type JSON list must not raise AttributeError mid-import."""
        path = os.path.join(self.tmp.name, "bad.json")
        with open(path, "w") as fh:
            json.dump(
                [
                    {"login": "good", "email": "g@x", "password": "p1"},
                    "garbage",
                    42,
                    None,
                    {"login": "also_good", "email": "g2@x", "password": "p2"},
                ],
                fh,
            )
        # Must not raise. Must import the two valid entries and silently
        # skip the three junk entries.
        inserted = self.manager.import_from_json(path)
        self.assertEqual(inserted, 2)
        self.assertIsNotNone(self.manager.get_user("good"))
        self.assertIsNotNone(self.manager.get_user("also_good"))

    def test_import_skips_entries_with_wrong_field_types(self) -> None:
        path = os.path.join(self.tmp.name, "bad2.json")
        with open(path, "w") as fh:
            json.dump(
                [
                    {"login": 123, "password": "p"},  # login not a string
                    {"login": "x", "password": 456},  # password not a string
                    {"login": "y", "email": 999, "password": "p"},  # email type
                    {"login": "ok", "email": "e@x", "password": "p"},  # valid
                ],
                fh,
            )
        inserted = self.manager.import_from_json(path)
        self.assertEqual(inserted, 1)
        self.assertIsNotNone(self.manager.get_user("ok"))


class ChangeMasterCorruptDbTests(_TmpDbCase):
    def test_corrupted_row_raises_value_error_not_invalid_token(self) -> None:
        """Corrupted ciphertext during change_master must not leak InvalidToken."""
        self.manager.create_user("alice", "a@x.com", "p1")
        # Corrupt the row directly via sqlite (simulates DB tampering / disk
        # corruption / partial write from a crashed previous run).
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET password_encrypted = 'GARBAGE' WHERE login='alice'"
            )
            conn.commit()
        # Old code path: raised cryptography.fernet.InvalidToken with no
        # message, surfaced through CLI as "Несподівана помилка: ".
        with self.assertRaises(ValueError) as ctx:
            self.manager.change_master_password("master-1", "master-2")
        # Message mentions "corrupted" so the CLI shows a useful hint.
        self.assertIn("corrupted", str(ctx.exception).lower())
        # CRITICAL: rollback worked — old master still functional, new master
        # does NOT. We don't want a half-migrated DB.
        m2 = PasswordManager(self.db_path)
        self.assertTrue(m2.verify_master_password("master-1"))
        self.assertFalse(m2.verify_master_password("master-2"))


class SearchUnicodeTests(_TmpDbCase):
    def test_search_case_insensitive_for_cyrillic(self) -> None:
        """Cyrillic search must be case-insensitive (docstring promise)."""
        self.manager.create_user("Адміністратор", "admin@x.com", "p1")
        self.manager.create_user("Користувач", "user@x.com", "p2")
        # Lowercase Cyrillic substring of a Capitalized login.
        results = [r.login for r in self.manager.search("адмін")]
        self.assertEqual(results, ["Адміністратор"])
        # Uppercase substring matches lowercase part of the login.
        results = [r.login for r in self.manager.search("КОРИСТ")]
        self.assertEqual(results, ["Користувач"])

    def test_search_still_works_for_ascii(self) -> None:
        """No regression for the ASCII path."""
        self.manager.create_user("Alice", "ALICE@x.com", "p1")
        self.assertEqual(
            [r.login for r in self.manager.search("alice")], ["Alice"]
        )
        self.assertEqual(
            [r.login for r in self.manager.search("ALICE")], ["Alice"]
        )

    def test_search_substring_in_email_only(self) -> None:
        self.manager.create_user("user1", "support@example.org", "p1")
        # No login match, but email contains "support".
        self.assertEqual(
            [r.login for r in self.manager.search("SUPPORT")], ["user1"]
        )


if __name__ == "__main__":
    unittest.main()
