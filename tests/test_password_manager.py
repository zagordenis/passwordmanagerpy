"""Self-contained smoke tests. Run with: python -m unittest tests.test_password_manager"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from password_manager.manager import PasswordManager


class PasswordManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        self.manager = PasswordManager(self.db_path)
        self.manager.set_master_password("correct horse battery staple")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_master_password_set_and_verify(self) -> None:
        # Re-open and verify master password on a fresh manager instance.
        fresh = PasswordManager(self.db_path)
        self.assertTrue(fresh.has_master_password())
        self.assertFalse(fresh.verify_master_password("wrong"))
        self.assertTrue(fresh.verify_master_password("correct horse battery staple"))

    def test_create_get_list(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "p@ssw0rd!")
        self.manager.create_user("bob", "bob@example.com", "hunter2")
        record = self.manager.get_user("alice")
        assert record is not None
        self.assertEqual(record.email, "alice@example.com")
        self.assertEqual(record.password, "p@ssw0rd!")
        all_records = self.manager.list_users()
        self.assertEqual([r.login for r in all_records], ["alice", "bob"])

    def test_duplicate_login_raises(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "p1")
        with self.assertRaises(ValueError):
            self.manager.create_user("alice", "x@y.com", "p2")

    def test_update_and_delete(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "p1")
        self.assertTrue(self.manager.update_password("alice", "p2"))
        record = self.manager.get_user("alice")
        assert record is not None
        self.assertEqual(record.password, "p2")
        self.assertTrue(self.manager.delete_user("alice"))
        self.assertIsNone(self.manager.get_user("alice"))

    def test_search(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "p1")
        self.manager.create_user("bob", "bob@corp.io", "p2")
        results = self.manager.search("corp")
        self.assertEqual([r.login for r in results], ["bob"])

    def test_password_not_stored_plaintext(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "secret-XYZ")
        with open(self.db_path, "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"secret-XYZ", blob)

    def test_export_import_roundtrip(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "p1")
        self.manager.create_user("bob", "bob@example.com", "p2")
        export_path = os.path.join(self.tmp.name, "export.json")
        self.assertEqual(self.manager.export_to_json(export_path), 2)

        with open(export_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual({entry["login"] for entry in data}, {"alice", "bob"})

        # New DB, import the export.
        other_db = os.path.join(self.tmp.name, "other.db")
        other = PasswordManager(other_db)
        other.set_master_password("other-master")
        inserted = other.import_from_json(export_path)
        self.assertEqual(inserted, 2)
        self.assertEqual(other.get_user("alice").password, "p1")  # type: ignore[union-attr]

    def test_locked_operations_require_master(self) -> None:
        fresh = PasswordManager(self.db_path)  # not yet unlocked
        with self.assertRaises(RuntimeError):
            fresh.create_user("x", "y", "z")

    def test_lock_after_unlock_clears_key(self) -> None:
        """Explicit lock() must drop the derived key so subsequent ops fail."""
        self.manager.create_user("alice", "a@x.com", "p1")
        self.assertTrue(self.manager.is_unlocked)
        self.manager.lock()
        self.assertFalse(self.manager.is_unlocked)
        with self.assertRaises(RuntimeError):
            self.manager.list_users()
        with self.assertRaises(RuntimeError):
            self.manager.create_user("bob", "b@x.com", "p2")
        # Re-unlock works and old data is intact.
        self.assertTrue(
            self.manager.verify_master_password("correct horse battery staple")
        )
        record = self.manager.get_user("alice")
        assert record is not None
        self.assertEqual(record.password, "p1")

    def test_export_path_expanduser(self) -> None:
        """Path starting with `~` must be expanded against $HOME, not taken literally."""
        self.manager.create_user("alice", "alice@example.com", "p1")
        original_home = os.environ.get("HOME")
        try:
            os.environ["HOME"] = self.tmp.name
            count = self.manager.export_to_json("~/export.json")
        finally:
            if original_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = original_home
        self.assertEqual(count, 1)
        # Literal "~/export.json" must NOT exist; the expanded path must.
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "~", "export.json")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "export.json")))

    def test_export_creates_missing_parent_dir(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "p1")
        target = os.path.join(self.tmp.name, "nested", "deeper", "export.json")
        count = self.manager.export_to_json(target)
        self.assertEqual(count, 1)
        self.assertTrue(os.path.exists(target))

    def test_change_master_password_reencrypts_all_rows(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "p1")
        self.manager.create_user("bob", "bob@example.com", "p2")

        count = self.manager.change_master_password(
            "correct horse battery staple", "new-master"
        )
        self.assertEqual(count, 2)

        # Old master no longer works on a fresh instance.
        fresh = PasswordManager(self.db_path)
        self.assertFalse(fresh.verify_master_password("correct horse battery staple"))
        # New master decrypts everything.
        self.assertTrue(fresh.verify_master_password("new-master"))
        self.assertEqual(fresh.get_user("alice").password, "p1")  # type: ignore[union-attr]
        self.assertEqual(fresh.get_user("bob").password, "p2")  # type: ignore[union-attr]

    def test_change_master_password_wrong_old_rejected(self) -> None:
        self.manager.create_user("alice", "alice@example.com", "p1")
        with self.assertRaisesRegex(ValueError, "old master password"):
            self.manager.change_master_password("wrong-old", "new-master")
        # Original master must still work after a rejected attempt.
        fresh = PasswordManager(self.db_path)
        self.assertTrue(fresh.verify_master_password("correct horse battery staple"))
        self.assertEqual(fresh.get_user("alice").password, "p1")  # type: ignore[union-attr]

    def test_change_master_password_empty_new_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "new master password"):
            self.manager.change_master_password(
                "correct horse battery staple", ""
            )

    def test_change_master_password_atomic_on_decrypt_failure(self) -> None:
        """If a row fails to decrypt mid-rotation, NOTHING gets committed."""
        self.manager.create_user("alice", "alice@example.com", "p1")
        self.manager.create_user("bob", "bob@example.com", "p2")
        # Corrupt bob's ciphertext so re-encryption will fail mid-loop.
        import sqlite3 as _sqlite3
        with _sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET password_encrypted = ? WHERE login = ?",
                ("not-a-valid-fernet-token", "bob"),
            )
            conn.commit()
        # Re-open manager so the instance state matches the on-disk state.
        broken = PasswordManager(self.db_path)
        self.assertTrue(
            broken.verify_master_password("correct horse battery staple")
        )

        with self.assertRaises(Exception):
            broken.change_master_password(
                "correct horse battery staple", "new-master"
            )

        # After failure: old master STILL works (no meta rotation),
        # alice's password STILL decrypts to 'p1' (no half-applied UPDATE).
        fresh = PasswordManager(self.db_path)
        self.assertTrue(
            fresh.verify_master_password("correct horse battery staple"),
            "old master must still work after rolled-back rotation",
        )
        self.assertEqual(fresh.get_user("alice").password, "p1")  # type: ignore[union-attr]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
