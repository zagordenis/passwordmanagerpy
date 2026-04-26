"""Argon2id KDF + backward-compat tests for PBKDF2-legacy databases."""

from __future__ import annotations

import os
import tempfile
import unittest

from cryptography.fernet import Fernet

from password_manager import crypto, db
from password_manager.manager import (
    META_KDF,
    META_SALT,
    META_VERIFIER,
    PasswordManager,
)


class _TmpDbCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")

    def tearDown(self) -> None:
        self.tmp.cleanup()


class NewDatabaseUsesArgon2idTests(_TmpDbCase):
    def test_new_db_writes_argon2id_marker(self) -> None:
        m = PasswordManager(self.db_path)
        m.set_master_password("master-1")
        with db.connect(self.db_path) as conn:
            kdf = db.get_meta(conn, META_KDF)
        self.assertIsNotNone(kdf)
        self.assertEqual(kdf.decode("utf-8"), crypto.KDF_ARGON2ID_V1)

    def test_new_db_is_not_legacy(self) -> None:
        m = PasswordManager(self.db_path)
        m.set_master_password("master-1")
        self.assertFalse(m.is_legacy_kdf())

    def test_verify_master_password_round_trip(self) -> None:
        m = PasswordManager(self.db_path)
        m.set_master_password("master-1")
        m.lock()
        self.assertTrue(m.verify_master_password("master-1"))
        self.assertFalse(m.verify_master_password("wrong"))


class LegacyPbkdf2DatabaseTests(_TmpDbCase):
    """Construct a DB the way the old code would have, then assert that the
    new code reads it correctly and migrates it on master change."""

    def _seed_legacy_db(self, master: str = "old-master") -> None:
        """Create a DB that has NO ``kdf_version`` row — i.e. PBKDF2 legacy."""
        salt = crypto.generate_salt()
        key = crypto.derive_key(master, salt, kdf_version=crypto.KDF_PBKDF2_LEGACY)
        fernet = Fernet(key)
        verifier = crypto.make_verifier(fernet)
        # Manually init schema and seed meta WITHOUT META_KDF.
        db.init_db(self.db_path)
        with db.connect(self.db_path) as conn:
            db.set_meta(conn, META_SALT, salt)
            db.set_meta(conn, META_VERIFIER, verifier)

    def test_legacy_db_detected_as_legacy(self) -> None:
        self._seed_legacy_db()
        m = PasswordManager(self.db_path)
        self.assertTrue(m.is_legacy_kdf())

    def test_legacy_db_verifies_master(self) -> None:
        """Old DB without `kdf_version` row must still unlock — via the
        PBKDF2 fallback."""
        self._seed_legacy_db("old-master")
        m = PasswordManager(self.db_path)
        self.assertTrue(m.verify_master_password("old-master"))
        self.assertFalse(m.verify_master_password("not-master"))

    def test_change_master_migrates_to_argon2id(self) -> None:
        """``change_master_password`` is the upgrade path — it must
        rewrite ``kdf_version`` and the verifier so a future verify uses
        Argon2id, not PBKDF2."""
        self._seed_legacy_db("old-master")
        m = PasswordManager(self.db_path)
        # Add a row to prove re-encryption survives the migration.
        self.assertTrue(m.verify_master_password("old-master"))
        m.create_user("alice", "a@x", "p@ssw0rd!")

        m.change_master_password("old-master", "new-master")

        # KDF marker has flipped:
        self.assertFalse(m.is_legacy_kdf())
        with db.connect(self.db_path) as conn:
            kdf = db.get_meta(conn, META_KDF)
        self.assertEqual(kdf.decode("utf-8"), crypto.KDF_ARGON2ID_V1)

        # Old master no longer works:
        m2 = PasswordManager(self.db_path)
        self.assertFalse(m2.verify_master_password("old-master"))
        # New master works AND the data was re-encrypted (decryptable):
        self.assertTrue(m2.verify_master_password("new-master"))
        record = m2.get_user("alice")
        self.assertIsNotNone(record)
        self.assertEqual(record.password, "p@ssw0rd!")


class CryptoLayerTests(unittest.TestCase):
    def test_unknown_kdf_version_rejected(self) -> None:
        with self.assertRaises(ValueError):
            crypto.derive_key("x", b"saltsalt12345678", kdf_version="bogus")

    def test_argon2id_and_pbkdf2_yield_different_keys(self) -> None:
        """Sanity: same password + salt → different keys for the two KDFs.
        If they ever matched we'd have a much bigger problem."""
        salt = b"saltsalt12345678"
        a = crypto.derive_key("x", salt, kdf_version=crypto.KDF_ARGON2ID_V1)
        p = crypto.derive_key("x", salt, kdf_version=crypto.KDF_PBKDF2_LEGACY)
        self.assertNotEqual(a, p)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
