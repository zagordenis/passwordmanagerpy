"""Tests for the listing format: row index + DB id."""

from __future__ import annotations

import io
import os
import re
import tempfile
import unittest
from unittest.mock import patch

from password_manager import cli
from password_manager.manager import PasswordManager


class ListingFormatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "users.db")
        self.manager = PasswordManager(self.db_path)
        self.manager.set_master_password("master-1")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _capture_list(self, manager: PasswordManager) -> str:
        out = io.StringIO()
        with patch("sys.stdout", new=out):
            cli._print_records(manager.list_users())
        return out.getvalue()

    def test_row_index_starts_from_one_after_deletion(self) -> None:
        """Видалення першого запису не повинно лишати DB id "1" видимим
        у переліку — порядковий номер починається з 1, а DB id зростає."""
        self.manager.create_user("alice", "a@x", "p1")
        self.manager.delete_user("alice")
        self.manager.create_user("bob", "b@x", "p2")

        output = self._capture_list(self.manager)

        # Точний рядок: рівно одна стрічка-запис, починається з [1] id=2.
        # `id=1` НЕ повинно з'являтися (alice видалена), і порядковий [1]
        # переюзається попри stable DB id 2.
        match = re.search(
            r"^\s*\[1\]\s+id=(\d+)\s+login='bob'", output, re.MULTILINE
        )
        self.assertIsNotNone(match, f"row not in expected format: {output!r}")
        # DB id для нового запису — не 1 (бо AUTOINCREMENT не переюзає),
        # тому конкретний id буде 2 за SQLite-семантикою AUTOINCREMENT.
        self.assertEqual(match.group(1), "2")
        # alice (id=1) точно не повинна світитися
        self.assertNotIn("alice", output)
        self.assertNotIn("id=1 ", output)

    def test_row_index_renumbers_each_listing(self) -> None:
        """Якщо в БД 3 записи з id 5, 7, 12 — порядковий номер у виводі
        має бути [1] [2] [3] незалежно від DB id."""
        # Створимо 5 акаунтів і видалимо середні щоб id-и розкрутились
        for i in range(5):
            self.manager.create_user(f"u{i}", f"e{i}", f"p{i}")
        self.manager.delete_user("u1")
        self.manager.delete_user("u3")

        output = self._capture_list(self.manager)

        # 3 рядки: [1] [2] [3] — у такому ж порядку, що list_users().
        rows = re.findall(
            r"^\s*\[(\d+)\]\s+id=(\d+)\s+login='([^']+)'", output, re.MULTILINE
        )
        self.assertEqual(
            [r[0] for r in rows], ["1", "2", "3"],
            f"row indices wrong: {rows}",
        )
        # DB id-и з gap-ами (1, 3, 5) — точна послідовність:
        self.assertEqual([r[1] for r in rows], ["1", "3", "5"])
        # Логіни в правильному порядку
        self.assertEqual([r[2] for r in rows], ["u0", "u2", "u4"])

    def test_single_record_without_index(self) -> None:
        """`_print_record` без index — для find-by-login: НЕ показує `[N]`,
        але показує `id=N`."""
        self.manager.create_user("alice", "a@x", "p1")
        record = self.manager.get_user("alice")
        self.assertIsNotNone(record)

        out = io.StringIO()
        with patch("sys.stdout", new=out):
            cli._print_record(record)
        output = out.getvalue()

        self.assertNotRegex(output, r"\[\d+\]")
        self.assertIn("id=", output)
        self.assertIn("login='alice'", output)

    def test_empty_listing(self) -> None:
        output = self._capture_list(self.manager)
        self.assertIn("порожньо", output)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
