import sqlite3
import unittest
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "test_users.db"


class SQLInjectionSecurityTests(unittest.TestCase):

    def test_parameterized_query_with_valid_user(self):
        with sqlite3.connect(DB_PATH) as conn:
            result = conn.execute(
                """
                SELECT id, username, role
                FROM users
                WHERE username = ?
                """,
                ("alice",)
            ).fetchone()

        self.assertIsNotNone(result)
        self.assertEqual(result[1], "alice")

    def test_parameterized_query_rejects_unknown_user(self):
        with sqlite3.connect(DB_PATH) as conn:
            result = conn.execute(
                """
                SELECT id, username, role
                FROM users
                WHERE username = ?
                """,
                ("unknown_user",)
            ).fetchone()

        self.assertIsNone(result)

    def test_parameterized_query_treats_injection_as_data(self):
        payload = "' OR '1'='1' --"

        with sqlite3.connect(DB_PATH) as conn:
            result = conn.execute(
                """
                SELECT id, username, role
                FROM users
                WHERE username = ?
                """,
                (payload,)
            ).fetchone()

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
