import sqlite3
import unittest
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "test_users.db"


def vulnerable_login(username, password):
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' "
        f"AND password = '{password}'"
    )

    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(query).fetchone()


def secure_login(username, password):
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = ? AND password = ?"
    )

    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(query, (username, password)).fetchone()


class AuthenticationBypassTests(unittest.TestCase):

    def test_wrong_password_is_rejected(self):
        self.assertIsNone(
            vulnerable_login("alice", "wrong-password")
        )
        self.assertIsNone(
            secure_login("alice", "wrong-password")
        )

    def test_secure_query_treats_injection_as_data(self):
        payload = "' OR '1'='1' --"

        result = secure_login(payload, "wrong-password")

        self.assertIsNone(result)

    def test_vulnerable_query_allows_controlled_bypass(self):
        # This test uses only the isolated test database.
        username = "' OR '1'='1' --"
        password = "anything"

        result = vulnerable_login(username, password)

        self.assertIsNotNone(result)

    def test_secure_query_rejects_same_bypass_input(self):
        username = "' OR '1'='1' --"
        password = "anything"

        result = secure_login(username, password)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
