import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "test_users.db"


def test_vulnerable_query(username, password):
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' "
        f"AND password = '{password}'"
    )

    with sqlite3.connect(DB_PATH) as connection:
        return connection.execute(query).fetchone()


def test_secure_query(username, password):
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = ? AND password = ?"
    )

    with sqlite3.connect(DB_PATH) as connection:
        return connection.execute(
            query, (username, password)
        ).fetchone()


if __name__ == "__main__":
    print("Normal login:")
    print("Vulnerable query:", test_vulnerable_query("alice", "LabPass123!"))
    print("Parameterized query:", test_secure_query("alice", "LabPass123!"))

    print("\nInvalid password:")
    print("Vulnerable query:", test_vulnerable_query("alice", "wrong-password"))
    print("Parameterized query:", test_secure_query("alice", "wrong-password"))
