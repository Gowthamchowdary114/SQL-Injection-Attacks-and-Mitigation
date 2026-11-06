import sqlite3
from pathlib import Path
from getpass import getpass

try:
    from .password_utils import verify_password
    from .security_controls import (
        is_rate_limited,
        record_login_failure,
        record_login_success,
        record_database_error,
    )
except ImportError:
    from password_utils import verify_password
    from security_controls import (
        is_rate_limited,
        record_login_failure,
        record_login_success,
        record_database_error,
    )

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "users.db"


def login(username, password):
    """Authenticate a user using a parameterized SQL query."""

    if is_rate_limited(username):
        return None

    try:
        with sqlite3.connect(DB_PATH) as connection:
            cursor = connection.cursor()

            cursor.execute(
                """
                SELECT id, username, password, role
                FROM users
                WHERE username = ?
                """,
                (username,),
            )

            user = cursor.fetchone()

        if user and verify_password(password, user[2]):
            record_login_success(username)
            return user[0], user[1], user[3]

        record_login_failure(username)
        return None

    except sqlite3.Error:
        record_database_error()
        print("A database error occurred.")
        return None


def main():
    print("=== SQL Injection Mitigation Lab ===")

    username = input("Username: ").strip()
    password = getpass("Password: ")

    user = login(username, password)

    if user:
        print(f"Login successful. Welcome, {user[1]}!")
        print(f"Role: {user[2]}")
    else:
        print("Login failed. Check your credentials.")


if __name__ == "__main__":
    main()
