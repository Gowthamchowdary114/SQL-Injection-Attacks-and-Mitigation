import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "users.db"


def login(username, password):
    try:
        with sqlite3.connect(DB_PATH) as connection:
            cursor = connection.cursor()

            # INTENTIONALLY VULNERABLE:
            # User input is concatenated directly into SQL.
            query = (
                "SELECT id, username, role FROM users "
                f"WHERE username = '{username}' "
                f"AND password = '{password}'"
            )

            cursor.execute(query)
            return cursor.fetchone()

    except sqlite3.Error:
        print("Database error.")
        return None


def main():
    print("=== Vulnerable SQL Injection Demonstration ===")
    username = input("Username: ")
    password = input("Password: ")

    user = login(username, password)

    if user:
        print(f"Login successful. Welcome, {user[1]}!")
        print(f"Role: {user[2]}")
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
