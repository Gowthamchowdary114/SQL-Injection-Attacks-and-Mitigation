import sqlite3
from pathlib import Path

from password_utils import hash_password

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "users.db"


def is_pbkdf2_hash(value):
    """Check whether a value matches this project's PBKDF2 storage format."""
    try:
        parts = value.split("$")

        if len(parts) != 3:
            return False

        iterations, salt_hex, hash_hex = parts

        return (
            iterations.isdigit()
            and int(iterations) > 0
            and len(bytes.fromhex(salt_hex)) == 16
            and len(bytes.fromhex(hash_hex)) == 32
        )
    except (AttributeError, ValueError):
        return False


def migrate():
    migrated = 0
    skipped = 0

    try:
        with sqlite3.connect(DB_PATH) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT id, password FROM users")
            users = cursor.fetchall()

            for user_id, stored_password in users:
                if is_pbkdf2_hash(stored_password):
                    skipped += 1
                    continue

                hashed_password = hash_password(stored_password)

                cursor.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (hashed_password, user_id),
                )
                migrated += 1

        print(f"Password migration completed.")
        print(f"Passwords migrated: {migrated}")
        print(f"Already-hashed passwords skipped: {skipped}")

    except (sqlite3.Error, ValueError) as error:
        print(f"Password migration failed: {error}")
        raise


if __name__ == "__main__":
    migrate()
