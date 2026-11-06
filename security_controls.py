import logging
import time
from collections import defaultdict, deque
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_PATH = LOG_DIR / "security.log"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("security")

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300
BLOCK_SECONDS = 300

_attempts = defaultdict(deque)
_blocked_until = {}


def _key(username):
    # Do not store passwords in the rate limiter.
    return username.strip().casefold()


def is_rate_limited(username):
    now = time.monotonic()
    key = _key(username)

    blocked_until = _blocked_until.get(key, 0)

    if now < blocked_until:
        logger.warning("Login temporarily blocked for username=%r", key)
        return True

    if blocked_until:
        _blocked_until.pop(key, None)

    attempts = _attempts[key]

    while attempts and now - attempts[0] >= WINDOW_SECONDS:
        attempts.popleft()

    return False


def record_login_failure(username):
    now = time.monotonic()
    key = _key(username)
    attempts = _attempts[key]

    while attempts and now - attempts[0] >= WINDOW_SECONDS:
        attempts.popleft()

    attempts.append(now)
    logger.warning("Login failed for username=%r", key)

    if len(attempts) >= MAX_ATTEMPTS:
        _blocked_until[key] = now + BLOCK_SECONDS
        logger.warning("Rate limit activated for username=%r", key)


def record_login_success(username):
    key = _key(username)
    _attempts.pop(key, None)
    _blocked_until.pop(key, None)
    logger.info("Login succeeded for username=%r", key)


def record_database_error():
    logger.exception("Database error during login")
