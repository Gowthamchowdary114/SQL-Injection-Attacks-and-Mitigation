import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from app import security_controls as security


class SecurityControlTests(unittest.TestCase):

    def setUp(self):
        # Isolate rate-limit state between tests.
        security._attempts.clear()
        security._blocked_until.clear()

        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "security.log"

        self.logger_patcher = patch.object(
            security,
            "LOG_PATH",
            self.log_file,
        )
        self.logger_patcher.start()

        self.handler = security.logging.FileHandler(self.log_file)
        self.handler.setLevel(security.logging.INFO)
        self.handler.setFormatter(
            security.logging.Formatter("%(levelname)s %(message)s")
        )
        security.logger.addHandler(self.handler)

    def tearDown(self):
        security.logger.removeHandler(self.handler)
        self.handler.close()
        self.logger_patcher.stop()
        self.temp_dir.cleanup()

    def test_rate_limit_after_five_failures(self):
        username = "rate_test_user"

        for _ in range(5):
            security.record_login_failure(username)

        self.assertTrue(security.is_rate_limited(username))

    def test_success_clears_failure_history(self):
        username = "success_test_user"

        for _ in range(4):
            security.record_login_failure(username)

        security.record_login_success(username)

        self.assertFalse(security.is_rate_limited(username))
        self.assertEqual(len(security._attempts.get(username, [])), 0)
        self.assertNotIn(username, security._blocked_until)
    def test_failed_login_is_logged(self):
        username = "logging_test_user"

        security.record_login_failure(username)

        for handler in security.logger.handlers:
            handler.flush()

        log_contents = self.log_file.read_text()

        self.assertIn("Login failed", log_contents)
        self.assertIn(username, log_contents)

    def test_successful_login_is_logged(self):
        username = "success_logging_user"

        security.record_login_success(username)

        for handler in security.logger.handlers:
            handler.flush()

        log_contents = self.log_file.read_text()

        self.assertIn("Login succeeded", log_contents)
        self.assertIn(username, log_contents)


if __name__ == "__main__":
    unittest.main(verbosity=2)
