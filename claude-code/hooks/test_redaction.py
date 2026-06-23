import subprocess
import unittest

from unbound import redact_secrets


class TestRedactSecrets(unittest.TestCase):
    def test_ticket_vector_timeout_expired_bearer(self):
        key = "sk-ant-fakekey1234567890"
        exc = subprocess.TimeoutExpired(
            cmd=["curl", "-H", f"Authorization: Bearer {key}", "https://gw"],
            timeout=20,
        )
        out = redact_secrets(str(exc))
        self.assertNotIn(key, out)
        self.assertIn("Bearer [REDACTED]", out)

    def test_bare_literal_key_scrubbed(self):
        key = "sk-ant-fakekey1234567890"
        out = redact_secrets(f"connect failed with {key} oops", key=key)
        self.assertNotIn(key, out)
        self.assertIn("[REDACTED]", out)

    def test_empty_key_does_not_wipe_message(self):
        self.assertEqual(redact_secrets("hello world", key=""), "hello world")
        self.assertEqual(redact_secrets("hello world", key=None), "hello world")

    def test_bare_literal_not_scrubbed_without_key(self):
        key = "sk-ant-fakekey1234567890"
        out = redact_secrets(f"connect failed with {key} oops")
        self.assertIn(key, out)

    def test_case_insensitive_bearer(self):
        out = redact_secrets("auth: bearer sk-ant-fakekey1234567890")
        self.assertNotIn("sk-ant-fakekey1234567890", out)
        self.assertIn("Bearer [REDACTED]", out)


if __name__ == "__main__":
    unittest.main()
