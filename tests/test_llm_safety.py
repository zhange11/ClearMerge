from __future__ import annotations

import unittest

from backend.clearmerge.llm.safety import sanitize_for_gemini, sanitize_text_for_gemini


class LlmSafetyTests(unittest.TestCase):
    def test_secret_is_redacted_and_hashed(self) -> None:
        secret = "ghp_test_secret_123"
        sanitized = sanitize_text_for_gemini(f"token={secret}")

        self.assertNotIn(secret, sanitized)
        self.assertIn("[REDACTED sha256:", sanitized)
        self.assertEqual(sanitized, sanitize_text_for_gemini(f"token={secret}"))

    def test_json_secret_is_redacted_before_prompt_use(self) -> None:
        payload = {"evidence": '{"Secret": "super-secret-value"}', "nested": ["password: another-secret"]}
        sanitized = sanitize_for_gemini(payload)

        self.assertNotIn("super-secret-value", str(sanitized))
        self.assertNotIn("another-secret", str(sanitized))
        self.assertIn("sha256:", str(sanitized))

    def test_non_secret_prompt_content_is_preserved(self) -> None:
        payload = {"title": "Add dependency checks", "line": 42, "enabled": True}

        self.assertEqual(sanitize_for_gemini(payload), payload)


if __name__ == "__main__":
    unittest.main()