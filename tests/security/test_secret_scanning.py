from __future__ import annotations

from sandbox.safety.secret_scanner import SecretScanner


class TestSecretScanner:
    def setup_method(self):
        self.scanner = SecretScanner()

    def test_clean_text(self):
        has_secrets, matches = self.scanner.scan("Just a normal text string")
        assert not has_secrets

    def test_aws_key_detected(self):
        text = "Use this key: AKIAIOSFODNN7EXAMPLE"
        has_secrets, matches = self.scanner.scan(text)
        assert has_secrets
        assert any(m["type"] == "aws_access_key" for m in matches)

    def test_github_token_detected(self):
        text = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        has_secrets, matches = self.scanner.scan(text)
        assert has_secrets
        assert any("github" in m["type"] for m in matches)

    def test_private_key_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n-----END RSA PRIVATE KEY-----"
        has_secrets, matches = self.scanner.scan(text)
        assert has_secrets
        assert any("private_key" in m["type"] for m in matches)

    def test_connection_string_detected(self):
        text = "DATABASE_URL=postgresql://admin:s3cret@db.example.com:5432/mydb"
        has_secrets, matches = self.scanner.scan(text)
        assert has_secrets

    def test_redaction(self):
        text = "Use key AKIAIOSFODNN7EXAMPLE to access the bucket"
        redacted, count = self.scanner.redact(text)
        assert count > 0
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[REDACTED:" in redacted

    def test_jwt_detected(self):
        text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"  # gitleaks:allow (public jwt.io example token)
        has_secrets, matches = self.scanner.scan(text)
        assert has_secrets
