import pytest

from src.discovery.patterns import (
    PATTERNS,
    is_high_entropy,
    redact_context,
    scan_text,
    shannon_entropy,
)


class TestShannonEntropy:
    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_character(self) -> None:
        assert shannon_entropy("aaaa") == 0.0

    def test_uniform_distribution(self) -> None:
        # "ab" repeated — 2 unique chars, each 50% = 1.0 bit
        result = shannon_entropy("abababab")
        assert abs(result - 1.0) < 0.01

    def test_high_entropy_random(self) -> None:
        # Base64-like random string should have high entropy
        value = "aB3kL9mNpQ2rStUvWxYz1234567890+/"
        assert shannon_entropy(value) > 4.5

    def test_low_entropy_english(self) -> None:
        value = "the quick brown fox jumps over the lazy dog"
        assert shannon_entropy(value) < 4.5

    def test_hex_string(self) -> None:
        # 16 unique hex chars, uniformly distributed
        value = "0123456789abcdef" * 4
        assert shannon_entropy(value) == 4.0


class TestIsHighEntropy:
    def test_short_strings_rejected(self) -> None:
        assert is_high_entropy("abc") is False

    def test_low_entropy_rejected(self) -> None:
        assert is_high_entropy("password") is False

    def test_high_entropy_accepted(self) -> None:
        assert is_high_entropy("aB3kL9mNpQ2rStUvWxYz1234567890+/") is True

    def test_custom_threshold(self) -> None:
        value = "0123456789abcdef" * 2
        assert is_high_entropy(value, threshold=3.5) is True
        assert is_high_entropy(value, threshold=4.5) is False


class TestScanText:
    def test_detects_aws_access_key(self) -> None:
        content = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        matches = scan_text(content)
        aws_matches = [m for m in matches if m.pattern.rule_id == "aws_access_key"]
        assert len(aws_matches) == 1
        assert "AKIAIOSFODNN7EXAMPLE" in aws_matches[0].matched_text

    def test_detects_private_key(self) -> None:
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."
        matches = scan_text(content)
        pk_matches = [m for m in matches if m.pattern.rule_id == "private_key"]
        assert len(pk_matches) == 1

    def test_detects_postgres_uri(self) -> None:
        content = 'DATABASE_URL = "postgres://user:pass@host:5432/db"'
        matches = scan_text(content)
        db_matches = [m for m in matches if m.pattern.rule_id == "postgres_uri"]
        assert len(db_matches) == 1

    def test_detects_mongodb_uri(self) -> None:
        content = 'MONGO_URL = "mongodb+srv://user:pass@cluster.example.com/db"'
        matches = scan_text(content)
        db_matches = [m for m in matches if m.pattern.rule_id == "mongodb_uri"]
        assert len(db_matches) == 1

    def test_no_false_positive_on_clean_code(self) -> None:
        content = """
def hello():
    print("Hello, world!")
    x = 42
    return x
"""
        matches = scan_text(content)
        assert len(matches) == 0

    def test_line_numbers_correct(self) -> None:
        content = "line1\nline2\nAKIAIOSFODNN7EXAMPLE\nline4"
        matches = scan_text(content)
        aws_matches = [m for m in matches if m.pattern.rule_id == "aws_access_key"]
        assert len(aws_matches) == 1
        assert aws_matches[0].line_number == 3

    def test_generic_password_detection(self) -> None:
        content = """password = "SuperSecret123!@#" """
        matches = scan_text(content)
        pwd_matches = [m for m in matches if m.pattern.rule_id == "generic_password"]
        assert len(pwd_matches) == 1


class TestRedactContext:
    def test_redacts_secret(self) -> None:
        content = "line1\nline2\nsecret=AKIAIOSFODNN7EXAMPLE\nline4\nline5"
        # Match position of AKIAIOSFODNN7EXAMPLE
        start = content.index("AKIAIOSFODNN7EXAMPLE")
        end = start + len("AKIAIOSFODNN7EXAMPLE")
        result = redact_context(content, start, end)
        assert "***REDACTED***" in result
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_preserves_surrounding_lines(self) -> None:
        content = "line1\nline2\nsecret=MYSECRET\nline4\nline5"
        start = content.index("MYSECRET")
        end = start + len("MYSECRET")
        result = redact_context(content, start, end, context_lines=1)
        assert "line2" in result
        assert "line4" in result
