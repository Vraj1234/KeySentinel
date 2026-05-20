import math
import re
from collections import Counter
from dataclasses import dataclass

from src.models.secret import SecretType


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    secret_type: SecretType
    provider: str
    confidence: float


@dataclass(frozen=True)
class RawMatch:
    pattern: SecretPattern
    matched_text: str
    line_number: int
    start: int
    end: int


# --- Built-in pattern registry ---

PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        rule_id="aws_access_key",
        name="AWS Access Key ID",
        pattern=re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        secret_type=SecretType.AWS_IAM_KEY,
        provider="aws",
        confidence=0.95,
    ),
    SecretPattern(
        rule_id="aws_secret_key",
        name="AWS Secret Access Key",
        pattern=re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
        secret_type=SecretType.AWS_IAM_KEY,
        provider="aws",
        confidence=0.5,  # low base — needs entropy boost
    ),
    SecretPattern(
        rule_id="gcp_api_key",
        name="GCP API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        secret_type=SecretType.GCP_SERVICE_ACCOUNT,
        provider="gcp",
        confidence=0.9,
    ),
    SecretPattern(
        rule_id="azure_client_secret",
        name="Azure Client Secret",
        pattern=re.compile(r"(?<![A-Za-z0-9~.])([A-Za-z0-9~.]{34,})(?![A-Za-z0-9~.])"),
        secret_type=SecretType.AZURE_AD_CREDENTIAL,
        provider="azure",
        confidence=0.3,  # very low base — needs context + entropy
    ),
    SecretPattern(
        rule_id="private_key",
        name="Private Key",
        pattern=re.compile(r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----"),
        secret_type=SecretType.SSH_KEY,
        provider="generic",
        confidence=0.99,
    ),
    SecretPattern(
        rule_id="postgres_uri",
        name="PostgreSQL Connection String",
        pattern=re.compile(r"postgres(?:ql)?://[^\s'\"]{10,}"),
        secret_type=SecretType.DATABASE_PASSWORD,
        provider="postgresql",
        confidence=0.85,
    ),
    SecretPattern(
        rule_id="mysql_uri",
        name="MySQL Connection String",
        pattern=re.compile(r"mysql://[^\s'\"]{10,}"),
        secret_type=SecretType.DATABASE_PASSWORD,
        provider="mysql",
        confidence=0.85,
    ),
    SecretPattern(
        rule_id="mongodb_uri",
        name="MongoDB Connection String",
        pattern=re.compile(r"mongodb(?:\+srv)?://[^\s'\"]{10,}"),
        secret_type=SecretType.DATABASE_PASSWORD,
        provider="mongodb",
        confidence=0.85,
    ),
    SecretPattern(
        rule_id="generic_api_key",
        name="Generic API Key Assignment",
        pattern=re.compile(
            r"""(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key)"""
            r"""[\s]*[=:]\s*['\"]([A-Za-z0-9\-_./+=]{16,})['\"]""",
            re.IGNORECASE,
        ),
        secret_type=SecretType.API_KEY,
        provider="generic",
        confidence=0.7,
    ),
    SecretPattern(
        rule_id="generic_password",
        name="Generic Password Assignment",
        pattern=re.compile(
            r"""(?:password|passwd|pwd)[\s]*[=:]\s*['\"]([^\s'\"]{8,})['\"]""",
            re.IGNORECASE,
        ),
        secret_type=SecretType.DATABASE_PASSWORD,
        provider="generic",
        confidence=0.6,
    ),
)


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def is_high_entropy(value: str, threshold: float = 4.5) -> bool:
    """Check if a string has suspiciously high entropy suggesting randomness."""
    if len(value) < 8:
        return False
    return shannon_entropy(value) >= threshold


def scan_text(
    content: str, patterns: list[SecretPattern] | None = None
) -> list[RawMatch]:
    """Run all patterns against text content. Returns raw matches with line numbers."""
    if patterns is None:
        patterns = list(PATTERNS)

    lines = content.split("\n")
    matches: list[RawMatch] = []
    offset = 0

    for line_idx, line in enumerate(lines, start=1):
        for pattern in patterns:
            for m in pattern.pattern.finditer(line):
                matches.append(
                    RawMatch(
                        pattern=pattern,
                        matched_text=m.group(0),
                        line_number=line_idx,
                        start=offset + m.start(),
                        end=offset + m.end(),
                    )
                )
        offset += len(line) + 1  # +1 for newline

    return matches


def redact_context(
    content: str, match_start: int, match_end: int, context_lines: int = 2
) -> str:
    """Extract surrounding lines with the matched secret replaced by ***REDACTED***."""
    lines = content.split("\n")
    redacted_content = content[:match_start] + "***REDACTED***" + content[match_end:]
    redacted_lines = redacted_content.split("\n")

    # Find which line the match is on
    char_count = 0
    match_line = 0
    for i, line in enumerate(lines):
        char_count += len(line) + 1
        if char_count > match_start:
            match_line = i
            break

    start_line = max(0, match_line - context_lines)
    end_line = min(len(redacted_lines), match_line + context_lines + 1)

    return "\n".join(redacted_lines[start_line:end_line])
