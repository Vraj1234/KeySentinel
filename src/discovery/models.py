from dataclasses import dataclass

from src.models.secret import RiskLevel, SecretLocation, SecretType


@dataclass(frozen=True)
class ScanFinding:
    """A potential secret found by a scanner. Never contains plaintext secret material."""

    source: str
    secret_type: SecretType
    location: SecretLocation
    location_detail: str
    matched_value_hash: str
    confidence: float
    context_snippet: str
    rule_id: str
    provider: str
    line_number: int | None = None


@dataclass(frozen=True)
class ClassificationResult:
    """A finding after AI classification."""

    finding: ScanFinding
    classification: str  # "real", "test", "false_positive"
    adjusted_confidence: float
    reasoning: str
    risk_level: RiskLevel


@dataclass(frozen=True)
class ScanReport:
    """Complete output of a discovery scan."""

    findings: tuple[ClassificationResult, ...]
    total_scanned: int
    scan_duration_seconds: float
    scanner_errors: tuple[str, ...]
