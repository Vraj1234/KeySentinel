from unittest.mock import AsyncMock, patch

import pytest

from src.discovery.classifier import FindingClassifier
from src.discovery.models import ClassificationResult, ScanFinding, ScanReport
from src.discovery.scanner import DiscoveryScanner, _deduplicate, to_secret_model
from src.models.secret import RiskLevel, SecretLocation, SecretType
from src.pipeline.engine import StepStatus


def _make_finding(
    rule_id: str = "test_rule",
    value_hash: str = "abc123",
    location_detail: str = "/test/file.py",
    confidence: float = 0.8,
) -> ScanFinding:
    return ScanFinding(
        source="test",
        secret_type=SecretType.API_KEY,
        location=SecretLocation.SOURCE_CODE,
        location_detail=location_detail,
        matched_value_hash=value_hash,
        confidence=confidence,
        context_snippet="test = ***REDACTED***",
        rule_id=rule_id,
        provider="generic",
    )


def _make_classification(
    finding: ScanFinding | None = None,
    classification: str = "real",
) -> ClassificationResult:
    finding = finding or _make_finding()
    return ClassificationResult(
        finding=finding,
        classification=classification,
        adjusted_confidence=finding.confidence,
        reasoning="test",
        risk_level=RiskLevel.MEDIUM,
    )


class TestDeduplicate:
    def test_removes_exact_duplicates(self) -> None:
        f1 = _make_finding(value_hash="same", location_detail="/same.py")
        f2 = _make_finding(value_hash="same", location_detail="/same.py")
        result = _deduplicate([f1, f2])
        assert len(result) == 1

    def test_keeps_different_locations(self) -> None:
        f1 = _make_finding(value_hash="same", location_detail="/file1.py")
        f2 = _make_finding(value_hash="same", location_detail="/file2.py")
        result = _deduplicate([f1, f2])
        assert len(result) == 2

    def test_keeps_different_hashes(self) -> None:
        f1 = _make_finding(value_hash="hash1", location_detail="/same.py")
        f2 = _make_finding(value_hash="hash2", location_detail="/same.py")
        result = _deduplicate([f1, f2])
        assert len(result) == 2

    def test_empty_list(self) -> None:
        assert _deduplicate([]) == []


class TestToSecretModel:
    def test_converts_classification_to_secret(self) -> None:
        finding = _make_finding(location_detail="/app/config.py")
        result = _make_classification(finding, classification="real")
        secret = to_secret_model(result)

        assert secret.secret_type == SecretType.API_KEY
        assert secret.provider == "generic"
        assert secret.location == SecretLocation.SOURCE_CODE
        assert secret.location_detail == "/app/config.py"
        assert secret.risk_level == RiskLevel.MEDIUM


class TestDiscoveryScannerPipelineStep:
    async def test_returns_completed_step_result(self) -> None:
        mock_report = ScanReport(
            findings=(
                _make_classification(),
            ),
            total_scanned=1,
            scan_duration_seconds=0.5,
            scanner_errors=(),
        )

        scanner = DiscoveryScanner(enable_classification=False)
        with patch.object(scanner, "run", new_callable=AsyncMock, return_value=mock_report):
            result = await scanner.run_as_pipeline_step({})

        assert result.status == StepStatus.COMPLETED
        assert result.output is not None
        assert result.output["findings_count"] == 1
        assert result.output["total_scanned"] == 1
        assert len(result.output["findings"]) == 1

    async def test_returns_failed_on_exception(self) -> None:
        scanner = DiscoveryScanner(enable_classification=False)
        with patch.object(
            scanner, "run", new_callable=AsyncMock, side_effect=RuntimeError("boom")
        ):
            result = await scanner.run_as_pipeline_step({})

        assert result.status == StepStatus.FAILED
        assert "boom" in (result.error or "")

    async def test_step_output_has_expected_shape(self) -> None:
        finding = _make_finding()
        classification = _make_classification(finding)
        mock_report = ScanReport(
            findings=(classification,),
            total_scanned=2,
            scan_duration_seconds=1.0,
            scanner_errors=("one error",),
        )

        scanner = DiscoveryScanner(enable_classification=False)
        with patch.object(scanner, "run", new_callable=AsyncMock, return_value=mock_report):
            result = await scanner.run_as_pipeline_step({})

        output = result.output
        assert output is not None
        assert "findings" in output
        assert "findings_count" in output
        assert "total_scanned" in output
        assert "scan_duration_seconds" in output
        assert "errors" in output
        assert output["errors"] == ["one error"]

        # Verify individual finding shape
        f = output["findings"][0]
        assert "classification" in f
        assert "confidence" in f
        assert "risk_level" in f
        assert "secret_type" in f
        assert "location" in f
        assert "location_detail" in f
        assert "provider" in f
        assert "rule_id" in f


class TestClassifierFailsafe:
    async def test_failsafe_on_api_error(self) -> None:
        classifier = FindingClassifier(api_key="fake-key")
        finding = _make_finding(confidence=0.9)

        with patch.object(
            classifier._client.messages,
            "create",
            new_callable=AsyncMock,
            side_effect=Exception("API down"),
        ):
            results = await classifier.classify([finding])

        assert len(results) == 1
        assert results[0].classification == "real"
        assert results[0].adjusted_confidence == 0.9
        assert "fail-safe" in results[0].reasoning
