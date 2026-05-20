"""Tests for compliance engine, report templates, and pipeline step."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from src.compliance.engine import ComplianceEngine
from src.compliance.models import ComplianceReport, ComplianceResult, ComplianceScore
from src.compliance.pipeline_step import compliance_assessment_step
from src.compliance.report_templates import (
    render_generic_report,
    render_pci_dss_report,
    render_soc2_report,
)
from src.compliance.summary_generator import ComplianceSummaryGenerator
from src.models.policy import ComplianceFramework, PolicyType
from src.pipeline.engine import StepStatus
from src.risk.models import PolicyViolation


def _make_policies() -> list[dict]:
    return [
        {
            "id": "p1",
            "name": "Max Age 90 Days",
            "policy_type": PolicyType.MAX_AGE.value,
            "framework": ComplianceFramework.SOC2.value,
            "threshold_value": 90,
            "is_enabled": True,
        },
        {
            "id": "p2",
            "name": "No Source Code Secrets",
            "policy_type": PolicyType.NO_SOURCE_CODE.value,
            "framework": ComplianceFramework.PCI_DSS.value,
            "is_enabled": True,
        },
    ]


def _make_secrets() -> list[dict]:
    return [
        {
            "id": "s1",
            "name": "prod-db-password",
            "location": "source_code",
            "last_rotated_at": "2024-01-01T00:00:00+00:00",
        },
        {
            "id": "s2",
            "name": "api-key-staging",
            "location": "vault",
            "last_rotated_at": datetime.now(UTC).isoformat(),
        },
        {
            "id": "s3",
            "name": "fresh-key",
            "location": "aws_secrets_manager",
            "last_rotated_at": datetime.now(UTC).isoformat(),
        },
    ]


class TestComplianceEngine:
    def test_evaluate_all_finds_violations(self) -> None:
        engine = ComplianceEngine(_make_policies())
        results = engine.evaluate_all(_make_secrets())

        assert len(results) == 3
        # s1 has source_code location AND is old → 2 violations
        s1 = next(r for r in results if r.secret_id == "s1")
        assert not s1.is_compliant
        assert len(s1.violations) == 2

        # s2 is in vault and fresh → compliant
        s2 = next(r for r in results if r.secret_id == "s2")
        assert s2.is_compliant

    def test_evaluate_all_with_no_secrets(self) -> None:
        engine = ComplianceEngine(_make_policies())
        results = engine.evaluate_all([])
        assert results == []

    def test_calculate_score_soc2(self) -> None:
        engine = ComplianceEngine(_make_policies())
        results = engine.evaluate_all(_make_secrets())
        score = engine.calculate_score(results, ComplianceFramework.SOC2)

        assert score.framework == ComplianceFramework.SOC2
        assert score.total_secrets == 3
        # s1 violates MAX_AGE (SOC2), s2 and s3 are compliant for SOC2
        assert score.compliant_count == 2
        assert score.violation_count == 1
        assert score.score_percentage == round(2 / 3 * 100, 1)

    def test_calculate_score_pci_dss(self) -> None:
        engine = ComplianceEngine(_make_policies())
        results = engine.evaluate_all(_make_secrets())
        score = engine.calculate_score(results, ComplianceFramework.PCI_DSS)

        # s1 in source_code violates NO_SOURCE_CODE (PCI DSS)
        assert score.violation_count == 1
        assert score.compliant_count == 2

    def test_calculate_score_empty(self) -> None:
        engine = ComplianceEngine(_make_policies())
        score = engine.calculate_score([], ComplianceFramework.SOC2)
        assert score.score_percentage == 100.0
        assert score.total_secrets == 0

    def test_generate_remediation_items(self) -> None:
        engine = ComplianceEngine(_make_policies())
        results = engine.evaluate_all(_make_secrets())
        items = engine.generate_remediation_items(results)

        # s1 has 2 violations → 2 remediation items
        assert len(items) == 2
        assert all(item.status == "open" for item in items)

        actions = {item.recommended_action for item in items}
        assert "Rotate secret immediately" in actions
        assert "Move secret to an approved vault" in actions


class TestReportTemplates:
    def _make_report(
        self,
        framework: ComplianceFramework,
    ) -> ComplianceReport:
        violation = PolicyViolation(
            policy_id="p1",
            policy_name="Max Age 90 Days",
            policy_type=PolicyType.MAX_AGE,
            framework=framework,
            reason="Secret is 200 days old (max: 90)",
            threshold_value=90,
            actual_value=200,
        )
        now = datetime.now(UTC)
        result = ComplianceResult(
            secret_id="s1",
            violations=(violation,),
            is_compliant=False,
        )
        from src.compliance.models import RemediationItem

        remediation = RemediationItem(
            violation=violation,
            secret_id="s1",
            status="open",
            recommended_action="Rotate secret immediately",
            created_at=now,
        )
        score = ComplianceScore(
            framework=framework,
            total_secrets=3,
            compliant_count=2,
            violation_count=1,
            score_percentage=66.7,
            assessed_at=now,
        )
        return ComplianceReport(
            framework=framework,
            score=score,
            results=(result,),
            remediation_items=(remediation,),
            executive_summary="Overall compliance posture is acceptable.",
            generated_at=now,
        )

    def test_soc2_report_has_sections(self) -> None:
        report = self._make_report(ComplianceFramework.SOC2)
        md = render_soc2_report(report)
        assert "SOC 2 Compliance Report" in md
        assert "CC6.1" in md
        assert "CC6.6" in md
        assert "CC7.2" in md
        assert "66.7%" in md
        assert "Executive Summary" in md
        assert "Remediation Items" in md

    def test_pci_dss_report_has_sections(self) -> None:
        report = self._make_report(ComplianceFramework.PCI_DSS)
        md = render_pci_dss_report(report)
        assert "PCI DSS Compliance Report" in md
        assert "Requirement 3" in md
        assert "Requirement 8" in md

    def test_generic_report(self) -> None:
        report = self._make_report(ComplianceFramework.INTERNAL)
        md = render_generic_report(report)
        assert "INTERNAL Compliance Report" in md
        assert "s1" in md
        assert "200 days old" in md

    def test_generic_report_no_violations(self) -> None:
        now = datetime.now(UTC)
        report = ComplianceReport(
            framework=ComplianceFramework.INTERNAL,
            score=ComplianceScore(
                framework=ComplianceFramework.INTERNAL,
                total_secrets=1,
                compliant_count=1,
                violation_count=0,
                score_percentage=100.0,
                assessed_at=now,
            ),
            results=(
                ComplianceResult(
                    secret_id="s1",
                    violations=(),
                    is_compliant=True,
                ),
            ),
            remediation_items=(),
            executive_summary="Full compliance.",
            generated_at=now,
        )
        md = render_generic_report(report)
        assert "No violations found" in md
        assert "No remediation items" in md


class TestComplianceSummaryGenerator:
    async def test_generates_summary_via_api(self) -> None:
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Compliance is strong.")]

        with patch("src.compliance.summary_generator.anthropic") as mock_mod:
            mock_client = AsyncMock()
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            mock_mod.AsyncAnthropic.return_value = mock_client

            gen = ComplianceSummaryGenerator(api_key="test-key")
            gen._client = mock_client

            summary = await gen.generate_summary({"score": {"score_percentage": 85}})

            assert "strong" in summary.lower()
            mock_client.messages.create.assert_called_once()

    async def test_fallback_on_failure(self) -> None:
        with patch("src.compliance.summary_generator.anthropic") as mock_mod:
            mock_client = AsyncMock()
            mock_client.messages.create = AsyncMock(side_effect=Exception("fail"))
            mock_mod.AsyncAnthropic.return_value = mock_client

            gen = ComplianceSummaryGenerator(api_key="test-key")
            gen._client = mock_client

            summary = await gen.generate_summary({
                "score": {
                    "score_percentage": 75,
                    "total_secrets": 10,
                    "violation_count": 3,
                },
            })

            assert "75%" in summary
            assert "10" in summary

    def test_fallback_summary_content(self) -> None:
        summary = ComplianceSummaryGenerator._fallback_summary({
            "score": {
                "score_percentage": 80.0,
                "total_secrets": 5,
                "violation_count": 1,
            },
        })
        assert "80.0%" in summary
        assert "5 secrets" in summary
        assert "1 violation" in summary


class TestCompliancePipelineStep:
    async def test_evaluates_with_policies_and_secrets(self) -> None:
        context = {
            "policies": _make_policies(),
            "secrets": _make_secrets(),
        }
        result = await compliance_assessment_step(context)

        assert result.status == StepStatus.COMPLETED
        assert result.output["total_evaluated"] == 3
        assert result.output["total_violations"] == 2
        assert len(result.output["scores"]) >= 2
        assert len(result.output["remediation_items"]) == 2

    async def test_skips_without_policies(self) -> None:
        result = await compliance_assessment_step({"secrets": _make_secrets()})
        assert result.status == StepStatus.COMPLETED
        assert result.output["skipped"] is True

    async def test_skips_without_secrets(self) -> None:
        result = await compliance_assessment_step({
            "policies": _make_policies(),
        })
        assert result.status == StepStatus.COMPLETED
        assert result.output["skipped"] is True

    async def test_uses_discovery_findings_as_fallback(self) -> None:
        context = {
            "policies": _make_policies(),
            "discovery": {
                "findings": [
                    {
                        "rule_id": "test-finding",
                        "location": "source_code",
                        "last_rotated_at": "2024-01-01T00:00:00+00:00",
                    }
                ],
            },
        }
        result = await compliance_assessment_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output["total_evaluated"] == 1
