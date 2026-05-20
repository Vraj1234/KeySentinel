from datetime import UTC, datetime, timedelta

import pytest

from src.models.policy import ComplianceFramework, PolicyType
from src.models.secret import RiskLevel, SecretLocation
from src.pipeline.engine import StepStatus
from src.risk.engine import RiskEngine
from src.risk.models import RiskSignal
from src.risk.pipeline_step import risk_assessment_step
from src.risk.policy import PolicyEvaluator
from src.risk.rules import (
    age_check,
    blast_radius_check,
    compliance_check,
    exposure_check,
    privilege_audit,
)


def _base_context(**overrides: object) -> dict:
    ctx: dict = {
        "secret_id": "test-secret",
        "name": "test-key",
        "provider": "generic",
        "location": "vault",
        "secret_type": "api_key",
    }
    ctx.update(overrides)
    return ctx


class TestAgeCheck:
    async def test_never_rotated(self) -> None:
        ctx = _base_context()
        signal = await age_check(ctx)
        assert signal is not None
        assert signal.rule_id == "age_check"
        assert signal.severity == RiskLevel.HIGH
        assert signal.score_delta == 25.0

    async def test_severely_overdue(self) -> None:
        old = datetime.now(UTC) - timedelta(days=200)
        ctx = _base_context(last_rotated_at=old, max_age_days=90)
        signal = await age_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.CRITICAL
        assert signal.score_delta == 30.0

    async def test_overdue(self) -> None:
        old = datetime.now(UTC) - timedelta(days=100)
        ctx = _base_context(last_rotated_at=old, max_age_days=90)
        signal = await age_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.HIGH

    async def test_approaching_max_age(self) -> None:
        old = datetime.now(UTC) - timedelta(days=75)
        ctx = _base_context(last_rotated_at=old, max_age_days=90)
        signal = await age_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.MEDIUM

    async def test_within_limit(self) -> None:
        recent = datetime.now(UTC) - timedelta(days=10)
        ctx = _base_context(last_rotated_at=recent, max_age_days=90)
        signal = await age_check(ctx)
        assert signal is None

    async def test_isoformat_string_date(self) -> None:
        old = (datetime.now(UTC) - timedelta(days=200)).isoformat()
        ctx = _base_context(last_rotated_at=old, max_age_days=90)
        signal = await age_check(ctx)
        assert signal is not None


class TestPrivilegeAudit:
    async def test_admin_permission(self) -> None:
        ctx = _base_context(permissions=["AdministratorAccess"])
        signal = await privilege_audit(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.HIGH
        assert signal.score_delta == 25.0

    async def test_wildcard_permission(self) -> None:
        ctx = _base_context(permissions=["s3:*"])
        signal = await privilege_audit(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.MEDIUM

    async def test_admin_name(self) -> None:
        ctx = _base_context(name="root-db-password")
        signal = await privilege_audit(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.MEDIUM

    async def test_limited_permissions(self) -> None:
        ctx = _base_context(permissions=["s3:GetObject"])
        signal = await privilege_audit(ctx)
        assert signal is None

    async def test_no_permissions(self) -> None:
        ctx = _base_context()
        signal = await privilege_audit(ctx)
        assert signal is None


class TestExposureCheck:
    async def test_source_code(self) -> None:
        ctx = _base_context(location=SecretLocation.SOURCE_CODE.value)
        signal = await exposure_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.CRITICAL
        assert signal.score_delta == 35.0

    async def test_config_file(self) -> None:
        ctx = _base_context(location=SecretLocation.CONFIG_FILE.value)
        signal = await exposure_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.HIGH

    async def test_environment_variable(self) -> None:
        ctx = _base_context(location=SecretLocation.ENVIRONMENT_VARIABLE.value)
        signal = await exposure_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.MEDIUM

    async def test_vault_no_signal(self) -> None:
        ctx = _base_context(location=SecretLocation.VAULT.value)
        signal = await exposure_check(ctx)
        assert signal is None


class TestBlastRadiusCheck:
    async def test_high_blast_radius(self) -> None:
        ctx = _base_context(blast_radius_affected_count=12)
        signal = await blast_radius_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.HIGH
        assert signal.score_delta == 20.0

    async def test_moderate_blast_radius(self) -> None:
        ctx = _base_context(blast_radius_affected_count=6)
        signal = await blast_radius_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.MEDIUM

    async def test_low_blast_radius(self) -> None:
        ctx = _base_context(blast_radius_affected_count=2)
        signal = await blast_radius_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.LOW

    async def test_zero_no_signal(self) -> None:
        ctx = _base_context(blast_radius_affected_count=0)
        signal = await blast_radius_check(ctx)
        assert signal is None

    async def test_no_graph_data(self) -> None:
        ctx = _base_context()
        signal = await blast_radius_check(ctx)
        assert signal is None


class TestComplianceCheck:
    async def test_policy_violation(self) -> None:
        ctx = _base_context(
            policy_violations=[
                {"reason": "Key too old", "framework": "soc2", "policy_type": "max_age"},
            ],
        )
        signal = await compliance_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.HIGH
        assert signal.score_delta == 20.0

    async def test_internal_violation(self) -> None:
        ctx = _base_context(
            policy_violations=[
                {"reason": "Not rotated", "framework": "internal", "policy_type": "max_age"},
            ],
        )
        signal = await compliance_check(ctx)
        assert signal is not None
        assert signal.severity == RiskLevel.MEDIUM

    async def test_no_violations(self) -> None:
        ctx = _base_context()
        signal = await compliance_check(ctx)
        assert signal is None


class TestRiskEngine:
    async def test_aggregation(self) -> None:
        engine = RiskEngine()
        # Source code + never rotated = high score
        ctx = _base_context(
            location=SecretLocation.SOURCE_CODE.value,
        )
        assessment = await engine.assess(ctx)
        assert assessment.risk_score > 0
        assert assessment.risk_level in (
            RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM,
        )

    async def test_low_risk_secret(self) -> None:
        engine = RiskEngine()
        recent = datetime.now(UTC) - timedelta(days=5)
        ctx = _base_context(
            location=SecretLocation.VAULT.value,
            last_rotated_at=recent,
            max_age_days=90,
        )
        assessment = await engine.assess(ctx)
        assert assessment.risk_score < 30
        assert assessment.risk_level in (RiskLevel.LOW, RiskLevel.INFO)

    async def test_custom_rule(self) -> None:
        async def always_flag(ctx: dict) -> RiskSignal | None:
            return RiskSignal(
                rule_id="custom",
                severity=RiskLevel.MEDIUM,
                score_delta=50.0,
                reason="Custom rule triggered",
            )

        engine = RiskEngine(rules=[always_flag])
        assessment = await engine.assess(_base_context())
        assert assessment.risk_score == 50.0
        assert len(assessment.signals) == 1

    async def test_no_signals_gives_info(self) -> None:
        async def noop(ctx: dict) -> RiskSignal | None:
            return None

        engine = RiskEngine(rules=[noop])
        assessment = await engine.assess(_base_context())
        assert assessment.risk_score == 0.0
        assert assessment.risk_level == RiskLevel.INFO

    async def test_score_clamped_to_100(self) -> None:
        async def max_rule(ctx: dict) -> RiskSignal | None:
            return RiskSignal(
                rule_id="max", severity=RiskLevel.CRITICAL,
                score_delta=200.0, reason="Extreme",
            )

        engine = RiskEngine(rules=[max_rule])
        assessment = await engine.assess(_base_context())
        assert assessment.risk_score == 100.0
        assert assessment.risk_level == RiskLevel.CRITICAL

    async def test_batch_assessment(self) -> None:
        engine = RiskEngine(rules=[])
        assessments = await engine.assess_batch([
            _base_context(secret_id="s1"),
            _base_context(secret_id="s2"),
        ])
        assert len(assessments) == 2


class TestPolicyEvaluator:
    def test_max_age_violation(self) -> None:
        policies = [{
            "id": "p1", "name": "90-day rotation",
            "policy_type": "max_age", "framework": "soc2",
            "threshold_value": 90, "is_enabled": True,
        }]
        evaluator = PolicyEvaluator(policies)
        ctx = _base_context(
            last_rotated_at=datetime.now(UTC) - timedelta(days=100),
        )
        violations = evaluator.evaluate(ctx)
        assert len(violations) == 1
        assert violations[0].policy_type == PolicyType.MAX_AGE

    def test_max_age_within_limit(self) -> None:
        policies = [{
            "id": "p1", "name": "90-day rotation",
            "policy_type": "max_age", "framework": "soc2",
            "threshold_value": 90, "is_enabled": True,
        }]
        evaluator = PolicyEvaluator(policies)
        ctx = _base_context(
            last_rotated_at=datetime.now(UTC) - timedelta(days=10),
        )
        violations = evaluator.evaluate(ctx)
        assert len(violations) == 0

    def test_no_source_code_violation(self) -> None:
        policies = [{
            "id": "p2", "name": "No secrets in code",
            "policy_type": "no_source_code", "framework": "internal",
            "is_enabled": True,
        }]
        evaluator = PolicyEvaluator(policies)
        ctx = _base_context(location=SecretLocation.SOURCE_CODE.value)
        violations = evaluator.evaluate(ctx)
        assert len(violations) == 1

    def test_approved_store_violation(self) -> None:
        policies = [{
            "id": "p3", "name": "Vault only",
            "policy_type": "approved_store_only", "framework": "pci_dss",
            "is_enabled": True,
        }]
        evaluator = PolicyEvaluator(policies)
        ctx = _base_context(location=SecretLocation.CONFIG_FILE.value)
        violations = evaluator.evaluate(ctx)
        assert len(violations) == 1

    def test_approved_store_passes(self) -> None:
        policies = [{
            "id": "p3", "name": "Vault only",
            "policy_type": "approved_store_only", "framework": "pci_dss",
            "is_enabled": True,
        }]
        evaluator = PolicyEvaluator(policies)
        ctx = _base_context(location=SecretLocation.VAULT.value)
        violations = evaluator.evaluate(ctx)
        assert len(violations) == 0

    def test_disabled_policy_skipped(self) -> None:
        policies = [{
            "id": "p1", "name": "Disabled",
            "policy_type": "max_age", "framework": "internal",
            "threshold_value": 1, "is_enabled": False,
        }]
        evaluator = PolicyEvaluator(policies)
        ctx = _base_context()
        violations = evaluator.evaluate(ctx)
        assert len(violations) == 0


class TestRiskPipelineStep:
    async def test_happy_path(self) -> None:
        context = {
            "discovery": {
                "findings": [
                    {
                        "secret_type": "api_key",
                        "location": "source_code",
                        "location_detail": "app/.env",
                        "provider": "generic",
                        "rule_id": "generic_api_key",
                    },
                ],
            },
        }
        result = await risk_assessment_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output is not None
        assert result.output["summary"]["total_assessed"] == 1

    async def test_missing_discovery_fails(self) -> None:
        result = await risk_assessment_step({})
        assert result.status == StepStatus.FAILED

    async def test_empty_findings(self) -> None:
        context = {"discovery": {"findings": []}}
        result = await risk_assessment_step(context)
        assert result.status == StepStatus.COMPLETED
        assert result.output["summary"]["total_assessed"] == 0
