"""Pipeline step for compliance assessment."""

import logging
from typing import Any

from src.compliance.engine import ComplianceEngine
from src.models.policy import ComplianceFramework
from src.pipeline.engine import StepResult, StepStatus

logger = logging.getLogger(__name__)


async def compliance_assessment_step(
    context: dict[str, Any],
) -> StepResult:
    """Evaluate all secrets against policies and produce compliance scores.

    Reads:
        context.get("policies") — list of policy dicts.
        context.get("secrets") — list of secret dicts, or
        context["discovery"]["findings"] — classified findings as fallback.
        context.get("anthropic_api_key") — for AI executive summary.

    Returns:
        StepResult with scores, results, and remediation items.
    """
    policies = context.get("policies", [])
    if not policies:
        return StepResult(
            status=StepStatus.COMPLETED,
            output={
                "scores": [],
                "results": [],
                "remediation_items": [],
                "skipped": True,
                "reason": "No policies provided",
            },
        )

    secrets = context.get("secrets", [])
    if not secrets:
        discovery = context.get("discovery", {})
        findings = discovery.get("findings", [])
        secrets = [
            {"id": f.get("rule_id", f"finding-{i}"), **f}
            for i, f in enumerate(findings)
        ]

    if not secrets:
        return StepResult(
            status=StepStatus.COMPLETED,
            output={
                "scores": [],
                "results": [],
                "remediation_items": [],
                "skipped": True,
                "reason": "No secrets to evaluate",
            },
        )

    try:
        engine = ComplianceEngine(policies)
        results = engine.evaluate_all(secrets)

        frameworks = {ComplianceFramework.SOC2, ComplianceFramework.PCI_DSS}
        policy_frameworks = {
            ComplianceFramework(p["framework"])
            for p in policies
            if "framework" in p
        }
        frameworks = frameworks | policy_frameworks

        scores = []
        for fw in frameworks:
            score = engine.calculate_score(results, fw)
            scores.append({
                "framework": score.framework.value,
                "score_percentage": score.score_percentage,
                "compliant_count": score.compliant_count,
                "violation_count": score.violation_count,
                "total_secrets": score.total_secrets,
            })

        remediation = engine.generate_remediation_items(results)

        serialized_results = [
            {
                "secret_id": r.secret_id,
                "is_compliant": r.is_compliant,
                "violation_count": len(r.violations),
            }
            for r in results
        ]

        serialized_remediation = [
            {
                "secret_id": item.secret_id,
                "policy_name": item.violation.policy_name,
                "recommended_action": item.recommended_action,
                "status": item.status,
            }
            for item in remediation
        ]

        return StepResult(
            status=StepStatus.COMPLETED,
            output={
                "scores": scores,
                "results": serialized_results,
                "remediation_items": serialized_remediation,
                "total_evaluated": len(results),
                "total_violations": len(remediation),
            },
        )

    except Exception as e:
        logger.error("Compliance assessment failed: %s", e, exc_info=True)
        return StepResult(status=StepStatus.FAILED, error=str(e))
