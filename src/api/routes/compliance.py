"""Compliance report and remediation endpoints."""

from typing import Any

from fastapi import APIRouter

from src.compliance.engine import ComplianceEngine
from src.models.policy import ComplianceFramework

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])

# In-memory store for latest compliance results. In a full deployment
# these would be persisted to the database.
_latest_results: dict[str, Any] = {}


@router.post("/assess")
async def trigger_compliance_assessment(
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Trigger compliance assessment across all provided secrets.

    Accepts {"policies": [...], "secrets": [...]} in the body.
    """
    body = body or {}
    policies = body.get("policies", [])
    secrets = body.get("secrets", [])

    if not policies:
        return {
            "status": "skipped",
            "reason": "No policies provided",
            "scores": [],
        }

    if not secrets:
        return {
            "status": "skipped",
            "reason": "No secrets provided",
            "scores": [],
        }

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

    # Cache latest results
    _latest_results["scores"] = scores
    _latest_results["remediation"] = [
        {
            "secret_id": item.secret_id,
            "policy_name": item.violation.policy_name,
            "recommended_action": item.recommended_action,
            "status": item.status,
        }
        for item in remediation
    ]

    return {
        "status": "completed",
        "scores": scores,
        "total_evaluated": len(results),
        "total_violations": len(remediation),
    }


@router.get("/score")
async def get_compliance_scores() -> dict[str, Any]:
    """Get current compliance scores per framework."""
    scores = _latest_results.get("scores", [])
    return {"scores": scores}


@router.get("/reports/{framework}")
async def get_compliance_report(framework: str) -> dict[str, Any]:
    """Get latest report for a specific framework."""
    scores = _latest_results.get("scores", [])
    match = next(
        (s for s in scores if s["framework"] == framework),
        None,
    )
    if match is None:
        return {
            "framework": framework,
            "status": "not_available",
            "message": "Run /assess first",
        }
    return {"framework": framework, "score": match}


@router.get("/remediation")
async def list_remediation_items() -> dict[str, Any]:
    """List open remediation items."""
    items = _latest_results.get("remediation", [])
    return {"items": items, "total": len(items)}
