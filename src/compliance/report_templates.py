"""Markdown report templates for compliance frameworks."""

from src.compliance.models import ComplianceReport
from src.models.policy import PolicyType


def render_soc2_report(report: ComplianceReport) -> str:
    """Render a SOC 2 compliance report in markdown."""
    lines = [
        "# SOC 2 Compliance Report",
        "",
        f"**Score:** {report.score.score_percentage}%",
        f"**Assessed:** {report.score.assessed_at.isoformat()}",
        f"**Secrets Evaluated:** {report.score.total_secrets}",
        "",
        "---",
        "",
        "## CC6.1 — Logical and Physical Access Controls",
        "",
        _section_for_policy_types(
            report,
            {PolicyType.APPROVED_STORE_ONLY, PolicyType.NO_SOURCE_CODE},
            "All secrets must reside in approved stores, never in source code.",
        ),
        "",
        "## CC6.6 — Encryption and Key Management",
        "",
        _section_for_policy_types(
            report,
            {PolicyType.MAX_AGE, PolicyType.REQUIRED_ROTATION, PolicyType.MIN_KEY_LENGTH},
            "Secrets must be rotated within policy thresholds.",
        ),
        "",
        "## CC7.2 — System Monitoring",
        "",
        _section_for_policy_types(
            report,
            {PolicyType.NO_SHARED_CREDENTIALS},
            "Credentials must be individually assigned for auditability.",
        ),
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "## Remediation Items",
        "",
        _remediation_table(report),
    ]
    return "\n".join(lines)


def render_pci_dss_report(report: ComplianceReport) -> str:
    """Render a PCI DSS compliance report in markdown."""
    lines = [
        "# PCI DSS Compliance Report",
        "",
        f"**Score:** {report.score.score_percentage}%",
        f"**Assessed:** {report.score.assessed_at.isoformat()}",
        f"**Secrets Evaluated:** {report.score.total_secrets}",
        "",
        "---",
        "",
        "## Requirement 3 — Protect Stored Account Data",
        "",
        _section_for_policy_types(
            report,
            {PolicyType.APPROVED_STORE_ONLY, PolicyType.NO_SOURCE_CODE},
            "Sensitive data must not be stored in insecure locations.",
        ),
        "",
        "## Requirement 8 — Identify Users and Authenticate Access",
        "",
        _section_for_policy_types(
            report,
            {
                PolicyType.MAX_AGE,
                PolicyType.REQUIRED_ROTATION,
                PolicyType.NO_SHARED_CREDENTIALS,
            },
            "Credentials must be unique, rotated, and properly managed.",
        ),
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "## Remediation Items",
        "",
        _remediation_table(report),
    ]
    return "\n".join(lines)


def render_generic_report(report: ComplianceReport) -> str:
    """Render a framework-agnostic compliance report."""
    lines = [
        f"# {report.framework.value.upper()} Compliance Report",
        "",
        f"**Score:** {report.score.score_percentage}%",
        f"**Assessed:** {report.score.assessed_at.isoformat()}",
        f"**Compliant:** {report.score.compliant_count}/{report.score.total_secrets}",
        "",
        "---",
        "",
        "## Violations",
        "",
    ]

    violations_found = False
    for result in report.results:
        for v in result.violations:
            violations_found = True
            lines.append(f"- **{result.secret_id}**: {v.reason} ({v.policy_name})")

    if not violations_found:
        lines.append("No violations found.")

    lines.extend([
        "",
        "## Executive Summary",
        "",
        report.executive_summary,
        "",
        "## Remediation Items",
        "",
        _remediation_table(report),
    ])
    return "\n".join(lines)


def _section_for_policy_types(
    report: ComplianceReport,
    policy_types: set[PolicyType],
    description: str,
) -> str:
    """Render violations matching specific policy types."""
    lines = [description, ""]
    found = False
    for result in report.results:
        for v in result.violations:
            if v.policy_type in policy_types:
                found = True
                lines.append(f"- **{result.secret_id}**: {v.reason}")

    if not found:
        lines.append("All checks passed.")
    return "\n".join(lines)


def _remediation_table(report: ComplianceReport) -> str:
    """Render remediation items as a markdown table."""
    if not report.remediation_items:
        return "No remediation items."

    lines = [
        "| Secret | Policy | Action | Status |",
        "|--------|--------|--------|--------|",
    ]
    for item in report.remediation_items:
        lines.append(
            f"| {item.secret_id} "
            f"| {item.violation.policy_name} "
            f"| {item.recommended_action} "
            f"| {item.status} |"
        )
    return "\n".join(lines)
