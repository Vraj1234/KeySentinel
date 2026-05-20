"""Seed data generators for the demo environment."""

from datetime import UTC, datetime, timedelta
from typing import Any


def generate_seed_secrets() -> list[dict[str, Any]]:
    """Create realistic secret entries across different types and risk levels."""
    now = datetime.now(UTC)
    return [
        {
            "id": "secret-aws-prod",
            "name": "AWS Production IAM Key",
            "secret_type": "aws_iam_key",
            "provider": "mock_aws_iam",
            "location": "aws_secrets_manager",
            "location_detail": "arn:aws:secretsmanager:us-east-1:123456:secret/prod-iam",
            "risk_level": "critical",
            "last_rotated_at": (now - timedelta(days=120)).isoformat(),
            "max_age_days": 90,
            "owner_service": "payment-service",
        },
        {
            "id": "secret-db-main",
            "name": "Main Database Password",
            "secret_type": "database_password",
            "provider": "mock_postgresql",
            "location": "vault",
            "location_detail": "vault://prod/database/main",
            "risk_level": "high",
            "last_rotated_at": (now - timedelta(days=60)).isoformat(),
            "max_age_days": 90,
            "owner_service": "api-gateway",
        },
        {
            "id": "secret-api-stripe",
            "name": "Stripe API Key",
            "secret_type": "api_key",
            "provider": "mock_aws_iam",
            "location": "environment_variable",
            "location_detail": "STRIPE_SECRET_KEY in payment-service deployment",
            "risk_level": "high",
            "last_rotated_at": (now - timedelta(days=200)).isoformat(),
            "max_age_days": 90,
            "owner_service": "payment-service",
        },
        {
            "id": "secret-oauth-github",
            "name": "GitHub OAuth Token",
            "secret_type": "oauth_token",
            "provider": "mock_aws_iam",
            "location": "ci_cd_variable",
            "location_detail": "GITHUB_TOKEN in CI pipeline",
            "risk_level": "medium",
            "last_rotated_at": (now - timedelta(days=30)).isoformat(),
            "max_age_days": 90,
            "owner_service": "ci-runner",
        },
        {
            "id": "secret-db-analytics",
            "name": "Analytics DB Readonly",
            "secret_type": "database_password",
            "provider": "mock_postgresql",
            "location": "vault",
            "location_detail": "vault://prod/database/analytics-ro",
            "risk_level": "low",
            "last_rotated_at": (now - timedelta(days=15)).isoformat(),
            "max_age_days": 90,
            "owner_service": "analytics-worker",
        },
        {
            "id": "secret-leaked-key",
            "name": "Leaked API Key (source code)",
            "secret_type": "api_key",
            "provider": "mock_aws_iam",
            "location": "source_code",
            "location_detail": "src/config/settings.py:42",
            "risk_level": "critical",
            "last_rotated_at": None,
            "max_age_days": 90,
            "owner_service": "backend-api",
        },
    ]


def generate_seed_policies() -> list[dict[str, Any]]:
    """Create standard compliance policies for SOC 2 and PCI DSS."""
    return [
        {
            "id": "policy-max-age-90",
            "name": "Maximum Key Age 90 Days",
            "policy_type": "max_age",
            "framework": "soc2",
            "threshold_value": 90,
            "is_enabled": True,
        },
        {
            "id": "policy-no-source",
            "name": "No Secrets in Source Code",
            "policy_type": "no_source_code",
            "framework": "pci_dss",
            "is_enabled": True,
        },
        {
            "id": "policy-approved-store",
            "name": "Approved Secret Stores Only",
            "policy_type": "approved_store_only",
            "framework": "soc2",
            "is_enabled": True,
        },
    ]


def generate_service_declarations() -> list[dict[str, Any]]:
    """Create service dependency declarations for the graph builder."""
    return [
        {
            "service_id": "payment-service",
            "name": "Payment Service",
            "service_type": "api",
            "secrets": ["secret-aws-prod", "secret-api-stripe"],
        },
        {
            "service_id": "api-gateway",
            "name": "API Gateway",
            "service_type": "api",
            "secrets": ["secret-db-main"],
        },
        {
            "service_id": "analytics-worker",
            "name": "Analytics Worker",
            "service_type": "worker",
            "secrets": ["secret-db-analytics"],
        },
        {
            "service_id": "ci-runner",
            "name": "CI Runner",
            "service_type": "cicd",
            "secrets": ["secret-oauth-github"],
        },
        {
            "service_id": "backend-api",
            "name": "Backend API",
            "service_type": "api",
            "secrets": ["secret-leaked-key"],
        },
    ]
