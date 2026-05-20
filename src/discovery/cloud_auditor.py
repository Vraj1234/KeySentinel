import asyncio
import hashlib
import logging
from datetime import UTC, datetime
from functools import partial
from typing import Any

import httpx

from src.discovery.models import ScanFinding
from src.models.secret import SecretLocation, SecretType

logger = logging.getLogger(__name__)


class CloudAuditor:
    """Enumerates existing keys and credentials from cloud providers."""

    def __init__(self, region: str = "us-east-1") -> None:
        self._region = region

    async def audit_all(self, providers: list[str] | None = None) -> list[ScanFinding]:
        """Run all configured cloud audits concurrently."""
        providers = providers or ["aws"]
        tasks = []

        if "aws" in providers:
            tasks.append(self.audit_aws())
        if "gcp" in providers:
            tasks.append(self.audit_gcp())
        if "azure" in providers:
            tasks.append(self.audit_azure())

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[ScanFinding] = []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("Cloud audit failed for provider: %s", result, exc_info=True)
            else:
                findings.extend(result)

        return findings

    async def audit_aws(self) -> list[ScanFinding]:
        """Enumerate AWS IAM access keys, their age, and status."""
        loop = asyncio.get_event_loop()
        try:
            import boto3

            iam_client = boto3.client("iam", region_name=self._region)

            users = await loop.run_in_executor(None, iam_client.list_users)
            findings: list[ScanFinding] = []

            for user in users.get("Users", []):
                username = user["UserName"]
                keys_response = await loop.run_in_executor(
                    None,
                    partial(iam_client.list_access_keys, UserName=username),
                )

                for key_meta in keys_response.get("AccessKeyMetadata", []):
                    key_id = key_meta["AccessKeyId"]
                    created = key_meta["CreateDate"]
                    status = key_meta["Status"]

                    age_days = (datetime.now(UTC) - created.replace(tzinfo=UTC)).days if created else 0
                    value_hash = hashlib.sha256(key_id.encode()).hexdigest()

                    findings.append(
                        ScanFinding(
                            source="cloud_auditor",
                            secret_type=SecretType.AWS_IAM_KEY,
                            location=SecretLocation.AWS_SECRETS_MANAGER,
                            location_detail=f"iam:user/{username}/key/{key_id}",
                            matched_value_hash=value_hash,
                            confidence=1.0,
                            context_snippet=(
                                f"IAM User: {username}, Key: {key_id[:8]}..., "
                                f"Status: {status}, Age: {age_days} days"
                            ),
                            rule_id="aws_iam_enumeration",
                            provider="aws",
                        )
                    )

            logger.info("AWS audit found %d IAM keys", len(findings))
            return findings

        except Exception as e:
            logger.error("AWS audit failed: %s", e, exc_info=True)
            raise

    async def audit_gcp(self, project_id: str | None = None) -> list[ScanFinding]:
        """Enumerate GCP service account keys via REST API."""
        import os

        project_id = project_id or os.environ.get("GCP_PROJECT_ID", "")
        if not project_id:
            logger.warning("GCP_PROJECT_ID not set, skipping GCP audit")
            return []

        token = os.environ.get("GCP_ACCESS_TOKEN", "")
        if not token:
            logger.warning("GCP_ACCESS_TOKEN not set, skipping GCP audit")
            return []

        findings: list[ScanFinding] = []

        async with httpx.AsyncClient() as client:
            # List service accounts
            sa_url = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"
            sa_response = await client.get(
                sa_url,
                headers={"Authorization": f"Bearer {token}"},
            )
            if sa_response.status_code != 200:
                logger.warning("GCP service accounts list failed: %d", sa_response.status_code)
                return []

            accounts = sa_response.json().get("accounts", [])

            for account in accounts:
                sa_email = account.get("email", "")
                keys_url = f"{sa_url}/{sa_email}/keys"
                keys_response = await client.get(
                    keys_url,
                    headers={"Authorization": f"Bearer {token}"},
                )
                if keys_response.status_code != 200:
                    continue

                for key in keys_response.json().get("keys", []):
                    key_name = key.get("name", "")
                    key_type = key.get("keyType", "")
                    if key_type == "SYSTEM_MANAGED":
                        continue

                    value_hash = hashlib.sha256(key_name.encode()).hexdigest()
                    findings.append(
                        ScanFinding(
                            source="cloud_auditor",
                            secret_type=SecretType.GCP_SERVICE_ACCOUNT,
                            location=SecretLocation.GCP_SECRET_MANAGER,
                            location_detail=key_name,
                            matched_value_hash=value_hash,
                            confidence=1.0,
                            context_snippet=f"Service Account: {sa_email}, Key Type: {key_type}",
                            rule_id="gcp_sa_key_enumeration",
                            provider="gcp",
                        )
                    )

        logger.info("GCP audit found %d service account keys", len(findings))
        return findings

    async def audit_azure(self, tenant_id: str | None = None) -> list[ScanFinding]:
        """Enumerate Azure AD app credentials via Microsoft Graph API."""
        import os

        tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID", "")
        token = os.environ.get("AZURE_ACCESS_TOKEN", "")
        if not tenant_id or not token:
            logger.warning("Azure credentials not set, skipping Azure audit")
            return []

        findings: list[ScanFinding] = []

        async with httpx.AsyncClient() as client:
            apps_url = "https://graph.microsoft.com/v1.0/applications"
            response = await client.get(
                apps_url,
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code != 200:
                logger.warning("Azure applications list failed: %d", response.status_code)
                return []

            for app in response.json().get("value", []):
                app_name = app.get("displayName", "unknown")
                app_id = app.get("appId", "")

                for cred in app.get("passwordCredentials", []):
                    key_id = cred.get("keyId", "")
                    value_hash = hashlib.sha256(key_id.encode()).hexdigest()
                    end_date = cred.get("endDateTime", "")

                    findings.append(
                        ScanFinding(
                            source="cloud_auditor",
                            secret_type=SecretType.AZURE_AD_CREDENTIAL,
                            location=SecretLocation.AZURE_KEY_VAULT,
                            location_detail=f"app/{app_id}/credential/{key_id}",
                            matched_value_hash=value_hash,
                            confidence=1.0,
                            context_snippet=f"App: {app_name}, Expires: {end_date}",
                            rule_id="azure_ad_credential_enumeration",
                            provider="azure",
                        )
                    )

        logger.info("Azure audit found %d app credentials", len(findings))
        return findings
