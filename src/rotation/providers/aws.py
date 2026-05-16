import asyncio
import logging
from datetime import UTC, datetime
from functools import partial
from typing import Any

from src.rotation.providers.base import KeyInfo, RotationProvider, RotationResult

logger = logging.getLogger(__name__)


class AWSIAMProvider(RotationProvider):
    """AWS IAM access key rotation provider.

    Handles creation, deactivation, and deletion of IAM user access keys
    via the boto3 SDK. New credentials are stored in AWS Secrets Manager
    and only a reference is returned.

    All boto3 calls are offloaded to a thread executor to avoid blocking
    the asyncio event loop.
    """

    def __init__(self, iam_user: str, region: str = "us-east-1", secrets_manager_arn: str = "") -> None:
        self._iam_user = iam_user
        self._region = region
        self._secrets_manager_arn = secrets_manager_arn
        self._client: Any = None
        self._secrets_client: Any = None

    @property
    def provider_name(self) -> str:
        return "aws_iam"

    def _get_client(self) -> Any:
        if self._client is None:
            import boto3

            self._client = boto3.client("iam", region_name=self._region)
        return self._client

    def _get_secrets_client(self) -> Any:
        if self._secrets_client is None:
            import boto3

            self._secrets_client = boto3.client("secretsmanager", region_name=self._region)
        return self._secrets_client

    async def _run_sync(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Offload a synchronous boto3 call to a thread executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, partial(fn, *args, **kwargs))

    async def create_key(self, secret_id: str) -> RotationResult:
        try:
            client = self._get_client()
            response = await self._run_sync(client.create_access_key, UserName=self._iam_user)
            key = response["AccessKey"]

            vault_ref = await self._store_in_vault(key["AccessKeyId"], key["SecretAccessKey"])

            return RotationResult(
                success=True,
                new_key_id=key["AccessKeyId"],
                new_key_created_at=datetime.now(UTC),
                vault_reference=vault_ref,
            )
        except Exception as e:
            logger.error("Failed to create IAM key for user %s: %s", self._iam_user, e, exc_info=True)
            return RotationResult(success=False, error=str(e))

    async def _store_in_vault(self, access_key_id: str, secret_access_key: str) -> str:
        """Store new credentials in AWS Secrets Manager. Returns the ARN."""
        import json

        secrets_client = self._get_secrets_client()
        response = await self._run_sync(
            secrets_client.put_secret_value,
            SecretId=self._secrets_manager_arn,
            SecretString=json.dumps({
                "access_key_id": access_key_id,
                "secret_access_key": secret_access_key,
            }),
        )
        return response["ARN"]

    async def verify_key(self, key_id: str) -> bool:
        """Verify key exists and is active by checking its status."""
        try:
            client = self._get_client()
            response = await self._run_sync(
                client.list_access_keys, UserName=self._iam_user
            )
            for key_meta in response.get("AccessKeyMetadata", []):
                if key_meta["AccessKeyId"] == key_id:
                    return key_meta["Status"] == "Active"
            return False
        except Exception as e:
            logger.warning("Key verification failed for %s: %s", key_id, e, exc_info=True)
            return False

    async def deactivate_key(self, key_id: str) -> RotationResult:
        try:
            client = self._get_client()
            await self._run_sync(
                client.update_access_key,
                UserName=self._iam_user,
                AccessKeyId=key_id,
                Status="Inactive",
            )
            return RotationResult(success=True, old_key_id=key_id)
        except Exception as e:
            logger.error("Failed to deactivate key %s: %s", key_id, e, exc_info=True)
            return RotationResult(success=False, error=str(e))

    async def delete_key(self, key_id: str) -> RotationResult:
        try:
            client = self._get_client()
            await self._run_sync(
                client.delete_access_key,
                UserName=self._iam_user,
                AccessKeyId=key_id,
            )
            return RotationResult(success=True, old_key_id=key_id)
        except Exception as e:
            logger.error("Failed to delete key %s: %s", key_id, e, exc_info=True)
            return RotationResult(success=False, error=str(e))

    async def reactivate_key(self, key_id: str) -> RotationResult:
        try:
            client = self._get_client()
            await self._run_sync(
                client.update_access_key,
                UserName=self._iam_user,
                AccessKeyId=key_id,
                Status="Active",
            )
            return RotationResult(success=True, old_key_id=key_id)
        except Exception as e:
            logger.error("Failed to reactivate key %s: %s", key_id, e, exc_info=True)
            return RotationResult(success=False, error=str(e))

    async def list_keys(self, secret_id: str) -> list[KeyInfo]:
        try:
            client = self._get_client()
            response = await self._run_sync(
                client.list_access_keys, UserName=self._iam_user
            )
            keys = []
            for key_meta in response["AccessKeyMetadata"]:
                keys.append(
                    KeyInfo(
                        key_id=key_meta["AccessKeyId"],
                        provider=self.provider_name,
                        created_at=key_meta["CreateDate"],
                        is_active=key_meta["Status"] == "Active",
                    )
                )
            return keys
        except Exception as e:
            logger.error("Failed to list keys for user %s: %s", self._iam_user, e, exc_info=True)
            return []
