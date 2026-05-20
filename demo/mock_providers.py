"""Simulated rotation providers for demo and testing."""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from src.rotation.providers.base import KeyInfo, RotationProvider, RotationResult

logger = logging.getLogger(__name__)


class MockAWSProvider(RotationProvider):
    """Simulates AWS IAM key rotation with in-memory state."""

    def __init__(self, delay: float = 0.1) -> None:
        self._keys: dict[str, dict[str, Any]] = {}
        self._delay = delay

    @property
    def provider_name(self) -> str:
        return "mock_aws_iam"

    async def create_key(self, secret_id: str) -> RotationResult:
        await asyncio.sleep(self._delay)
        key_id = f"AKIA{uuid4().hex[:16].upper()}"
        vault_ref = f"mock-vault://aws/{key_id}"
        self._keys[key_id] = {
            "secret_id": secret_id,
            "created_at": datetime.now(UTC),
            "is_active": True,
        }
        logger.info("MockAWS: created key %s for secret %s", key_id, secret_id)
        return RotationResult(
            success=True,
            new_key_id=key_id,
            new_key_created_at=datetime.now(UTC),
            vault_reference=vault_ref,
        )

    async def verify_key(self, key_id: str) -> bool:
        await asyncio.sleep(self._delay)
        key = self._keys.get(key_id)
        return key is not None and key["is_active"]

    async def deactivate_key(self, key_id: str) -> RotationResult:
        await asyncio.sleep(self._delay)
        if key_id in self._keys:
            self._keys[key_id]["is_active"] = False
            logger.info("MockAWS: deactivated key %s", key_id)
            return RotationResult(success=True, old_key_id=key_id)
        return RotationResult(success=False, error=f"Key {key_id} not found")

    async def delete_key(self, key_id: str) -> RotationResult:
        await asyncio.sleep(self._delay)
        if key_id in self._keys:
            del self._keys[key_id]
            logger.info("MockAWS: deleted key %s", key_id)
            return RotationResult(success=True, old_key_id=key_id)
        return RotationResult(success=False, error=f"Key {key_id} not found")

    async def list_keys(self, secret_id: str) -> list[KeyInfo]:
        return [
            KeyInfo(
                key_id=kid,
                provider=self.provider_name,
                created_at=info["created_at"],
                is_active=info["is_active"],
            )
            for kid, info in self._keys.items()
            if info["secret_id"] == secret_id
        ]

    async def reactivate_key(self, key_id: str) -> RotationResult:
        if key_id in self._keys:
            self._keys[key_id]["is_active"] = True
            return RotationResult(success=True, old_key_id=key_id)
        return RotationResult(success=False, error=f"Key {key_id} not found")


class MockDatabaseProvider(RotationProvider):
    """Simulates PostgreSQL credential rotation with in-memory state."""

    def __init__(self, delay: float = 0.1) -> None:
        self._credentials: dict[str, dict[str, Any]] = {}
        self._delay = delay

    @property
    def provider_name(self) -> str:
        return "mock_postgresql"

    async def create_key(self, secret_id: str) -> RotationResult:
        await asyncio.sleep(self._delay)
        cred_id = f"dbcred-{uuid4().hex[:8]}"
        vault_ref = f"mock-vault://db/{cred_id}"
        self._credentials[cred_id] = {
            "secret_id": secret_id,
            "created_at": datetime.now(UTC),
            "is_active": True,
        }
        logger.info("MockDB: created credential %s", cred_id)
        return RotationResult(
            success=True,
            new_key_id=cred_id,
            new_key_created_at=datetime.now(UTC),
            vault_reference=vault_ref,
        )

    async def verify_key(self, key_id: str) -> bool:
        await asyncio.sleep(self._delay)
        cred = self._credentials.get(key_id)
        return cred is not None and cred["is_active"]

    async def deactivate_key(self, key_id: str) -> RotationResult:
        await asyncio.sleep(self._delay)
        if key_id in self._credentials:
            self._credentials[key_id]["is_active"] = False
            return RotationResult(success=True, old_key_id=key_id)
        return RotationResult(success=False, error=f"Credential {key_id} not found")

    async def delete_key(self, key_id: str) -> RotationResult:
        await asyncio.sleep(self._delay)
        if key_id in self._credentials:
            del self._credentials[key_id]
            return RotationResult(success=True, old_key_id=key_id)
        return RotationResult(success=False, error=f"Credential {key_id} not found")

    async def list_keys(self, secret_id: str) -> list[KeyInfo]:
        return [
            KeyInfo(
                key_id=cid,
                provider=self.provider_name,
                created_at=info["created_at"],
                is_active=info["is_active"],
            )
            for cid, info in self._credentials.items()
            if info["secret_id"] == secret_id
        ]

    async def reactivate_key(self, key_id: str) -> RotationResult:
        if key_id in self._credentials:
            self._credentials[key_id]["is_active"] = True
            return RotationResult(success=True, old_key_id=key_id)
        return RotationResult(
            success=False, error=f"Credential {key_id} not found"
        )
