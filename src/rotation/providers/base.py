import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RotationResult:
    success: bool
    new_key_id: str | None = None
    new_key_created_at: datetime | None = None
    old_key_id: str | None = None
    error: str | None = None
    vault_reference: str | None = None


@dataclass(frozen=True)
class KeyInfo:
    key_id: str
    provider: str
    created_at: datetime
    is_active: bool
    permissions: tuple[str, ...] | None = None
    last_used_at: datetime | None = None


class RotationProvider(ABC):
    """Base interface for all secret rotation providers.

    Each provider implements the rotation lifecycle:
    create_key → verify_new_key → deactivate_old_key → delete_old_key

    Providers must be deterministic — no LLM calls in the rotation path.
    Secret material must never be returned in RotationResult. Providers
    must store new credentials directly in the target vault/secret store
    and return only a reference ID.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique identifier for this provider (e.g., 'aws_iam', 'stripe')."""

    @abstractmethod
    async def create_key(self, secret_id: str) -> RotationResult:
        """Create a new key/credential with the provider.

        The new credential must be stored directly in the target secret store.
        Only a vault reference should be returned, never plaintext secret material.
        """

    @abstractmethod
    async def verify_key(self, key_id: str) -> bool:
        """Verify that a key is functional (e.g., make a test API call)."""

    @abstractmethod
    async def deactivate_key(self, key_id: str) -> RotationResult:
        """Deactivate an old key (key still exists but can't be used)."""

    @abstractmethod
    async def delete_key(self, key_id: str) -> RotationResult:
        """Permanently delete an old key after grace period."""

    @abstractmethod
    async def list_keys(self, secret_id: str) -> list[KeyInfo]:
        """List all keys/credentials for a given secret."""

    async def rollback(self, old_key_id: str, new_key_id: str) -> RotationResult:
        """Rollback a rotation: reactivate old key and delete new key."""
        reactivate = await self.reactivate_key(old_key_id)
        if not reactivate.success:
            return reactivate

        return await self.delete_key(new_key_id)

    async def reactivate_key(self, key_id: str) -> RotationResult:
        """Reactivate a previously deactivated key. Override if supported."""
        return RotationResult(
            success=False,
            error=f"Reactivation not supported by provider {self.provider_name}",
        )
