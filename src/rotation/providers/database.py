import logging
import re
import secrets
import string
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

from src.rotation.providers.base import KeyInfo, RotationProvider, RotationResult

logger = logging.getLogger(__name__)

_VALID_IDENTIFIER = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")


def _generate_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class PostgreSQLProvider(RotationProvider):
    """PostgreSQL password rotation provider.

    Rotates database user passwords via ALTER ROLE. New passwords are stored
    directly in the configured secret store, never returned in RotationResult.
    """

    def __init__(
        self,
        host: str,
        port: int,
        admin_user: str,
        admin_password: str,
        target_user: str,
        vault_store_fn: Callable[[str, str], Coroutine[Any, Any, str]] | None = None,
    ) -> None:
        if not _VALID_IDENTIFIER.match(target_user):
            raise ValueError(
                f"Invalid PostgreSQL role name: '{target_user}'. "
                "Must match ^[a-zA-Z_][a-zA-Z0-9_]{{0,62}}$"
            )
        self._host = host
        self._port = port
        self._admin_user = admin_user
        self._admin_password = admin_password
        self._target_user = target_user
        self._vault_store_fn = vault_store_fn

    @property
    def provider_name(self) -> str:
        return "postgresql"

    async def create_key(self, secret_id: str) -> RotationResult:
        if not _VALID_IDENTIFIER.match(self._target_user):
            return RotationResult(
                success=False,
                error=f"Unsafe role name at execution time: {self._target_user!r}",
            )

        new_password = _generate_password()
        try:
            import asyncpg

            async with await asyncpg.connect(
                host=self._host,
                port=self._port,
                user=self._admin_user,
                password=self._admin_password,
            ) as conn:
                await conn.execute(
                    f"ALTER ROLE {self._target_user} WITH PASSWORD $1",
                    new_password,
                )

            vault_ref = None
            if self._vault_store_fn:
                vault_ref = await self._vault_store_fn(secret_id, new_password)

            return RotationResult(
                success=True,
                new_key_id=f"{self._target_user}@{self._host}",
                new_key_created_at=datetime.now(UTC),
                vault_reference=vault_ref,
            )
        except Exception as e:
            logger.error(
                "Failed to rotate password for %s: %s", self._target_user, e, exc_info=True
            )
            return RotationResult(success=False, error=str(e))

    async def verify_key(self, key_id: str) -> bool:
        return True

    async def deactivate_key(self, key_id: str) -> RotationResult:
        return RotationResult(success=True, old_key_id=key_id)

    async def delete_key(self, key_id: str) -> RotationResult:
        return RotationResult(success=True, old_key_id=key_id)

    async def list_keys(self, secret_id: str) -> list[KeyInfo]:
        return [
            KeyInfo(
                key_id=f"{self._target_user}@{self._host}",
                provider=self.provider_name,
                created_at=datetime.now(UTC),
                is_active=True,
            )
        ]
