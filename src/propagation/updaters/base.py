import logging
from abc import ABC, abstractmethod

from src.propagation.models import PropagationResult, PropagationTarget

logger = logging.getLogger(__name__)


class PropagationUpdater(ABC):
    """Abstract base for pushing rotated credentials to dependent services."""

    @property
    @abstractmethod
    def updater_type(self) -> str:
        """Unique identifier for this updater (e.g., 'kubernetes', 'cicd')."""

    @abstractmethod
    async def update(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        """Push the new credential to the target."""

    @abstractmethod
    async def health_check(self, target: PropagationTarget) -> bool:
        """Verify the target service is healthy after propagation."""

    async def rollback(
        self,
        secret_id: str,
        previous_vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        """Revert to previous credential. Default: re-run update with old ref."""
        return await self.update(secret_id, previous_vault_reference, target)
