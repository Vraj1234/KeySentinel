"""Simulated propagation updaters for demo and testing."""

import logging

from src.propagation.models import PropagationResult, PropagationTarget
from src.propagation.updaters.base import PropagationUpdater

logger = logging.getLogger(__name__)


class MockVaultUpdater(PropagationUpdater):
    """Simulates pushing credentials to a vault."""

    @property
    def updater_type(self) -> str:
        return "vault"

    async def update(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        logger.info(
            "MockVault: updated %s -> %s (ref: %s)",
            secret_id,
            target.target_id,
            vault_reference,
        )
        return PropagationResult(
            target=target,
            success=True,
            health_check_passed=True,
        )

    async def health_check(self, target: PropagationTarget) -> bool:
        return True


class MockKubernetesUpdater(PropagationUpdater):
    """Simulates updating Kubernetes secrets."""

    @property
    def updater_type(self) -> str:
        return "kubernetes"

    async def update(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        logger.info(
            "MockK8s: patched secret %s in %s",
            secret_id,
            target.target_id,
        )
        return PropagationResult(
            target=target,
            success=True,
            health_check_passed=True,
        )

    async def health_check(self, target: PropagationTarget) -> bool:
        return True


class MockCICDUpdater(PropagationUpdater):
    """Simulates updating CI/CD environment variables."""

    @property
    def updater_type(self) -> str:
        return "cicd"

    async def update(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        logger.info(
            "MockCICD: updated env var for %s in %s",
            secret_id,
            target.target_id,
        )
        return PropagationResult(
            target=target,
            success=True,
            health_check_passed=True,
        )

    async def health_check(self, target: PropagationTarget) -> bool:
        return True
