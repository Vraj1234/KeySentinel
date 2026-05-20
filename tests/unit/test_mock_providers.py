"""Tests for demo mock providers and updaters."""

from demo.mock_providers import MockAWSProvider, MockDatabaseProvider
from demo.mock_updaters import MockCICDUpdater, MockKubernetesUpdater, MockVaultUpdater
from src.propagation.models import PropagationTarget


class TestMockAWSProvider:
    async def test_full_lifecycle(self) -> None:
        provider = MockAWSProvider(delay=0)

        # Create
        result = await provider.create_key("secret-1")
        assert result.success
        assert result.new_key_id is not None
        assert result.vault_reference.startswith("mock-vault://aws/")

        key_id = result.new_key_id

        # Verify
        assert await provider.verify_key(key_id) is True

        # List
        keys = await provider.list_keys("secret-1")
        assert len(keys) == 1
        assert keys[0].key_id == key_id

        # Deactivate
        deactivate = await provider.deactivate_key(key_id)
        assert deactivate.success
        assert await provider.verify_key(key_id) is False

        # Reactivate
        reactivate = await provider.reactivate_key(key_id)
        assert reactivate.success
        assert await provider.verify_key(key_id) is True

        # Delete
        delete = await provider.delete_key(key_id)
        assert delete.success
        assert await provider.verify_key(key_id) is False

    async def test_delete_nonexistent(self) -> None:
        provider = MockAWSProvider(delay=0)
        result = await provider.delete_key("nonexistent")
        assert not result.success

    def test_provider_name(self) -> None:
        assert MockAWSProvider().provider_name == "mock_aws_iam"


class TestMockDatabaseProvider:
    async def test_full_lifecycle(self) -> None:
        provider = MockDatabaseProvider(delay=0)

        result = await provider.create_key("db-secret")
        assert result.success
        assert result.vault_reference.startswith("mock-vault://db/")

        key_id = result.new_key_id
        assert await provider.verify_key(key_id) is True

        await provider.deactivate_key(key_id)
        assert await provider.verify_key(key_id) is False

        await provider.reactivate_key(key_id)
        assert await provider.verify_key(key_id) is True

        await provider.delete_key(key_id)
        keys = await provider.list_keys("db-secret")
        assert len(keys) == 0

    def test_provider_name(self) -> None:
        assert MockDatabaseProvider().provider_name == "mock_postgresql"


class TestMockUpdaters:
    async def test_vault_updater(self) -> None:
        updater = MockVaultUpdater()
        target = PropagationTarget(
            target_type="vault",
            target_id="vault-prod",
        )
        result = await updater.update("s1", "mock-vault://ref", target)
        assert result.success
        assert result.health_check_passed
        assert await updater.health_check(target) is True
        assert updater.updater_type == "vault"

    async def test_kubernetes_updater(self) -> None:
        updater = MockKubernetesUpdater()
        target = PropagationTarget(
            target_type="kubernetes",
            target_id="k8s-prod",
        )
        result = await updater.update("s1", "mock-vault://ref", target)
        assert result.success
        assert updater.updater_type == "kubernetes"

    async def test_cicd_updater(self) -> None:
        updater = MockCICDUpdater()
        target = PropagationTarget(
            target_type="cicd",
            target_id="github-actions",
        )
        result = await updater.update("s1", "mock-vault://ref", target)
        assert result.success
        assert updater.updater_type == "cicd"
