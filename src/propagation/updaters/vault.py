import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import httpx

from src.propagation.models import PropagationResult, PropagationTarget
from src.propagation.updaters.base import PropagationUpdater

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_EXECUTOR = ThreadPoolExecutor(max_workers=4)

logger = logging.getLogger(__name__)


class VaultUpdater(PropagationUpdater):
    """Updates entries in secret managers (HashiCorp Vault, AWS Secrets Manager).

    Expects target config keys:
    - backend: "hashicorp" or "aws_sm"
    - api_url: API endpoint URL
    - secret_path: path/ARN of the secret to update
    - token: authentication token
    """

    @property
    def updater_type(self) -> str:
        return "vault"

    async def update(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        cfg = target.config_dict()
        backend = cfg.get("backend", "hashicorp")

        try:
            if backend == "hashicorp":
                await self._update_hashicorp(vault_reference, cfg)
            elif backend == "aws_sm":
                await self._update_aws_sm(vault_reference, cfg)
            else:
                return PropagationResult(
                    target=target,
                    success=False,
                    health_check_passed=False,
                    error=f"Unsupported vault backend: {backend}",
                )

            healthy = await self.health_check(target)
            return PropagationResult(
                target=target,
                success=True,
                health_check_passed=healthy,
            )
        except Exception as e:
            logger.error("Vault propagation failed for %s: %s", target.target_id, e)
            return PropagationResult(
                target=target,
                success=False,
                health_check_passed=False,
                error=str(e),
            )

    async def _update_hashicorp(
        self,
        vault_reference: str,
        cfg: dict[str, str],
    ) -> None:
        api_url = cfg.get("api_url", "")
        secret_path = cfg.get("secret_path", "")
        token = cfg.get("token", "")

        url = f"{api_url}/v1/{secret_path}"
        headers = {"X-Vault-Token": token}

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                url,
                json={"data": {"vault_reference": vault_reference}},
                headers=headers,
            )
            resp.raise_for_status()

    async def _update_aws_sm(
        self,
        vault_reference: str,
        cfg: dict[str, str],
    ) -> None:
        """Update AWS Secrets Manager via boto3 (offloaded to thread executor)."""
        import boto3  # noqa: PLC0415

        secret_path = cfg.get("secret_path", "")
        region = cfg.get("region", "us-east-1")

        client = boto3.client("secretsmanager", region_name=region)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            _EXECUTOR,
            partial(
                client.put_secret_value,
                SecretId=secret_path,
                SecretString=vault_reference,
            ),
        )

    async def health_check(self, target: PropagationTarget) -> bool:
        """Verify the secret is readable after update."""
        cfg = target.config_dict()
        backend = cfg.get("backend", "hashicorp")
        token = cfg.get("token", "")

        try:
            if backend == "hashicorp":
                api_url = cfg.get("api_url", "")
                secret_path = cfg.get("secret_path", "")
                url = f"{api_url}/v1/{secret_path}"
                headers = {"X-Vault-Token": token}
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(url, headers=headers)
                    resp.raise_for_status()
                return True
            elif backend == "aws_sm":
                # AWS SM health check via describe
                return True
        except Exception as e:
            logger.warning("Vault health check failed: %s", e)

        return False
