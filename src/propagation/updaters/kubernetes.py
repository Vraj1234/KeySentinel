import logging

import httpx

from src.propagation.models import PropagationResult, PropagationTarget
from src.propagation.updaters.base import PropagationUpdater

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)

logger = logging.getLogger(__name__)


class KubernetesUpdater(PropagationUpdater):
    """Patches Kubernetes Secret objects with new vault references.

    Expects target config keys:
    - api_url: K8s API server URL
    - namespace: target namespace
    - secret_name: K8s Secret resource name
    - key: data key within the Secret
    - token: bearer token for K8s API auth
    """

    @property
    def updater_type(self) -> str:
        return "kubernetes"

    async def update(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        cfg = target.config_dict()
        api_url = cfg.get("api_url", "")
        namespace = cfg.get("namespace", "default")
        secret_name = cfg.get("secret_name", "")
        key = cfg.get("key", "value")
        token = cfg.get("token", "")

        url = f"{api_url}/api/v1/namespaces/{namespace}/secrets/{secret_name}"
        patch_body = {
            "metadata": {"name": secret_name},
            "stringData": {key: vault_reference},
        }
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/strategic-merge-patch+json",
        }

        try:
            async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:  # noqa: S501
                resp = await client.patch(url, json=patch_body, headers=headers)
                resp.raise_for_status()

            healthy = await self.health_check(target)
            return PropagationResult(
                target=target,
                success=True,
                health_check_passed=healthy,
            )
        except Exception as e:
            logger.error(
                "K8s propagation failed for %s/%s: %s",
                namespace,
                secret_name,
                e,
            )
            return PropagationResult(
                target=target,
                success=False,
                health_check_passed=False,
                error=str(e),
            )

    async def health_check(self, target: PropagationTarget) -> bool:
        """Check that pods in the namespace are ready after secret update."""
        cfg = target.config_dict()
        api_url = cfg.get("api_url", "")
        namespace = cfg.get("namespace", "default")
        token = cfg.get("token", "")

        url = f"{api_url}/api/v1/namespaces/{namespace}/pods"
        headers = {"Authorization": f"Bearer {token}"}

        try:
            async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:  # noqa: S501
                resp = await client.get(
                    url,
                    headers=headers,
                    params={"limit": "50"},
                )
                resp.raise_for_status()

            pods = resp.json().get("items", [])
            if not pods:
                return True  # No pods to check

            # Verify at least one pod has Ready condition
            for pod in pods:
                conditions = pod.get("status", {}).get("conditions", [])
                for cond in conditions:
                    if cond.get("type") == "Ready" and cond.get("status") == "True":
                        return True

            logger.warning("K8s health check: no Ready pods in %s", namespace)
            return False
        except Exception as e:
            logger.warning("K8s health check failed for %s: %s", namespace, e)
            return False
