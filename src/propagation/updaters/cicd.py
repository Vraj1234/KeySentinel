import logging

import httpx

from src.propagation.models import PropagationResult, PropagationTarget
from src.propagation.updaters.base import PropagationUpdater

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)

logger = logging.getLogger(__name__)


class CICDUpdater(PropagationUpdater):
    """Updates CI/CD environment variables via provider APIs.

    Supports GitHub Actions and GitLab CI. Expects target config keys:
    - platform: "github" or "gitlab"
    - api_url: API base URL
    - repo: repository identifier (owner/repo for GitHub, project_id for GitLab)
    - variable_name: environment variable name to update
    - token: API authentication token
    """

    @property
    def updater_type(self) -> str:
        return "cicd"

    async def update(
        self,
        secret_id: str,
        vault_reference: str,
        target: PropagationTarget,
    ) -> PropagationResult:
        cfg = target.config_dict()
        platform = cfg.get("platform", "github")

        try:
            if platform == "github":
                await self._update_github(vault_reference, cfg)
            elif platform == "gitlab":
                await self._update_gitlab(vault_reference, cfg)
            else:
                return PropagationResult(
                    target=target,
                    success=False,
                    health_check_passed=False,
                    error=f"Unsupported CI/CD platform: {platform}",
                )

            healthy = await self.health_check(target)
            return PropagationResult(
                target=target,
                success=True,
                health_check_passed=healthy,
            )
        except Exception as e:
            logger.error("CI/CD propagation failed for %s: %s", target.target_id, e)
            return PropagationResult(
                target=target,
                success=False,
                health_check_passed=False,
                error=str(e),
            )

    async def _update_github(
        self,
        vault_reference: str,
        cfg: dict[str, str],
    ) -> None:
        api_url = cfg.get("api_url", "https://api.github.com")
        repo = cfg.get("repo", "")
        var_name = cfg.get("variable_name", "")
        token = cfg.get("token", "")

        url = f"{api_url}/repos/{repo}/actions/variables/{var_name}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        }

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.patch(
                url,
                json={"value": vault_reference},
                headers=headers,
            )
            resp.raise_for_status()

    async def _update_gitlab(
        self,
        vault_reference: str,
        cfg: dict[str, str],
    ) -> None:
        api_url = cfg.get("api_url", "https://gitlab.com/api/v4")
        project_id = cfg.get("repo", "")
        var_name = cfg.get("variable_name", "")
        token = cfg.get("token", "")

        url = f"{api_url}/projects/{project_id}/variables/{var_name}"
        headers = {"PRIVATE-TOKEN": token}

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.put(
                url,
                json={"value": vault_reference},
                headers=headers,
            )
            resp.raise_for_status()

    async def health_check(self, target: PropagationTarget) -> bool:
        """Verify CI/CD variable was updated by reading it back."""
        cfg = target.config_dict()
        platform = cfg.get("platform", "github")
        token = cfg.get("token", "")

        try:
            if platform == "github":
                api_url = cfg.get("api_url", "https://api.github.com")
                repo = cfg.get("repo", "")
                var_name = cfg.get("variable_name", "")
                url = f"{api_url}/repos/{repo}/actions/variables/{var_name}"
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                }
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(url, headers=headers)
                    resp.raise_for_status()
                return True
            elif platform == "gitlab":
                api_url = cfg.get("api_url", "https://gitlab.com/api/v4")
                project_id = cfg.get("repo", "")
                var_name = cfg.get("variable_name", "")
                url = f"{api_url}/projects/{project_id}/variables/{var_name}"
                headers = {"PRIVATE-TOKEN": token}
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(url, headers=headers)
                    resp.raise_for_status()
                return True
        except Exception as e:
            logger.warning("CI/CD health check failed: %s", e)

        return False
