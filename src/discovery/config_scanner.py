import asyncio
import hashlib
import logging
import os
import re
from functools import partial
from pathlib import Path

from src.discovery.models import ScanFinding
from src.discovery.patterns import (
    PATTERNS,
    SecretPattern,
    is_high_entropy,
    redact_context,
    scan_text,
)
from src.models.secret import SecretLocation, SecretType

logger = logging.getLogger(__name__)

SECRET_KEY_PATTERNS = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|auth|credential)",
    re.IGNORECASE,
)

CONFIG_EXTENSIONS = frozenset({
    ".env", ".yml", ".yaml", ".tf", ".tfvars", ".toml", ".ini", ".cfg", ".conf",
})


class ConfigScanner:
    """Scans configuration files for hardcoded secrets."""

    def __init__(
        self,
        patterns: list[SecretPattern] | None = None,
        entropy_threshold: float = 4.5,
    ) -> None:
        self._patterns = patterns or list(PATTERNS)
        self._entropy_threshold = entropy_threshold

    async def scan_directory(self, dir_path: str) -> list[ScanFinding]:
        """Auto-detect config files in a directory and scan all of them."""
        loop = asyncio.get_event_loop()
        config_files = await loop.run_in_executor(
            None, partial(self._find_config_files, dir_path)
        )

        findings: list[ScanFinding] = []
        for file_path in config_files:
            suffix = Path(file_path).suffix.lower()
            name = Path(file_path).name.lower()

            if name.startswith(".env") or suffix == ".env":
                findings.extend(await self.scan_env_file(file_path))
            elif suffix in (".yml", ".yaml"):
                findings.extend(await self.scan_yaml_file(file_path))
            elif suffix in (".tf", ".tfvars"):
                findings.extend(await self.scan_terraform(file_path))
            else:
                findings.extend(await self._scan_generic_config(file_path))

        logger.info("Scanned %d config files in %s, found %d findings", len(config_files), dir_path, len(findings))
        return findings

    async def scan_env_file(self, file_path: str) -> list[ScanFinding]:
        """Parse .env file and check values for secrets."""
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, partial(self._read_file, file_path))
        if content is None:
            return []

        findings: list[ScanFinding] = []
        for line_num, line in enumerate(content.split("\n"), start=1):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")

            if not value or len(value) < 8:
                continue

            is_secret_key = bool(SECRET_KEY_PATTERNS.search(key))
            has_entropy = is_high_entropy(value, self._entropy_threshold)

            if is_secret_key or has_entropy:
                confidence = 0.8 if (is_secret_key and has_entropy) else 0.5
                value_hash = hashlib.sha256(value.encode()).hexdigest()

                findings.append(
                    ScanFinding(
                        source="config_scanner",
                        secret_type=self._infer_type_from_key(key),
                        location=SecretLocation.CONFIG_FILE,
                        location_detail=f"{file_path}:{key}",
                        matched_value_hash=value_hash,
                        confidence=confidence,
                        context_snippet=f"{key}=***REDACTED***",
                        rule_id="env_secret_value",
                        provider="generic",
                        line_number=line_num,
                    )
                )

        return findings

    async def scan_yaml_file(self, file_path: str) -> list[ScanFinding]:
        """Scan YAML files (docker-compose, K8s manifests) for secrets."""
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, partial(self._read_file, file_path))
        if content is None:
            return []

        findings: list[ScanFinding] = []

        try:
            import yaml

            docs = list(yaml.safe_load_all(content))
        except Exception as e:
            logger.warning("Failed to parse YAML %s: %s", file_path, e)
            # Fall back to pattern-based scanning
            return await self._scan_generic_config(file_path)

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            # K8s Secret detection
            if doc.get("kind") == "Secret" and "data" in doc:
                for key, value in doc["data"].items():
                    if isinstance(value, str):
                        value_hash = hashlib.sha256(value.encode()).hexdigest()
                        findings.append(
                            ScanFinding(
                                source="config_scanner",
                                secret_type=SecretType.GENERIC,
                                location=SecretLocation.KUBERNETES_SECRET,
                                location_detail=f"{file_path}:data.{key}",
                                matched_value_hash=value_hash,
                                confidence=0.9,
                                context_snippet=f"data.{key}: ***REDACTED***",
                                rule_id="k8s_secret_data",
                                provider="kubernetes",
                            )
                        )

            # Docker Compose / generic YAML: scan environment values
            self._scan_yaml_dict(doc, file_path, "", findings)

        return findings

    async def scan_terraform(self, file_path: str) -> list[ScanFinding]:
        """Scan Terraform files for hardcoded credentials."""
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, partial(self._read_file, file_path))
        if content is None:
            return []

        # Use pattern-based scanning for .tf files
        raw_matches = scan_text(content, self._patterns)
        findings: list[ScanFinding] = []

        for match in raw_matches:
            value_hash = hashlib.sha256(match.matched_text.encode()).hexdigest()
            snippet = redact_context(content, match.start, match.end)
            findings.append(
                ScanFinding(
                    source="config_scanner",
                    secret_type=match.pattern.secret_type,
                    location=SecretLocation.CONFIG_FILE,
                    location_detail=file_path,
                    matched_value_hash=value_hash,
                    confidence=match.pattern.confidence,
                    context_snippet=snippet,
                    rule_id=match.pattern.rule_id,
                    provider=match.pattern.provider,
                    line_number=match.line_number,
                )
            )

        return findings

    async def _scan_generic_config(self, file_path: str) -> list[ScanFinding]:
        """Fall back to pattern-based scanning for any config file."""
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, partial(self._read_file, file_path))
        if content is None:
            return []

        raw_matches = scan_text(content, self._patterns)
        findings: list[ScanFinding] = []

        for match in raw_matches:
            value_hash = hashlib.sha256(match.matched_text.encode()).hexdigest()
            snippet = redact_context(content, match.start, match.end)
            findings.append(
                ScanFinding(
                    source="config_scanner",
                    secret_type=match.pattern.secret_type,
                    location=SecretLocation.CONFIG_FILE,
                    location_detail=file_path,
                    matched_value_hash=value_hash,
                    confidence=match.pattern.confidence,
                    context_snippet=snippet,
                    rule_id=match.pattern.rule_id,
                    provider=match.pattern.provider,
                    line_number=match.line_number,
                )
            )

        return findings

    def _scan_yaml_dict(
        self,
        obj: dict | list | str,
        file_path: str,
        path: str,
        findings: list[ScanFinding],
    ) -> None:
        """Recursively scan YAML structure for secret-like values."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, str) and bool(SECRET_KEY_PATTERNS.search(str(key))):
                    if len(value) >= 8 and is_high_entropy(value, self._entropy_threshold):
                        value_hash = hashlib.sha256(value.encode()).hexdigest()
                        findings.append(
                            ScanFinding(
                                source="config_scanner",
                                secret_type=self._infer_type_from_key(str(key)),
                                location=SecretLocation.CONFIG_FILE,
                                location_detail=f"{file_path}:{current_path}",
                                matched_value_hash=value_hash,
                                confidence=0.7,
                                context_snippet=f"{current_path}: ***REDACTED***",
                                rule_id="yaml_secret_value",
                                provider="generic",
                            )
                        )
                else:
                    self._scan_yaml_dict(value, file_path, current_path, findings)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._scan_yaml_dict(item, file_path, f"{path}[{i}]", findings)

    @staticmethod
    def _infer_type_from_key(key: str) -> SecretType:
        """Infer SecretType from a key name."""
        key_lower = key.lower()
        if "aws" in key_lower:
            return SecretType.AWS_IAM_KEY
        if "gcp" in key_lower or "google" in key_lower:
            return SecretType.GCP_SERVICE_ACCOUNT
        if "azure" in key_lower:
            return SecretType.AZURE_AD_CREDENTIAL
        if any(kw in key_lower for kw in ("password", "passwd", "pwd", "db_")):
            return SecretType.DATABASE_PASSWORD
        if any(kw in key_lower for kw in ("token", "oauth")):
            return SecretType.OAUTH_TOKEN
        if any(kw in key_lower for kw in ("api_key", "apikey", "api-key")):
            return SecretType.API_KEY
        return SecretType.GENERIC

    @staticmethod
    def _read_file(file_path: str) -> str | None:
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    @staticmethod
    def _find_config_files(dir_path: str) -> list[str]:
        files: list[str] = []
        for root, _, filenames in os.walk(dir_path):
            for name in filenames:
                p = Path(name)
                if p.suffix.lower() in CONFIG_EXTENSIONS or p.name.lower().startswith(".env"):
                    files.append(os.path.join(root, name))
        return files
