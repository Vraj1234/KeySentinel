import asyncio
import hashlib
import logging
import os
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

SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "dist", "build",
    ".eggs", "vendor", ".tox",
})

SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz", ".bz2",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin",
})


def _is_binary(file_path: str, sample_size: int = 8192) -> bool:
    """Check if a file is binary by looking for null bytes."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(sample_size)
            return b"\x00" in chunk
    except OSError:
        return True


def _read_file(file_path: str, max_size_kb: int) -> str | None:
    """Read a file if it's within size limits. Returns None for skipped files."""
    try:
        size = os.path.getsize(file_path)
        if size > max_size_kb * 1024:
            return None
        with open(file_path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


class RepoScanner:
    """Scans git repositories for hardcoded secrets using pattern matching and entropy."""

    def __init__(
        self,
        patterns: list[SecretPattern] | None = None,
        max_file_size_kb: int = 512,
        entropy_threshold: float = 4.5,
    ) -> None:
        self._patterns = patterns or list(PATTERNS)
        self._max_file_size_kb = max_file_size_kb
        self._entropy_threshold = entropy_threshold

    async def scan_repository(self, repo_path: str) -> list[ScanFinding]:
        """Scan an entire repository directory for hardcoded secrets."""
        loop = asyncio.get_event_loop()
        file_paths = await loop.run_in_executor(
            None, partial(self._collect_files, repo_path)
        )

        findings: list[ScanFinding] = []
        for file_path in file_paths:
            file_findings = await self.scan_file(file_path)
            findings.extend(file_findings)

        logger.info("Scanned %d files in %s, found %d findings", len(file_paths), repo_path, len(findings))
        return findings

    async def scan_file(self, file_path: str) -> list[ScanFinding]:
        """Scan a single file for secrets."""
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(
            None, partial(_read_file, file_path, self._max_file_size_kb)
        )
        if content is None:
            return []

        is_bin = await loop.run_in_executor(None, partial(_is_binary, file_path))
        if is_bin:
            return []

        raw_matches = scan_text(content, self._patterns)
        findings: list[ScanFinding] = []

        for match in raw_matches:
            confidence = match.pattern.confidence
            if confidence < 0.8 and is_high_entropy(match.matched_text, self._entropy_threshold):
                confidence = min(confidence + 0.3, 0.95)

            value_hash = hashlib.sha256(match.matched_text.encode()).hexdigest()
            snippet = redact_context(content, match.start, match.end)

            findings.append(
                ScanFinding(
                    source="repo_scanner",
                    secret_type=match.pattern.secret_type,
                    location=SecretLocation.SOURCE_CODE,
                    location_detail=file_path,
                    matched_value_hash=value_hash,
                    confidence=confidence,
                    context_snippet=snippet,
                    rule_id=match.pattern.rule_id,
                    provider=match.pattern.provider,
                    line_number=match.line_number,
                )
            )

        return findings

    async def scan_git_history(
        self, repo_path: str, max_commits: int = 100
    ) -> list[ScanFinding]:
        """Scan recent git history for secrets introduced in commits."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "log", f"--max-count={max_commits}",
                "--diff-filter=A", "-p", "--no-color",
                cwd=repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode != 0:
                logger.warning("git log failed in %s", repo_path)
                return []

            content = stdout.decode("utf-8", errors="replace")
            raw_matches = scan_text(content, self._patterns)
            findings: list[ScanFinding] = []

            for match in raw_matches:
                confidence = match.pattern.confidence
                if confidence < 0.8 and is_high_entropy(match.matched_text, self._entropy_threshold):
                    confidence = min(confidence + 0.3, 0.95)

                value_hash = hashlib.sha256(match.matched_text.encode()).hexdigest()
                snippet = redact_context(content, match.start, match.end)

                findings.append(
                    ScanFinding(
                        source="repo_scanner",
                        secret_type=match.pattern.secret_type,
                        location=SecretLocation.SOURCE_CODE,
                        location_detail=f"{repo_path} (git history)",
                        matched_value_hash=value_hash,
                        confidence=confidence,
                        context_snippet=snippet,
                        rule_id=match.pattern.rule_id,
                        provider=match.pattern.provider,
                        line_number=match.line_number,
                    )
                )

            return findings
        except FileNotFoundError:
            logger.warning("git not found, skipping history scan")
            return []

    def _collect_files(self, repo_path: str) -> list[str]:
        """Walk directory and collect scannable file paths."""
        files: list[str] = []
        for root, dirs, filenames in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in filenames:
                if Path(name).suffix.lower() in SKIP_EXTENSIONS:
                    continue
                files.append(os.path.join(root, name))
        return files
