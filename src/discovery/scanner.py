import logging
import time
from dataclasses import asdict
from typing import Any

from src.config import settings
from src.discovery.classifier import FindingClassifier
from src.discovery.cloud_auditor import CloudAuditor
from src.discovery.config_scanner import ConfigScanner
from src.discovery.models import ClassificationResult, ScanFinding, ScanReport
from src.discovery.repo_scanner import RepoScanner
from src.models.secret import RiskLevel, Secret, SecretLocation, SecretType
from src.pipeline.engine import StepResult, StepStatus

logger = logging.getLogger(__name__)


class DiscoveryScanner:
    """Unified coordinator for all discovery scanners.

    Orchestrates repo scanning, config scanning, and cloud auditing.
    Deduplicates findings and optionally classifies them via AI.
    Integrates with the pipeline engine as a step handler.
    """

    def __init__(
        self,
        repo_paths: list[str] | None = None,
        config_dirs: list[str] | None = None,
        cloud_providers: list[str] | None = None,
        enable_classification: bool = True,
    ) -> None:
        self._repo_paths = repo_paths or []
        self._config_dirs = config_dirs or []
        self._cloud_providers = cloud_providers or []
        self._enable_classification = enable_classification

        self._repo_scanner = RepoScanner(
            max_file_size_kb=settings.scan_max_file_size_kb,
            entropy_threshold=settings.entropy_threshold,
        )
        self._config_scanner = ConfigScanner(
            entropy_threshold=settings.entropy_threshold,
        )
        self._cloud_auditor = CloudAuditor()
        self._classifier: FindingClassifier | None = None

        if enable_classification and settings.anthropic_api_key:
            self._classifier = FindingClassifier(
                api_key=settings.anthropic_api_key,
                model=settings.classifier_model,
                batch_size=settings.classifier_batch_size,
            )

    async def run(self) -> ScanReport:
        """Execute full discovery scan and return classified results."""
        start_time = time.monotonic()
        all_findings: list[ScanFinding] = []
        errors: list[str] = []
        total_scanned = 0

        # Run repo scans
        for repo_path in self._repo_paths:
            try:
                findings = await self._repo_scanner.scan_repository(repo_path)
                all_findings.extend(findings)
                total_scanned += 1
            except Exception as e:
                errors.append(f"Repo scan failed for {repo_path}: {e}")
                logger.error("Repo scan failed for %s: %s", repo_path, e, exc_info=True)

        # Run config scans
        for config_dir in self._config_dirs:
            try:
                findings = await self._config_scanner.scan_directory(config_dir)
                all_findings.extend(findings)
                total_scanned += 1
            except Exception as e:
                errors.append(f"Config scan failed for {config_dir}: {e}")
                logger.error("Config scan failed for %s: %s", config_dir, e, exc_info=True)

        # Run cloud audits
        if self._cloud_providers:
            try:
                findings = await self._cloud_auditor.audit_all(self._cloud_providers)
                all_findings.extend(findings)
                total_scanned += len(self._cloud_providers)
            except Exception as e:
                errors.append(f"Cloud audit failed: {e}")
                logger.error("Cloud audit failed: %s", e, exc_info=True)

        # Deduplicate
        deduped = _deduplicate(all_findings)
        logger.info(
            "Discovery: %d raw findings, %d after dedup", len(all_findings), len(deduped)
        )

        # Classify
        if self._classifier and deduped:
            classified = await self._classifier.classify(deduped)
        else:
            classified = [
                ClassificationResult(
                    finding=f,
                    classification="real",
                    adjusted_confidence=f.confidence,
                    reasoning="Classification disabled or unavailable",
                    risk_level=RiskLevel.MEDIUM,
                )
                for f in deduped
            ]

        duration = time.monotonic() - start_time
        return ScanReport(
            findings=tuple(classified),
            total_scanned=total_scanned,
            scan_duration_seconds=round(duration, 2),
            scanner_errors=tuple(errors),
        )

    async def run_as_pipeline_step(self, context: dict[str, Any]) -> StepResult:
        """Pipeline-compatible handler. Returns StepResult with findings in output."""
        try:
            report = await self.run()
            return StepResult(
                status=StepStatus.COMPLETED,
                output={
                    "findings_count": len(report.findings),
                    "findings": [
                        {
                            "classification": r.classification,
                            "confidence": r.adjusted_confidence,
                            "risk_level": r.risk_level.value,
                            "secret_type": r.finding.secret_type.value,
                            "location": r.finding.location.value,
                            "location_detail": r.finding.location_detail,
                            "provider": r.finding.provider,
                            "rule_id": r.finding.rule_id,
                        }
                        for r in report.findings
                    ],
                    "total_scanned": report.total_scanned,
                    "scan_duration_seconds": report.scan_duration_seconds,
                    "errors": list(report.scanner_errors),
                },
            )
        except Exception as e:
            logger.error("Discovery pipeline step failed: %s", e, exc_info=True)
            return StepResult(status=StepStatus.FAILED, error=str(e))


def to_secret_model(result: ClassificationResult) -> Secret:
    """Convert a ClassificationResult to a Secret ORM model for DB persistence."""
    return Secret(
        name=f"{result.finding.secret_type.value} in {result.finding.location_detail}",
        secret_type=result.finding.secret_type,
        provider=result.finding.provider,
        location=result.finding.location,
        location_detail=result.finding.location_detail,
        risk_level=result.risk_level,
        risk_score=result.adjusted_confidence,
        description=result.reasoning,
    )


def _deduplicate(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Deduplicate findings by hash + location."""
    seen: set[str] = set()
    unique: list[ScanFinding] = []

    for finding in findings:
        key = f"{finding.matched_value_hash}:{finding.location_detail}"
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique
