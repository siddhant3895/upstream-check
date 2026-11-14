"""Source availability checks: reachability, status code, and non-empty payload inspection."""

from __future__ import annotations

from typing import List

from upstream_check.config.models import SourceConfig
from upstream_check.core.models import (
    CheckCategory,
    CheckFinding,
    FetchedDataset,
    Severity,
)


def run_availability_checks(
    source: SourceConfig, dataset: FetchedDataset
) -> List[CheckFinding]:
    """Verify source reachability and non-empty dataset response."""
    findings: List[CheckFinding] = []
    if not dataset.available:
        details = []
        if dataset.error_message:
            details.append(f"Reason: {dataset.error_message}")
        findings.append(
            CheckFinding(
                category=CheckCategory.AVAILABILITY,
                passed=False,
                title="Source endpoint unreachable or returned error",
                details=details,
                severity=Severity.CRITICAL,
            )
        )
        return findings

    findings.append(
        CheckFinding(
            category=CheckCategory.AVAILABILITY,
            passed=True,
            title="HTTP response received",
            severity=Severity.INFO,
        )
    )

    min_rows = source.quality.min_rows if source.quality is not None else 1
    if len(dataset.rows) == 0 and min_rows > 0:
        findings.append(
            CheckFinding(
                category=CheckCategory.AVAILABILITY,
                passed=False,
                title="Endpoint returned an empty dataset (0 rows)",
                details=[f"Minimum required rows: {min_rows}"],
                severity=Severity.CRITICAL,
            )
        )
    return findings
