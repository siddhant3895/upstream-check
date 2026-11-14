"""Markdown summary reporter with deterministic incident fingerprinting and diagnostic execution-error fallbacks."""

from __future__ import annotations

import hashlib
import json
import re
from typing import List, Optional

from upstream_check.core.models import EngineReport

STANDALONE_NUM_RE = re.compile(r"(?<![A-Za-z0-9_])[+-]?\d+(?:\.\d+)?%?")


def _normalize_finding_title(title: str, column: Optional[str] = None) -> str:
    """Normalize dynamic numbers/percentages/hours in a finding title while preserving column identifiers."""
    normalized = title
    if column:
        normalized = normalized.replace(column, "<COLUMN>")
    return STANDALONE_NUM_RE.sub("<N>", normalized)


def compute_incident_fingerprint(report: EngineReport) -> str:
    """Compute a deterministic SHA-256 fingerprint of failing check identities (invariant to advancing hours/counts)."""
    if report.passed:
        return ""
    signatures = []
    for res in report.results:
        for finding in res.failed_findings:
            signatures.append(
                {
                    "source": res.source_name,
                    "category": finding.category.value,
                    "column": finding.column or "",
                    "code": _normalize_finding_title(finding.title, finding.column),
                }
            )
    canonical = json.dumps(signatures, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_execution_error_fingerprint(error_message: str, exit_code: int) -> str:
    """Compute a deterministic SHA-256 fingerprint for early CLI/configuration execution failures."""
    payload = {
        "category": "EXECUTION_ERROR",
        "exit_code": exit_code,
        "code": _normalize_finding_title(error_message.strip()),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def format_execution_error_markdown(
    error_message: str, exit_code: int, config_path: str = ""
) -> str:
    """Generate a fallback diagnostic Markdown report when CLI execution fails before check completion."""
    fp = compute_execution_error_fingerprint(error_message, exit_code)
    lines: List[str] = [
        "## Upstream Check Report — EXECUTION ERROR",
        "",
        f"- **Status**: `Execution / Configuration Failure` (Exit Code `{exit_code}`)",
    ]
    if config_path:
        lines.append(f"- **Configuration**: `{config_path}`")
    lines.extend(
        [
            "",
            "### Diagnostic Error",
            "",
            "```text",
            error_message.strip(),
            "```",
            "",
            "**Result:** FAILED — Upstream Check could not complete execution due to the error above.",
            "",
            f"<!-- upstream-check-fingerprint:{fp} -->",
        ]
    )
    return "\n".join(lines)


def format_markdown_report(report: EngineReport) -> str:
    """Generate a clean Markdown report suitable for GitHub Actions workflow summaries and issue comments."""
    status_badge = "PASSED" if report.passed else "FAILED"
    lines: List[str] = [
        f"## Upstream Check Report — {status_badge}",
        "",
    ]

    for res in report.results:
        src_status = "Pass" if res.passed else "Fail"
        lines.append(f"### Source: `{res.source_name}` ({src_status})")
        lines.append(f"- **Endpoint**: `{res.endpoint}`")
        lines.append(f"- **Format**: `{res.format}` | **Rows**: `{res.row_count}`")
        lines.append("")
        lines.append("| Category | Status | Finding | Details |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for f in res.findings:
            icon = "✓ Pass" if f.passed else "✗ Fail"
            detail_str = "; ".join(f.details) if f.details else "—"
            lines.append(
                f"| {f.category.value} | {icon} | {f.title} | {detail_str} |"
            )
        lines.append("")

    total = report.total_failed_findings
    if report.passed:
        lines.append("**Result:** All upstream checks passed (0 findings require attention).")
    else:
        noun = "finding requires" if total == 1 else "findings require"
        lines.append(f"**Result:** FAILED — **{total}** {noun} attention.")
        fp = compute_incident_fingerprint(report)
        lines.append("")
        lines.append(f"<!-- upstream-check-fingerprint:{fp} -->")

    return "\n".join(lines)
