"""Readable terminal reporter with optional ANSI/Rich styling and plain-text fidelity."""

from __future__ import annotations

from typing import List

from upstream_check.core.models import (
    CheckCategory,
    EngineReport,
    SourceCheckResult,
)


def _c(text: str, code: str, color: bool) -> str:
    if not color:
        return text
    return f"\033[{code}m{text}\033[0m"


def _format_single_source(result: SourceCheckResult, color: bool = False) -> List[str]:
    lines: List[str] = [
        f"{_c('Source:', '1', color)} {result.source_name}",
        f"{_c('Endpoint:', '1', color)} {result.endpoint}",
        "",
    ]

    categories = [
        CheckCategory.AVAILABILITY,
        CheckCategory.SCHEMA,
        CheckCategory.QUALITY,
        CheckCategory.FRESHNESS,
    ]

    for cat in categories:
        cat_findings = [f for f in result.findings if f.category == cat]
        if not cat_findings:
            continue
        lines.append(_c(cat.value, "1;36", color))
        for finding in cat_findings:
            if finding.passed:
                symbol = _c("✓", "1;32", color)
                title = finding.title
            else:
                symbol = _c("✗", "1;31", color)
                title = _c(finding.title, "1;31", color)
            lines.append(f"  {symbol} {title}")
            for detail in finding.details:
                lines.append(f"    {_c(detail, '2', color)}")
        lines.append("")

    return lines


def format_terminal_report(report: EngineReport, color: bool = False) -> str:
    """Format an EngineReport for terminal display."""
    lines: List[str] = [_c("UPSTREAM CHECK", "1;37", color), ""]

    for idx, res in enumerate(report.results):
        if idx > 0:
            lines.append("================================")
            lines.append("")
        lines.extend(_format_single_source(res, color=color))

    lines.append("--------------------------------")
    total_failures = report.total_failed_findings
    if report.passed:
        lines.append(_c("RESULT: PASSED", "1;32", color))
        lines.append("0 findings require attention.")
    else:
        lines.append(_c("RESULT: FAILED", "1;31", color))
        noun = "finding requires" if total_failures == 1 else "findings require"
        lines.append(f"{total_failures} {noun} attention.")

    return "\n".join(lines)
