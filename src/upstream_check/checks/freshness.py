"""Freshness monitoring: detect stale datasets, future-dated timestamps, and malformed timestamp ratios."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from upstream_check.config.models import SourceConfig
from upstream_check.core.models import (
    CheckCategory,
    CheckFinding,
    FetchedDataset,
    Severity,
)
from upstream_check.core.types import is_missing, parse_timestamp


def _format_hours(seconds: float) -> str:
    hours = seconds / 3600.0
    rounded = round(hours)
    if abs(hours - rounded) < 0.05:
        return f"{int(rounded)} hours"
    return f"{hours:.1f} hours"


def _format_pct(val: float) -> str:
    rounded = round(val, 1)
    if rounded.is_integer():
        return f"{int(rounded)}%"
    return f"{rounded}%"


def run_freshness_checks(
    source: SourceConfig,
    dataset: FetchedDataset,
    reference_time: Optional[datetime] = None,
) -> List[CheckFinding]:
    """Validate dataset freshness, future-clock-skew limits, and timestamp parse ratios."""
    findings: List[CheckFinding] = []
    if not dataset.available or not dataset.rows or source.freshness is None:
        return findings

    col_name = source.freshness.column
    parsed_dates: List[datetime] = []
    invalid_count = 0
    total_rows = len(dataset.rows)

    if col_name:
        if col_name not in dataset.headers:
            findings.append(
                CheckFinding(
                    category=CheckCategory.FRESHNESS,
                    passed=False,
                    title=f"Freshness column '{col_name}' missing from dataset",
                    severity=Severity.CRITICAL,
                    column=col_name,
                )
            )
            return findings

        for row in dataset.rows:
            raw_val = row.get(col_name)
            if is_missing(raw_val):
                invalid_count += 1
                continue
            dt = parse_timestamp(raw_val)
            if dt is not None:
                parsed_dates.append(dt)
            else:
                invalid_count += 1
    elif source.freshness.use_last_modified_fallback and dataset.last_modified:
        dt_header = parse_timestamp(dataset.last_modified)
        if dt_header is not None:
            parsed_dates.append(dt_header)

    if not parsed_dates:
        target_label = f"column '{col_name}'" if col_name else "Last-Modified header"
        findings.append(
            CheckFinding(
                category=CheckCategory.FRESHNESS,
                passed=False,
                title=f"No valid timestamps found in {target_label}",
                severity=Severity.CRITICAL,
                column=col_name,
            )
        )
        return findings

    # 1. Check malformed / missing timestamp ratio when evaluating a timestamp column
    if col_name and total_rows > 0:
        invalid_pct = (invalid_count / total_rows) * 100.0
        if invalid_pct > source.freshness.max_invalid_pct:
            findings.append(
                CheckFinding(
                    category=CheckCategory.FRESHNESS,
                    passed=False,
                    title=(
                        f"Freshness column '{col_name}' has {_format_pct(invalid_pct)} "
                        f"invalid or missing timestamps ({invalid_count}/{total_rows} rows)"
                    ),
                    details=[
                        f"Maximum allowed invalid timestamps: {_format_pct(source.freshness.max_invalid_pct)}"
                    ],
                    severity=Severity.CRITICAL,
                    column=col_name,
                )
            )

    latest_dt = max(parsed_dates)
    now = reference_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    delta_seconds = (now - latest_dt).total_seconds()
    max_skew_seconds = source.freshness.max_future_skew_seconds

    # 2. Detect future-dated timestamps beyond acceptable clock skew
    if delta_seconds < -max_skew_seconds:
        future_seconds = abs(delta_seconds)
        future_str = _format_hours(future_seconds)
        findings.append(
            CheckFinding(
                category=CheckCategory.FRESHNESS,
                passed=False,
                title=f"Timestamp in '{col_name or 'Last-Modified'}' is {future_str} in the future",
                details=[
                    f"Latest timestamp: {latest_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                    f"Reference time: {now.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                ],
                severity=Severity.CRITICAL,
                column=col_name,
            )
        )
        return findings

    age_seconds = max(0.0, delta_seconds)
    max_age_seconds = source.freshness.max_age_seconds

    actual_str = _format_hours(age_seconds)
    allowed_str = _format_hours(max_age_seconds)

    if age_seconds > max_age_seconds:
        findings.append(
            CheckFinding(
                category=CheckCategory.FRESHNESS,
                passed=False,
                title=f"Data is {actual_str} old",
                details=[f"Maximum allowed: {allowed_str}"],
                severity=Severity.CRITICAL,
                column=col_name,
                expected=f"<= {allowed_str}",
                received=actual_str,
            )
        )
    elif not findings:
        findings.append(
            CheckFinding(
                category=CheckCategory.FRESHNESS,
                passed=True,
                title=f"Data is fresh ({actual_str} old, limit {allowed_str})",
                severity=Severity.INFO,
                column=col_name,
            )
        )

    return findings
