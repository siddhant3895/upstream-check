"""Data quality validation: missing value rates, baseline null spikes, row-drop alerts, duplicates, and ranges."""

from __future__ import annotations

import json
from typing import Any, List, Optional, Set, Tuple

from upstream_check.config.models import SourceConfig
from upstream_check.core.models import (
    BaselineModel,
    CheckCategory,
    CheckFinding,
    FetchedDataset,
    InferredType,
    Severity,
)
from upstream_check.core.types import (
    infer_column_type,
    is_missing,
    to_float,
    types_compatible,
)


def _format_pct(val: float) -> str:
    rounded = round(val, 1)
    if rounded.is_integer():
        return f"{int(rounded)}%"
    return f"{rounded}%"


def _hashable_cell(val: Any) -> Any:
    if isinstance(val, (dict, list)):
        return json.dumps(val, sort_keys=True, default=str)
    return val


def run_quality_checks(
    source: SourceConfig,
    dataset: FetchedDataset,
    baseline: Optional[BaselineModel] = None,
) -> List[CheckFinding]:
    """Check missing value rates, null spikes, uniqueness, row counts/drops, and numeric bounds."""
    findings: List[CheckFinding] = []
    if not dataset.available:
        return findings

    total_rows = len(dataset.rows)
    quality_cfg = source.quality
    max_null_pct = quality_cfg.max_null_pct if quality_cfg else None
    max_spike_pct = quality_cfg.max_null_spike_pct if quality_cfg else 20.0
    max_row_drop_pct = quality_cfg.max_row_drop_pct if quality_cfg else 50.0
    from_csv = source.format == "csv"

    # 1. Per-cell checks (only when rows are present)
    if total_rows > 0:
        null_violations: List[Tuple[str, float, List[str]]] = []
        for col_name in dataset.headers:
            values = [row.get(col_name) for row in dataset.rows]
            null_count = sum(1 for v in values if is_missing(v))
            null_pct = (null_count / total_rows * 100.0) if total_rows > 0 else 0.0

            col_rule = source.columns.get(col_name)
            col_max_null = (
                col_rule.max_null_pct
                if (col_rule and col_rule.max_null_pct is not None)
                else max_null_pct
            )
            base_col = baseline.columns.get(col_name) if baseline else None
            base_null_pct = base_col.null_pct if base_col is not None else None

            exceeded_max = col_max_null is not None and null_pct > col_max_null
            exceeded_spike = (
                base_null_pct is not None
                and (null_pct - base_null_pct) > max_spike_pct
            )

            if exceeded_max or exceeded_spike:
                details: List[str] = []
                if base_null_pct is not None:
                    details.append(f"Previous baseline: {_format_pct(base_null_pct)}")
                elif col_max_null is not None:
                    details.append(f"Maximum allowed: {_format_pct(col_max_null)}")
                null_violations.append((col_name, null_pct, details))

        for col_name, null_pct, details in null_violations:
            if len(null_violations) == 1:
                title = f"Missing values: {_format_pct(null_pct)}"
            else:
                title = f"Missing values in {col_name}: {_format_pct(null_pct)}"
            findings.append(
                CheckFinding(
                    category=CheckCategory.QUALITY,
                    passed=False,
                    title=title,
                    details=details,
                    severity=Severity.CRITICAL,
                    column=col_name,
                )
            )

        # 2. Numerical range and allowed_values validation per column
        for col_name, col_rule in source.columns.items():
            if col_name not in dataset.headers:
                continue
            if col_rule.min is not None or col_rule.max is not None:
                col_values = [row.get(col_name) for row in dataset.rows]
                inferred = infer_column_type(col_values, from_csv=from_csv)

                expected_type = col_rule.type
                if not expected_type and baseline and col_name in baseline.columns:
                    expected_type = baseline.columns[col_name].inferred_type
                already_flagged_schema_type = bool(
                    expected_type
                    and inferred != InferredType.NULL
                    and not types_compatible(
                        expected_type, inferred.value, from_csv=from_csv
                    )
                )

                out_of_range: List[Tuple[int, float]] = []
                non_numeric: List[Tuple[int, Any]] = []
                for idx, row in enumerate(dataset.rows):
                    raw_val = row.get(col_name)
                    if is_missing(raw_val):
                        continue
                    num = to_float(raw_val)
                    if num is None:
                        non_numeric.append((idx + 1, raw_val))
                        continue
                    if col_rule.min is not None and num < col_rule.min:
                        out_of_range.append((idx + 1, num))
                    elif col_rule.max is not None and num > col_rule.max:
                        out_of_range.append((idx + 1, num))

                if non_numeric and not already_flagged_schema_type:
                    sample_row, sample_val = non_numeric[0]
                    findings.append(
                        CheckFinding(
                            category=CheckCategory.QUALITY,
                            passed=False,
                            title=(
                                f"Column {col_name} has {len(non_numeric)} "
                                "non-numeric value(s) violating numeric bounds"
                            ),
                            details=[
                                f"First non-numeric value at row {sample_row}: {sample_val!r}"
                            ],
                            severity=Severity.CRITICAL,
                            column=col_name,
                        )
                    )

                if out_of_range:
                    sample_row, sample_val = out_of_range[0]
                    low = col_rule.min if col_rule.min is not None else "-inf"
                    high = col_rule.max if col_rule.max is not None else "inf"
                    findings.append(
                        CheckFinding(
                            category=CheckCategory.QUALITY,
                            passed=False,
                            title=(
                                f"Column {col_name} has {len(out_of_range)} "
                                "value(s) outside allowed range"
                            ),
                            details=[
                                f"Allowed range: [{low}, {high}]",
                                f"First violation at row {sample_row}: {sample_val}",
                            ],
                            severity=Severity.CRITICAL,
                            column=col_name,
                        )
                    )

            if col_rule.allowed_values is not None:
                allowed_set = {str(v).strip() for v in col_rule.allowed_values}
                invalid_vals: List[Tuple[int, Any]] = []
                for idx, row in enumerate(dataset.rows):
                    val = row.get(col_name)
                    if is_missing(val):
                        continue
                    if str(val).strip() not in allowed_set:
                        invalid_vals.append((idx + 1, val))
                if invalid_vals:
                    sample_row, sample_val = invalid_vals[0]
                    findings.append(
                        CheckFinding(
                            category=CheckCategory.QUALITY,
                            passed=False,
                            title=(
                                f"Column {col_name} has {len(invalid_vals)} "
                                "disallowed value(s)"
                            ),
                            details=[
                                f"Allowed values: {col_rule.allowed_values}",
                                f"First violation at row {sample_row}: {sample_val}",
                            ],
                            severity=Severity.CRITICAL,
                            column=col_name,
                        )
                    )

        # 3. Duplicate key detection
        if quality_cfg and quality_cfg.unique:
            missing_unique = [
                c for c in quality_cfg.unique if c not in dataset.headers
            ]
            if missing_unique:
                missing_label = ", ".join(missing_unique)
                findings.append(
                    CheckFinding(
                        category=CheckCategory.QUALITY,
                        passed=False,
                        title=f"Unique key column(s) missing from dataset: {missing_label}",
                        severity=Severity.CRITICAL,
                    )
                )
            else:
                seen_keys: Set[Tuple[Any, ...]] = set()
                duplicate_count = 0
                for row in dataset.rows:
                    raw_vals = [row.get(c) for c in quality_cfg.unique]
                    if any(is_missing(k) for k in raw_vals):
                        continue
                    key = tuple(_hashable_cell(k) for k in raw_vals)
                    if key in seen_keys:
                        duplicate_count += 1
                    else:
                        seen_keys.add(key)
                if duplicate_count > 0:
                    key_label = ", ".join(quality_cfg.unique)
                    findings.append(
                        CheckFinding(
                            category=CheckCategory.QUALITY,
                            passed=False,
                            title=f"Duplicate records detected: {duplicate_count}",
                            details=[f"Unique key columns: ({key_label})"],
                            severity=Severity.CRITICAL,
                        )
                    )

    # 4. Row count bounds & baseline row-count drop detection (runs even when total_rows == 0)
    if quality_cfg:
        if total_rows < quality_cfg.min_rows:
            findings.append(
                CheckFinding(
                    category=CheckCategory.QUALITY,
                    passed=False,
                    title=f"Row count below minimum: {total_rows}",
                    details=[f"Minimum required: {quality_cfg.min_rows}"],
                    severity=Severity.CRITICAL,
                )
            )
        if quality_cfg.max_rows is not None and total_rows > quality_cfg.max_rows:
            findings.append(
                CheckFinding(
                    category=CheckCategory.QUALITY,
                    passed=False,
                    title=f"Row count exceeds maximum: {total_rows}",
                    details=[f"Maximum allowed: {quality_cfg.max_rows}"],
                    severity=Severity.CRITICAL,
                )
            )

    if (
        baseline is not None
        and baseline.row_count > 0
        and max_row_drop_pct is not None
    ):
        drop_pct = (baseline.row_count - total_rows) / baseline.row_count * 100.0
        if drop_pct > max_row_drop_pct:
            findings.append(
                CheckFinding(
                    category=CheckCategory.QUALITY,
                    passed=False,
                    title=(
                        f"Row count dropped by {_format_pct(drop_pct)} "
                        f"({total_rows} vs {baseline.row_count})"
                    ),
                    details=[
                        f"Baseline row count: {baseline.row_count}",
                        f"Maximum allowed drop: {_format_pct(max_row_drop_pct)}",
                    ],
                    severity=Severity.CRITICAL,
                )
            )

    if not findings and total_rows > 0:
        findings.append(
            CheckFinding(
                category=CheckCategory.QUALITY,
                passed=True,
                title="All data quality checks passed",
                severity=Severity.INFO,
            )
        )

    return findings
