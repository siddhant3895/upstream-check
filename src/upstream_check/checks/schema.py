"""Schema change detection and baseline generation."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from upstream_check.config.models import SourceConfig
from upstream_check.core.models import (
    BaselineModel,
    CheckCategory,
    CheckFinding,
    ColumnBaseline,
    FetchedDataset,
    InferredType,
    Severity,
)
from upstream_check.core.types import (
    infer_column_type,
    is_missing,
    normalize_display_type,
    to_float,
    types_compatible,
)


def build_baseline(
    source: SourceConfig,
    dataset: FetchedDataset,
    captured_at: Optional[datetime] = None,
) -> BaselineModel:
    """Generate a deterministic BaselineModel snapshot from a fetched dataset."""
    now_iso = (captured_at or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    from_csv = source.format == "csv"
    total_rows = len(dataset.rows)
    columns: Dict[str, ColumnBaseline] = {}

    for col_name in dataset.headers:
        col_values = [row.get(col_name) for row in dataset.rows]
        null_count = sum(1 for v in col_values if is_missing(v))
        null_pct = (null_count / total_rows * 100.0) if total_rows > 0 else 0.0
        inferred = infer_column_type(col_values, from_csv=from_csv)

        min_val: Optional[float] = None
        max_val: Optional[float] = None
        if inferred in (InferredType.INTEGER, InferredType.NUMBER):
            numeric_vals = [
                f for f in (to_float(v) for v in col_values) if f is not None
            ]
            if numeric_vals:
                min_val = min(numeric_vals)
                max_val = max(numeric_vals)

        distinct_vals = {str(v).strip() for v in col_values if not is_missing(v)}

        columns[col_name] = ColumnBaseline(
            name=col_name,
            inferred_type=normalize_display_type(inferred.value),
            null_count=null_count,
            total_count=total_rows,
            null_pct=round(null_pct, 2),
            min_value=min_val,
            max_value=max_val,
            distinct_count=len(distinct_vals),
        )

    return BaselineModel(
        version=1,
        source_name=source.name,
        endpoint_redacted=dataset.redacted_endpoint,
        format=source.format,
        captured_at=now_iso,
        row_count=total_rows,
        column_order=list(dataset.headers),
        columns=columns,
    )


def _names_look_related(old_col: str, new_col: str) -> bool:
    """Check if two column names share tokens, prefixes, or substrings."""
    a = old_col.lower().strip()
    b = new_col.lower().strip()
    if a in b or b in a:
        return True
    tokens_a = {t for t in re.split(r"[^a-z0-9]+", a) if len(t) >= 2}
    tokens_b = {t for t in re.split(r"[^a-z0-9]+", b) if len(t) >= 2}
    return bool(tokens_a & tokens_b)


def _numeric_ranges_plausible(
    old_meta: Optional[ColumnBaseline], new_vals: Sequence[Any]
) -> bool:
    """Verify that a candidate renamed numeric column is within a plausible order of magnitude of the baseline."""
    if old_meta is None or old_meta.min_value is None or old_meta.max_value is None:
        return True
    nums = [f for f in (to_float(v) for v in new_vals) if f is not None]
    if not nums:
        return True
    new_min = min(nums)
    new_max = max(nums)
    old_min = old_meta.min_value
    old_max = old_meta.max_value

    # Allow generous drift (10x span or overlapping magnitudes), but reject e.g. [0.5, 0.8] vs [2500000, 12000000]
    old_abs_max = max(abs(old_min), abs(old_max), 1e-6)
    new_abs_max = max(abs(new_min), abs(new_max), 1e-6)
    ratio = max(old_abs_max, new_abs_max) / min(old_abs_max, new_abs_max)
    return ratio <= 100.0


def _detect_renamed_columns(
    missing_cols: Set[str],
    added_cols: Set[str],
    baseline: Optional[BaselineModel],
    dataset: FetchedDataset,
    from_csv: bool,
) -> Tuple[List[Tuple[str, str]], Set[str], Set[str]]:
    """Pair removed and added columns that represent a field rename without false-matching unrelated replacements."""
    if not missing_cols or not added_cols or baseline is None:
        return [], missing_cols, added_cols

    renames: List[Tuple[str, str]] = []
    remaining_missing = set(missing_cols)
    remaining_added = set(added_cols)

    header_index = {h: idx for idx, h in enumerate(dataset.headers)}
    base_index = {h: idx for idx, h in enumerate(baseline.column_order)}

    for old_col in sorted(missing_cols):
        old_meta = baseline.columns.get(old_col)
        old_type = old_meta.inferred_type if old_meta else None
        old_pos = base_index.get(old_col, -1)

        best_match: Optional[str] = None
        for new_col in sorted(remaining_added):
            new_vals = [r.get(new_col) for r in dataset.rows]
            new_type = normalize_display_type(
                infer_column_type(new_vals, from_csv=from_csv).value
            )
            new_pos = header_index.get(new_col, -2)
            type_ok = old_type == new_type or not dataset.rows
            if not type_ok:
                continue
            range_ok = _numeric_ranges_plausible(old_meta, new_vals)
            name_related = _names_look_related(old_col, new_col)
            if old_pos == new_pos and (range_ok or name_related):
                best_match = new_col
                break
        if (
            best_match is None
            and len(remaining_missing) == 1
            and len(remaining_added) == 1
        ):
            candidate = next(iter(remaining_added))
            cand_vals = [r.get(candidate) for r in dataset.rows]
            cand_type = normalize_display_type(
                infer_column_type(cand_vals, from_csv=from_csv).value
            )
            type_ok = old_type == cand_type or not dataset.rows
            range_ok = _numeric_ranges_plausible(old_meta, cand_vals)
            name_related = _names_look_related(old_col, candidate)
            if type_ok and (range_ok or name_related):
                best_match = candidate

        if best_match is not None:
            renames.append((old_col, best_match))
            remaining_missing.discard(old_col)
            remaining_added.discard(best_match)

    return renames, remaining_missing, remaining_added


def run_schema_checks(
    source: SourceConfig,
    dataset: FetchedDataset,
    baseline: Optional[BaselineModel] = None,
) -> List[CheckFinding]:
    """Validate dataset columns, empty/duplicate headers, ragged row widths, and types."""
    findings: List[CheckFinding] = []
    if not dataset.available or (not dataset.headers and not dataset.rows):
        return findings

    empty_header_positions = [
        idx + 1 for idx, h in enumerate(dataset.headers) if not h.strip()
    ]
    if empty_header_positions:
        pos_str = ", ".join(str(p) for p in empty_header_positions)
        findings.append(
            CheckFinding(
                category=CheckCategory.SCHEMA,
                passed=False,
                title=f"Empty CSV header column name at position(s): {pos_str}",
                details=["All CSV header columns must have non-empty names"],
                severity=Severity.CRITICAL,
            )
        )

    if dataset.duplicate_headers:
        dup_list = ", ".join(dataset.duplicate_headers)
        findings.append(
            CheckFinding(
                category=CheckCategory.SCHEMA,
                passed=False,
                title=f"Duplicate CSV header column(s) detected: {dup_list}",
                details=[
                    "Duplicate column headers cause later columns to overwrite earlier values"
                ],
                severity=Severity.CRITICAL,
            )
        )

    if dataset.malformed_rows:
        first_line, exp_w, act_w = dataset.malformed_rows[0]
        findings.append(
            CheckFinding(
                category=CheckCategory.SCHEMA,
                passed=False,
                title=(
                    f"Malformed CSV row width in {len(dataset.malformed_rows)} row(s)"
                ),
                details=[
                    f"First mismatch at line {first_line}: expected {exp_w} columns, received {act_w}"
                ],
                severity=Severity.CRITICAL,
            )
        )

    from_csv = source.format == "csv"
    actual_headers = {h for h in dataset.headers if h.strip()}

    configured_required = {
        col_name for col_name, rule in source.columns.items() if rule.required
    }
    explicitly_optional = {
        col_name for col_name, rule in source.columns.items() if not rule.required
    }
    baseline_headers = (
        (set(baseline.column_order) - explicitly_optional) if baseline else set()
    )
    all_expected_headers = configured_required | baseline_headers

    missing_cols = all_expected_headers - actual_headers
    added_cols = (actual_headers - set(baseline.column_order)) if baseline else set()

    renames, remaining_missing, remaining_added = _detect_renamed_columns(
        missing_cols=missing_cols,
        added_cols=added_cols,
        baseline=baseline,
        dataset=dataset,
        from_csv=from_csv,
    )

    for old_col, new_col in renames:
        findings.append(
            CheckFinding(
                category=CheckCategory.SCHEMA,
                passed=False,
                title=f"Column {old_col} renamed to {new_col}",
                details=[
                    f"Expected column: {old_col}",
                    f"Received column: {new_col}",
                ],
                severity=Severity.CRITICAL,
                column=old_col,
                expected=old_col,
                received=new_col,
            )
        )

    for col in sorted(remaining_missing):
        findings.append(
            CheckFinding(
                category=CheckCategory.SCHEMA,
                passed=False,
                title=f"Missing required column: {col}",
                details=[
                    "Column was present in schema contract/baseline but is missing from response"
                ],
                severity=Severity.CRITICAL,
                column=col,
            )
        )

    allow_extra = (
        source.schema_config.allow_extra_columns
        if source.schema_config is not None
        else False
    )
    if not allow_extra:
        for col in sorted(remaining_added):
            findings.append(
                CheckFinding(
                    category=CheckCategory.SCHEMA,
                    passed=False,
                    title=f"Unexpected new column: {col}",
                    details=["Column is not present in baseline schema"],
                    severity=Severity.CRITICAL,
                    column=col,
                )
            )

    if (
        not renames
        and not remaining_missing
        and not dataset.duplicate_headers
        and not dataset.malformed_rows
        and not empty_header_positions
    ):
        findings.append(
            CheckFinding(
                category=CheckCategory.SCHEMA,
                passed=True,
                title="Required columns present",
                severity=Severity.INFO,
            )
        )

    if not dataset.rows:
        return findings

    columns_to_check: Dict[str, str] = {}
    if baseline:
        for col_name, col_base in baseline.columns.items():
            columns_to_check[col_name] = col_base.inferred_type
    for col_name, col_rule in source.columns.items():
        if col_rule.type:
            columns_to_check[col_name] = col_rule.type

    checked_null_cols: Set[str] = set()
    for col_name, expected_type in columns_to_check.items():
        if col_name not in actual_headers:
            continue
        col_values = [row.get(col_name) for row in dataset.rows]
        inferred = infer_column_type(col_values, from_csv=from_csv)
        actual_display = normalize_display_type(inferred.value)
        expected_display = normalize_display_type(expected_type)

        if inferred == InferredType.NULL and expected_display != "null":
            if col_name in explicitly_optional:
                continue
            checked_null_cols.add(col_name)
            findings.append(
                CheckFinding(
                    category=CheckCategory.SCHEMA,
                    passed=False,
                    title=f"Column {col_name} contains only null values",
                    details=[
                        f"Expected type: {expected_display}",
                        "Received: 100% null (0 valid observations)",
                    ],
                    severity=Severity.CRITICAL,
                    column=col_name,
                    expected=expected_display,
                    received="null",
                )
            )
            continue

        if not types_compatible(expected_type, inferred.value, from_csv=from_csv):
            findings.append(
                CheckFinding(
                    category=CheckCategory.SCHEMA,
                    passed=False,
                    title=f"Column {col_name} changed type",
                    details=[
                        f"Expected: {expected_display}",
                        f"Received: {actual_display}",
                    ],
                    severity=Severity.CRITICAL,
                    column=col_name,
                    expected=expected_display,
                    received=actual_display,
                )
            )

    for col_name in sorted(configured_required):
        if col_name not in actual_headers or col_name in checked_null_cols:
            continue
        col_values = [row.get(col_name) for row in dataset.rows]
        if all(is_missing(v) for v in col_values):
            findings.append(
                CheckFinding(
                    category=CheckCategory.SCHEMA,
                    passed=False,
                    title=f"Required column {col_name} contains only null values",
                    details=["Received: 100% null (0 non-null observations)"],
                    severity=Severity.CRITICAL,
                    column=col_name,
                )
            )

    return findings
