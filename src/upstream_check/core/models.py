"""Core domain models for Upstream Check with strict baseline integrity validation and RFC 8259 JSON parsing."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import math
from typing import Any, Dict, List, Optional, Set, Tuple


class InferredType(str, Enum):
    """Supported inferred column types."""

    STRING = "string"
    NUMBER = "number"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    OBJECT = "object"
    ARRAY = "array"
    NULL = "null"


VALID_BASELINE_TYPES = {t.value for t in InferredType}
ALLOWED_BASELINE_ROOT_KEYS = {
    "version",
    "source_name",
    "endpoint",
    "format",
    "captured_at",
    "row_count",
    "column_order",
    "columns",
}
ALLOWED_COLUMN_BASELINE_KEYS = {
    "name",
    "inferred_type",
    "null_count",
    "total_count",
    "null_pct",
    "min_value",
    "max_value",
    "distinct_count",
}


class CheckCategory(str, Enum):
    """Core capability categories."""

    AVAILABILITY = "SOURCE AVAILABILITY"
    SCHEMA = "SCHEMA VALIDATION"
    QUALITY = "DATA QUALITY"
    FRESHNESS = "FRESHNESS"


class Severity(str, Enum):
    """Finding severity level."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class FetchedDataset:
    """Normalized tabular representation of a fetched JSON or CSV source."""

    source_name: str
    endpoint: str
    redacted_endpoint: str
    available: bool
    status_code: Optional[int] = None
    latency_ms: float = 0.0
    content_type: Optional[str] = None
    last_modified: Optional[str] = None
    error_message: Optional[str] = None
    headers: List[str] = field(default_factory=list)
    duplicate_headers: List[str] = field(default_factory=list)
    malformed_rows: List[Tuple[int, int, int]] = field(default_factory=list)
    rows: List[Dict[str, Any]] = field(default_factory=list)
    raw_byte_size: int = 0


@dataclass
class CheckFinding:
    """Single explainable check result item."""

    category: CheckCategory
    passed: bool
    title: str
    details: List[str] = field(default_factory=list)
    severity: Severity = Severity.CRITICAL
    column: Optional[str] = None
    expected: Optional[str] = None
    received: Optional[str] = None


def reject_nonstandard_json_constant(token: str) -> Any:
    """Reject NaN, Infinity, and -Infinity tokens prohibited by RFC 8259."""
    raise ValueError(
        f"Non-standard JSON constant '{token}' is not valid RFC 8259 JSON"
    )


def _reject_unknown_keys(
    scope: str, data: Dict[str, Any], allowed: Set[str]
) -> None:
    unknown = set(data.keys()) - allowed
    if unknown:
        unk_list = ", ".join(sorted(unknown))
        raise ValueError(
            f"Unknown field(s) in {scope}: {unk_list}. Allowed: {sorted(allowed)}"
        )


def _require_int(field_name: str, val: Any, min_val: int = 0) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(
            f"Baseline field '{field_name}' must be an integer (got {val!r})."
        )
    if val < min_val:
        raise ValueError(
            f"Baseline field '{field_name}' must be >= {min_val} (got {val})."
        )
    return val


def _require_finite_float(field_name: str, val: Any) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(
            f"Baseline field '{field_name}' must be a number (got {val!r})."
        )
    try:
        fval = float(val)
    except OverflowError as exc:
        raise ValueError(
            f"Baseline field '{field_name}' overflowed float range."
        ) from exc
    if not math.isfinite(fval):
        raise ValueError(
            f"Baseline field '{field_name}' must be finite (got {val})."
        )
    return fval


def parse_strict_json_object(raw_text: str, label: str = "JSON") -> Dict[str, Any]:
    """Parse a JSON object while rejecting duplicate keys and non-standard constants (NaN/Infinity)."""

    def _no_dup_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        obj: Dict[str, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError(f"Duplicate key '{k}' in {label}")
            obj[k] = v
        return obj

    parsed = json.loads(
        raw_text,
        object_pairs_hook=_no_dup_pairs,
        parse_constant=reject_nonstandard_json_constant,
    )
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} root must be a JSON object.")
    return parsed


@dataclass
class ColumnBaseline:
    """Recorded baseline profile for a single column/field."""

    name: str
    inferred_type: str
    null_count: int
    total_count: int
    null_pct: float
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    distinct_count: int = 0


@dataclass
class BaselineModel:
    """Reproducible baseline snapshot for an external data source."""

    version: int
    source_name: str
    endpoint_redacted: str
    format: str
    captured_at: str
    row_count: int
    column_order: List[str]
    columns: Dict[str, ColumnBaseline]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "source_name": self.source_name,
            "endpoint": self.endpoint_redacted,
            "format": self.format,
            "captured_at": self.captured_at,
            "row_count": self.row_count,
            "column_order": list(self.column_order),
            "columns": {
                col_name: {
                    "name": col.name,
                    "inferred_type": col.inferred_type,
                    "null_count": col.null_count,
                    "total_count": col.total_count,
                    "null_pct": round(col.null_pct, 2),
                    "min_value": col.min_value,
                    "max_value": col.max_value,
                    "distinct_count": col.distinct_count,
                }
                for col_name, col in self.columns.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineModel":
        """Parse and strictly validate a baseline dictionary."""
        if not isinstance(data, dict):
            raise ValueError("Baseline payload must be a JSON object.")
        _reject_unknown_keys("BaselineModel", data, ALLOWED_BASELINE_ROOT_KEYS)

        version = _require_int("version", data.get("version"), min_val=1)
        if version != 1:
            raise ValueError(
                f"Unsupported baseline version '{version}'. Expected '1'."
            )

        source_name = data.get("source_name")
        if not isinstance(source_name, str) or not source_name.strip():
            raise ValueError("Baseline 'source_name' must be a non-empty string.")

        fmt = data.get("format")
        if not isinstance(fmt, str) or fmt.lower().strip() not in ("csv", "json"):
            raise ValueError(
                f"Invalid baseline format '{fmt}'. Expected 'csv' or 'json'."
            )
        fmt = fmt.lower().strip()

        row_count = _require_int("row_count", data.get("row_count"), min_val=0)

        raw_columns = data.get("columns")
        if not isinstance(raw_columns, dict) or not raw_columns:
            raise ValueError("Baseline 'columns' must be a non-empty object.")

        raw_order = data.get("column_order")
        if raw_order is None:
            column_order = list(raw_columns.keys())
        else:
            if not isinstance(raw_order, list) or not raw_order:
                raise ValueError("Baseline 'column_order' must be a non-empty list.")
            if any(not isinstance(c, str) or not c.strip() for c in raw_order):
                raise ValueError(
                    "Baseline 'column_order' entries must be non-empty strings."
                )
            if len(set(raw_order)) != len(raw_order):
                raise ValueError("Baseline 'column_order' contains duplicate columns.")
            column_order = list(raw_order)

        if set(column_order) != set(raw_columns.keys()):
            missing_profiles = sorted(set(column_order) - set(raw_columns.keys()))
            extra_profiles = sorted(set(raw_columns.keys()) - set(column_order))
            raise ValueError(
                f"Baseline 'column_order' and 'columns' keys do not match "
                f"(missing profiles: {missing_profiles}, extra profiles: {extra_profiles})."
            )

        cols: Dict[str, ColumnBaseline] = {}
        for col_name, col_data in raw_columns.items():
            if not isinstance(col_name, str) or not col_name.strip():
                raise ValueError("Baseline column key must be a non-empty string.")
            if not isinstance(col_data, dict):
                raise ValueError(
                    f"Baseline profile for column '{col_name}' must be an object."
                )
            _reject_unknown_keys(
                f"columns.{col_name}", col_data, ALLOWED_COLUMN_BASELINE_KEYS
            )
            rec_name = col_data.get("name", col_name)
            if rec_name != col_name:
                raise ValueError(
                    f"Baseline column '{col_name}' has mismatched internal name '{rec_name}'."
                )

            inf_type = col_data.get("inferred_type")
            if (
                not isinstance(inf_type, str)
                or inf_type.lower().strip() not in VALID_BASELINE_TYPES
            ):
                raise ValueError(
                    f"Invalid inferred_type '{inf_type}' for column '{col_name}'."
                )
            inf_type = inf_type.lower().strip()

            null_count = _require_int(
                f"columns.{col_name}.null_count", col_data.get("null_count", 0), 0
            )
            total_count = _require_int(
                f"columns.{col_name}.total_count",
                col_data.get("total_count", row_count),
                0,
            )
            if total_count != row_count:
                raise ValueError(
                    f"Column '{col_name}' total_count ({total_count}) does not match "
                    f"baseline row_count ({row_count})."
                )
            if null_count > total_count:
                raise ValueError(
                    f"Column '{col_name}' null_count ({null_count}) exceeds "
                    f"total_count ({total_count})."
                )

            non_null_count = total_count - null_count
            null_pct = _require_finite_float(
                f"columns.{col_name}.null_pct", col_data.get("null_pct", 0.0)
            )
            if null_pct < 0.0 or null_pct > 100.0:
                raise ValueError(
                    f"Column '{col_name}' null_pct must be between 0 and 100 (got {null_pct})."
                )
            if total_count > 0:
                expected_pct = (null_count / total_count) * 100.0
                if abs(null_pct - expected_pct) > 1.0:
                    raise ValueError(
                        f"Column '{col_name}' null_pct ({null_pct}%) is inconsistent with "
                        f"null_count/total_count ({null_count}/{total_count} = {expected_pct:.2f}%)."
                    )

            raw_min = col_data.get("min_value")
            raw_max = col_data.get("max_value")
            min_val = (
                _require_finite_float(f"columns.{col_name}.min_value", raw_min)
                if raw_min is not None
                else None
            )
            max_val = (
                _require_finite_float(f"columns.{col_name}.max_value", raw_max)
                if raw_max is not None
                else None
            )
            if (min_val is None) != (max_val is None):
                raise ValueError(
                    f"Column '{col_name}' must specify both min_value and max_value or neither."
                )
            if min_val is not None and max_val is not None:
                if inf_type not in ("number", "integer"):
                    raise ValueError(
                        f"Non-numeric column '{col_name}' ({inf_type}) cannot have numeric min/max."
                    )
                if non_null_count == 0:
                    raise ValueError(
                        f"100%-null column '{col_name}' cannot have non-null min_value/max_value."
                    )
                if min_val > max_val:
                    raise ValueError(
                        f"Column '{col_name}' min_value ({min_val}) exceeds max_value ({max_val})."
                    )

            distinct_count = _require_int(
                f"columns.{col_name}.distinct_count",
                col_data.get("distinct_count", 0),
                0,
            )
            if distinct_count > non_null_count:
                raise ValueError(
                    f"Column '{col_name}' distinct_count ({distinct_count}) exceeds "
                    f"non-null row count ({non_null_count})."
                )

            cols[col_name] = ColumnBaseline(
                name=col_name,
                inferred_type=inf_type,
                null_count=null_count,
                total_count=total_count,
                null_pct=null_pct,
                min_value=min_val,
                max_value=max_val,
                distinct_count=distinct_count,
            )

        return cls(
            version=version,
            source_name=source_name.strip(),
            endpoint_redacted=str(data.get("endpoint", "")),
            format=fmt,
            captured_at=str(data.get("captured_at", "")),
            row_count=row_count,
            column_order=column_order,
            columns=cols,
        )


@dataclass
class SourceCheckResult:
    """Aggregated validation results for a single configured source."""

    source_name: str
    endpoint: str
    format: str
    findings: List[CheckFinding] = field(default_factory=list)
    row_count: int = 0
    latency_ms: float = 0.0

    @property
    def failed_findings(self) -> List[CheckFinding]:
        return [
            f
            for f in self.findings
            if not f.passed and f.severity == Severity.CRITICAL
        ]

    @property
    def warning_findings(self) -> List[CheckFinding]:
        return [
            f
            for f in self.findings
            if not f.passed and f.severity == Severity.WARNING
        ]

    @property
    def passed(self) -> bool:
        return len(self.failed_findings) == 0


@dataclass
class EngineReport:
    """Complete execution report across all configured sources."""

    results: List[SourceCheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(r.passed for r in self.results)

    @property
    def total_failed_findings(self) -> int:
        return sum(len(r.failed_findings) for r in self.results)
