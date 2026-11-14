"""Strict Pydantic configuration models rejecting unknown keys, unresolved env vars, NaN/inf, and path traversal."""

from __future__ import annotations

import math
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import yaml
from pydantic import BaseModel, Field

from upstream_check.core.types import (
    expand_env_vars,
    parse_duration_seconds,
    resolve_source_target,
    safe_read_regular_file_bytes,
    validate_source_name,
)

VALID_COLUMN_TYPES = {
    "string",
    "str",
    "text",
    "number",
    "float",
    "numeric",
    "integer",
    "int",
    "boolean",
    "bool",
    "datetime",
    "timestamp",
    "date",
    "object",
    "array",
}


def _check_unknown_fields(cls_name: str, data: Dict[str, Any], allowed: Set[str]) -> None:
    unknown = set(data.keys()) - allowed
    if unknown:
        unk_str = ", ".join(sorted(unknown))
        raise ValueError(
            f"Unknown configuration field(s) in {cls_name}: {unk_str}. "
            f"Allowed fields: {sorted(allowed)}"
        )


def _reject_bool_for_numeric(cls_name: str, data: Dict[str, Any], numeric_keys: Set[str]) -> None:
    for k in numeric_keys:
        if k in data and isinstance(data[k], bool):
            raise ValueError(
                f"{cls_name}.{k} must be a number, not a boolean (got {data[k]})."
            )


def _check_finite(name: str, val: Optional[float]) -> None:
    if val is not None and not math.isfinite(float(val)):
        raise ValueError(f"{name} must be a finite number (got {val}).")


def _check_pct(name: str, val: Optional[float]) -> None:
    if val is not None:
        _check_finite(name, val)
        if val < 0.0 or val > 100.0:
            raise ValueError(f"{name} must be between 0 and 100 (got {val}).")


def _validate_env_placeholders(field_name: str, value: str) -> None:
    """Validate ${ENV_VAR} syntax and ensure any referenced environment variable is set."""
    if not isinstance(value, str):
        return
    if "${}" in value:
        raise ValueError(f"Empty environment variable placeholder '${{}}' in {field_name}.")
    expand_env_vars(value)


class FreshnessConfig(BaseModel):
    """Freshness threshold rules for a timestamp column or HTTP Last-Modified header."""

    column: Optional[str] = None
    max_age: str = "24h"
    max_future_skew: str = "5m"
    max_invalid_pct: float = 0.0
    use_last_modified_fallback: bool = True

    def __init__(self, **data: Any) -> None:
        _check_unknown_fields(
            "FreshnessConfig",
            data,
            {
                "column",
                "max_age",
                "max_future_skew",
                "max_invalid_pct",
                "use_last_modified_fallback",
            },
        )
        _reject_bool_for_numeric("FreshnessConfig", data, {"max_invalid_pct"})
        super().__init__(**data)
        if self.column is not None and not self.column.strip():
            raise ValueError("freshness.column cannot be an empty string.")
        seconds = parse_duration_seconds(self.max_age)
        if seconds <= 0:
            raise ValueError("freshness.max_age must be greater than 0")
        skew_seconds = parse_duration_seconds(self.max_future_skew)
        if skew_seconds < 0:
            raise ValueError("freshness.max_future_skew must be >= 0")
        _check_pct("freshness.max_invalid_pct", self.max_invalid_pct)

    @property
    def max_age_seconds(self) -> float:
        return parse_duration_seconds(self.max_age)

    @property
    def max_future_skew_seconds(self) -> float:
        return parse_duration_seconds(self.max_future_skew)


class SchemaConfig(BaseModel):
    """Schema validation and baseline path configuration."""

    baseline: Optional[str] = None
    allow_extra_columns: bool = False

    def __init__(self, **data: Any) -> None:
        _check_unknown_fields(
            "SchemaConfig", data, {"baseline", "allow_extra_columns"}
        )
        super().__init__(**data)
        if self.baseline is not None:
            if not self.baseline.strip():
                raise ValueError("schema.baseline cannot be an empty string.")
            _validate_env_placeholders("schema.baseline", self.baseline)


class ColumnRuleConfig(BaseModel):
    """Per-column validation contract."""

    required: bool = True
    type: Optional[str] = None
    min: Optional[float] = None
    max: Optional[float] = None
    max_null_pct: Optional[float] = None
    allowed_values: Optional[List[Any]] = None

    def __init__(self, **data: Any) -> None:
        _check_unknown_fields(
            "ColumnRuleConfig",
            data,
            {"required", "type", "min", "max", "max_null_pct", "allowed_values"},
        )
        _reject_bool_for_numeric(
            "ColumnRuleConfig", data, {"min", "max", "max_null_pct"}
        )
        if "type" in data and data["type"] is not None:
            raw_t = str(data["type"]).lower().strip()
            if raw_t not in VALID_COLUMN_TYPES:
                raise ValueError(
                    f"Unsupported column type '{data['type']}'. Supported: {sorted(VALID_COLUMN_TYPES)}"
                )
            data["type"] = raw_t
        super().__init__(**data)
        _check_finite("column.min", self.min)
        _check_finite("column.max", self.max)
        _check_pct("column.max_null_pct", self.max_null_pct)
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(
                f"column.min ({self.min}) cannot exceed column.max ({self.max})."
            )
        if self.allowed_values is not None and len(self.allowed_values) == 0:
            raise ValueError("column.allowed_values cannot be an empty list.")


class QualityConfig(BaseModel):
    """Dataset-level data quality validation thresholds."""

    max_null_pct: Optional[float] = None
    max_null_spike_pct: float = 20.0
    max_row_drop_pct: Optional[float] = 50.0
    unique: List[str] = Field(default_factory=list)
    min_rows: int = 1
    max_rows: Optional[int] = None

    def __init__(self, **data: Any) -> None:
        _check_unknown_fields(
            "QualityConfig",
            data,
            {
                "max_null_pct",
                "max_null_spike_pct",
                "max_row_drop_pct",
                "unique",
                "min_rows",
                "max_rows",
            },
        )
        _reject_bool_for_numeric(
            "QualityConfig",
            data,
            {
                "max_null_pct",
                "max_null_spike_pct",
                "max_row_drop_pct",
                "min_rows",
                "max_rows",
            },
        )
        super().__init__(**data)
        _check_pct("quality.max_null_pct", self.max_null_pct)
        _check_pct("quality.max_null_spike_pct", self.max_null_spike_pct)
        _check_pct("quality.max_row_drop_pct", self.max_row_drop_pct)
        for u_col in self.unique:
            if not isinstance(u_col, str) or not u_col.strip():
                raise ValueError(
                    "quality.unique entries must be non-empty column names."
                )
        if len(set(self.unique)) != len(self.unique):
            raise ValueError("quality.unique contains duplicate column names.")
        if self.min_rows < 0:
            raise ValueError(
                f"quality.min_rows must be >= 0 (got {self.min_rows})."
            )
        if self.max_rows is not None:
            if self.max_rows < 0:
                raise ValueError(
                    f"quality.max_rows must be >= 0 (got {self.max_rows})."
                )
            if self.min_rows > self.max_rows:
                raise ValueError(
                    f"quality.min_rows ({self.min_rows}) cannot exceed quality.max_rows ({self.max_rows})."
                )


class SourceConfig(BaseModel):
    """Single external data source definition."""

    name: str
    url: str
    format: str = "csv"
    delimiter: Optional[str] = None
    flatten_json: bool = True
    retries: int = 2
    retry_backoff_seconds: float = 0.25
    max_response_bytes: int = 52_428_800  # 50 MB default cap
    headers: Dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = 15.0
    json_records_path: Optional[str] = None
    freshness: Optional[FreshnessConfig] = None
    schema_config: Optional[SchemaConfig] = Field(default=None)
    columns: Dict[str, ColumnRuleConfig] = Field(default_factory=dict)
    quality: Optional[QualityConfig] = None

    def __init__(self, **data: Any) -> None:
        _check_unknown_fields(
            "SourceConfig",
            data,
            {
                "name",
                "url",
                "format",
                "delimiter",
                "flatten_json",
                "retries",
                "retry_backoff_seconds",
                "max_response_bytes",
                "headers",
                "timeout_seconds",
                "json_records_path",
                "freshness",
                "schema",
                "schema_config",
                "columns",
                "quality",
            },
        )
        _reject_bool_for_numeric(
            "SourceConfig",
            data,
            {
                "retries",
                "retry_backoff_seconds",
                "max_response_bytes",
                "timeout_seconds",
            },
        )
        if "schema" in data and "schema_config" not in data:
            data["schema_config"] = data.pop("schema")
        if "name" in data and data["name"] is not None:
            data["name"] = validate_source_name(str(data["name"]))
        if "format" in data and data["format"] is not None:
            fmt = str(data["format"]).lower().strip()
            if fmt not in ("csv", "json"):
                raise ValueError(
                    f"Unsupported format '{data['format']}'. Expected 'csv' or 'json'."
                )
            data["format"] = fmt
        super().__init__(**data)
        if not self.url or not self.url.strip():
            raise ValueError("source.url cannot be empty.")
        _validate_env_placeholders("source.url", self.url)
        resolve_source_target(self.url)
        for hk, hv in self.headers.items():
            _validate_env_placeholders(f"source.headers.{hk}", str(hv))
        _check_finite("source.retry_backoff_seconds", self.retry_backoff_seconds)
        _check_finite("source.timeout_seconds", self.timeout_seconds)
        if self.retries < 0 or self.retries > 10:
            raise ValueError(
                f"source.retries must be between 0 and 10 (got {self.retries})."
            )
        if self.retry_backoff_seconds < 0:
            raise ValueError("source.retry_backoff_seconds must be >= 0.")
        if self.timeout_seconds <= 0:
            raise ValueError("source.timeout_seconds must be > 0.")
        if self.max_response_bytes <= 0:
            raise ValueError("source.max_response_bytes must be > 0.")


class UpstreamCheckConfig(BaseModel):
    """Root configuration schema for upstream-check.yaml."""

    version: int = 1
    sources: List[SourceConfig] = Field(default_factory=list)

    def __init__(self, **data: Any) -> None:
        _check_unknown_fields(
            "UpstreamCheckConfig", data, {"version", "sources"}
        )
        _reject_bool_for_numeric("UpstreamCheckConfig", data, {"version"})
        super().__init__(**data)
        if self.version != 1:
            raise ValueError(
                f"Unsupported configuration version '{self.version}'. Expected '1'."
            )
        if not self.sources:
            raise ValueError(
                "Configuration must define at least one source in 'sources'."
            )
        seen = set()
        for src in self.sources:
            if src.name in seen:
                raise ValueError(
                    f"Duplicate source name '{src.name}' in configuration."
                )
            seen.add(src.name)


def load_config(path: Union[str, Path]) -> UpstreamCheckConfig:
    """Load and validate an Upstream Check YAML configuration file without blocking on FIFOs."""
    cfg_path = Path(path)
    raw_bytes, _ = safe_read_regular_file_bytes(
        cfg_path, max_bytes=10_485_760, label="configuration file"
    )
    raw_text = raw_bytes.decode("utf-8")
    try:
        parsed = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML syntax in {cfg_path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"Configuration file {cfg_path} must contain a YAML mapping.")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if hasattr(UpstreamCheckConfig, "model_validate"):
            return UpstreamCheckConfig.model_validate(parsed)
        return UpstreamCheckConfig.parse_obj(parsed)


def dump_config_yaml(config_dict: Dict[str, Any]) -> str:
    """Serialize a configuration dictionary into clean, human-readable YAML."""
    return yaml.safe_dump(config_dict, sort_keys=False, default_flow_style=False)
