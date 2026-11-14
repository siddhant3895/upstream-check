"""Orchestration engine for Upstream Check with canonical local-source resolution and baseline collision checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

import httpx

from upstream_check.checks.availability import run_availability_checks
from upstream_check.checks.freshness import run_freshness_checks
from upstream_check.checks.quality import run_quality_checks
from upstream_check.checks.schema import build_baseline, run_schema_checks
from upstream_check.config.models import (
    SchemaConfig,
    SourceConfig,
    UpstreamCheckConfig,
)
from upstream_check.core.models import (
    BaselineModel,
    CheckCategory,
    CheckFinding,
    EngineReport,
    Severity,
    SourceCheckResult,
    parse_strict_json_object,
)
from upstream_check.core.types import (
    atomic_write_text_safe,
    expand_env_vars,
    has_plaintext_credentials,
    parse_timestamp,
    paths_refer_to_same_file,
    redact_text,
    redact_url,
    resolve_safe_baseline_path,
    resolve_source_target,
    safe_read_regular_file_bytes,
    validate_source_name,
)
from upstream_check.sources import fetch_source


def _expand_for_inference(url: str) -> str:
    try:
        return expand_env_vars(url)
    except Exception:
        return url


def infer_format_from_url(url: str) -> str:
    """Detect whether a URL or path points to CSV or JSON."""
    candidate = _expand_for_inference(url)
    path = unquote(urlsplit(candidate).path).lower()
    if path.endswith(".json") or path.endswith(".geojson"):
        return "json"
    return "csv"


def infer_name_from_url(url: str) -> str:
    """Derive a clean slug name from a URL or file path."""
    candidate = _expand_for_inference(url)
    path = unquote(urlsplit(candidate).path).strip("/\\")
    if not path:
        return "upstream-source"
    stem = Path(path.replace("\\", "/")).stem.lower()
    slug = re.sub(r"[^a-z0-9._-]+", "-", stem).strip("-._")
    if not slug or not slug[0].isalnum():
        slug = f"source-{slug}" if slug else "upstream-source"
    return slug[:64]


def _resolve_filtered_sources(
    config: UpstreamCheckConfig, source_filter: Optional[str] = None
) -> List[SourceConfig]:
    """Return matching sources or raise ValueError if source_filter does not match any configured source."""
    if not source_filter:
        return list(config.sources)
    matched = [s for s in config.sources if s.name == source_filter]
    if not matched:
        available = ", ".join(s.name for s in config.sources)
        raise ValueError(
            f"Unknown source '{source_filter}'. Configured sources: {available}"
        )
    return matched


def _source_local_paths(
    sources: List[SourceConfig], target_dir: Path
) -> List[Path]:
    """Resolve all canonical local source paths across configured sources."""
    paths: List[Path] = []
    for src in sources:
        target = resolve_source_target(src.url, base_dir=target_dir)
        for p in target.protected_paths():
            if p not in paths:
                paths.append(p)
    return paths


def _raw_baseline_candidate(raw_rel: str, target_dir: Path) -> Path:
    expanded = expand_env_vars(raw_rel.strip())
    cand = Path(expanded)
    return cand if cand.is_absolute() else (target_dir / cand)


def validate_baseline_destinations(
    config: UpstreamCheckConfig, target_dir: Path
) -> Dict[str, Path]:
    """Audit all configured sources and baseline destinations for source/baseline and baseline/baseline collisions."""
    local_sources: List[Tuple[str, List[Path]]] = []
    for src in config.sources:
        validate_source_name(src.name)
        resolved = resolve_source_target(src.url, base_dir=target_dir)
        if not resolved.is_remote:
            local_sources.append((src.name, resolved.protected_paths()))

    resolved_baselines: Dict[str, Path] = {}
    seen_baselines: List[Tuple[str, str, Path, Path]] = []

    for src in config.sources:
        raw_rel = (
            src.schema_config.baseline
            if (src.schema_config and src.schema_config.baseline)
            else f"baselines/{src.name}.json"
        )
        raw_cand = _raw_baseline_candidate(raw_rel, target_dir)
        if os.path.islink(raw_cand):
            raise ValueError(
                f"Baseline destination '{raw_rel}' for source '{src.name}' is a symbolic link "
                f"('{raw_cand}'). Refusing to write baseline through a symlink."
            )
        b_path = resolve_safe_baseline_path(raw_rel, target_dir)

        for src_owner, src_paths in local_sources:
            for sp in src_paths:
                if paths_refer_to_same_file(b_path, sp) or paths_refer_to_same_file(
                    raw_cand, sp
                ):
                    if src_owner == src.name:
                        raise ValueError(
                            f"Baseline destination '{raw_rel}' for source '{src.name}' "
                            f"collides with its own local source file '{sp}'."
                        )
                    raise ValueError(
                        f"Baseline destination '{raw_rel}' for source '{src.name}' "
                        f"collides with local source file '{sp}' of source '{src_owner}'."
                    )

        if os.path.lexists(raw_cand):
            try:
                st = os.lstat(raw_cand)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError(
                        f"Baseline destination '{raw_rel}' for source '{src.name}' "
                        "is not a regular file."
                    )
                if st.st_nlink > 1:
                    raise ValueError(
                        f"Baseline destination '{raw_rel}' for source '{src.name}' "
                        f"has {st.st_nlink} hard links; updating it would alter another file."
                    )
            except OSError:
                pass

        for prev_name, prev_raw, prev_b_path, prev_raw_cand in seen_baselines:
            if paths_refer_to_same_file(
                b_path, prev_b_path
            ) or paths_refer_to_same_file(raw_cand, prev_raw_cand):
                raise ValueError(
                    f"Baseline destination '{raw_rel}' for source '{src.name}' "
                    f"collides with baseline destination '{prev_raw}' for source '{prev_name}'."
                )

        seen_baselines.append((src.name, raw_rel, b_path, raw_cand))
        resolved_baselines[src.name] = b_path

    return resolved_baselines


def load_baseline_if_configured(
    source: SourceConfig,
    base_dir: Optional[Path] = None,
    all_sources: Optional[List[SourceConfig]] = None,
) -> Tuple[Optional[BaselineModel], Optional[CheckFinding]]:
    """Load and validate a baseline JSON file if configured on the source, or return a critical finding."""
    if not source.schema_config or not source.schema_config.baseline:
        return None, None
    raw_ref = source.schema_config.baseline
    root_dir = (base_dir or Path.cwd()).resolve()
    try:
        raw_cand = _raw_baseline_candidate(raw_ref, root_dir)
        b_path = resolve_safe_baseline_path(raw_ref, root_dir)
    except ValueError as exc:
        return None, CheckFinding(
            category=CheckCategory.SCHEMA,
            passed=False,
            title=f"Unsafe baseline path rejected: {raw_ref}",
            details=[str(exc)],
            severity=Severity.CRITICAL,
        )

    sources_to_check = all_sources if all_sources is not None else [source]
    for candidate_src in sources_to_check:
        try:
            resolved_src = resolve_source_target(
                candidate_src.url, base_dir=root_dir
            )
            for sp in resolved_src.protected_paths():
                if paths_refer_to_same_file(b_path, sp) or paths_refer_to_same_file(
                    raw_cand, sp
                ):
                    return None, CheckFinding(
                        category=CheckCategory.SCHEMA,
                        passed=False,
                        title=f"Baseline path collides with local source file: {raw_ref}",
                        details=[
                            f"Baseline '{raw_ref}' for source '{source.name}' aliases "
                            f"local source file '{sp}' (source '{candidate_src.name}')."
                        ],
                        severity=Severity.CRITICAL,
                    )
        except Exception:
            pass

    if not os.path.lexists(b_path):
        return None, CheckFinding(
            category=CheckCategory.SCHEMA,
            passed=False,
            title=f"Configured baseline file not found: {raw_ref}",
            details=[f"Resolved path: {b_path}"],
            severity=Severity.CRITICAL,
        )
    try:
        raw_bytes, _ = safe_read_regular_file_bytes(
            b_path, max_bytes=52_428_800, label=f"baseline '{raw_ref}'"
        )
        raw_text = raw_bytes.decode("utf-8")
        data = parse_strict_json_object(raw_text, label=f"baseline '{raw_ref}'")
        baseline = BaselineModel.from_dict(data)
        if baseline.source_name != source.name:
            raise ValueError(
                f"Baseline source_name '{baseline.source_name}' does not match "
                f"configured source '{source.name}'."
            )
        if baseline.format != source.format:
            raise ValueError(
                f"Baseline format '{baseline.format}' does not match "
                f"configured source format '{source.format}'."
            )
        return baseline, None
    except Exception as exc:
        return None, CheckFinding(
            category=CheckCategory.SCHEMA,
            passed=False,
            title=f"Invalid or corrupted baseline file: {raw_ref}",
            details=[str(exc)],
            severity=Severity.CRITICAL,
        )


def run_source_checks(
    source: SourceConfig,
    base_dir: Optional[Path] = None,
    reference_time: Optional[datetime] = None,
    http_client: Optional[httpx.Client] = None,
    all_sources: Optional[List[SourceConfig]] = None,
) -> SourceCheckResult:
    """Execute availability, schema, quality, and freshness checks for a single source."""
    dataset = fetch_source(
        source,
        base_dir=str(base_dir) if base_dir else None,
        http_client=http_client,
    )
    baseline, baseline_error = load_baseline_if_configured(
        source, base_dir=base_dir, all_sources=all_sources
    )

    findings: List[CheckFinding] = []
    avail_findings = run_availability_checks(source, dataset)
    findings.extend(avail_findings)
    already_flagged_empty = any(
        not f.passed and "empty dataset" in f.title for f in avail_findings
    )
    if baseline_error is not None:
        findings.append(baseline_error)
    if dataset.available and (dataset.headers or dataset.rows):
        findings.extend(run_schema_checks(source, dataset, baseline=baseline))
    if dataset.available:
        q_findings = run_quality_checks(source, dataset, baseline=baseline)
        if already_flagged_empty:
            q_findings = [
                f
                for f in q_findings
                if f.title != "Row count below minimum: 0"
            ]
        findings.extend(q_findings)
    if dataset.available and dataset.rows:
        findings.extend(
            run_freshness_checks(source, dataset, reference_time=reference_time)
        )

    return SourceCheckResult(
        source_name=source.name,
        endpoint=dataset.redacted_endpoint,
        format=source.format,
        findings=findings,
        row_count=len(dataset.rows),
        latency_ms=dataset.latency_ms,
    )


def run_all_checks(
    config: UpstreamCheckConfig,
    base_dir: Optional[Path] = None,
    source_filter: Optional[str] = None,
    reference_time: Optional[datetime] = None,
    http_client: Optional[httpx.Client] = None,
    max_workers: int = 8,
) -> EngineReport:
    """Run checks across all configured sources concurrently while preserving deterministic source order."""
    target_sources = _resolve_filtered_sources(config, source_filter=source_filter)
    all_cfg_sources = list(config.sources)
    if len(target_sources) == 1 or max_workers <= 1:
        results = [
            run_source_checks(
                src,
                base_dir=base_dir,
                reference_time=reference_time,
                http_client=http_client,
                all_sources=all_cfg_sources,
            )
            for src in target_sources
        ]
        return EngineReport(results=results)

    workers = min(max_workers, len(target_sources))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                run_source_checks,
                src,
                base_dir,
                reference_time,
                http_client,
                all_cfg_sources,
            )
            for src in target_sources
        ]
        results = [f.result() for f in futures]
    return EngineReport(results=results)


def update_baselines(
    config: UpstreamCheckConfig,
    base_dir: Optional[Path] = None,
    source_filter: Optional[str] = None,
    http_client: Optional[httpx.Client] = None,
) -> List[Tuple[str, Path, BaselineModel]]:
    """Re-fetch configured sources and atomically update their baseline JSON snapshots."""
    target_dir = (base_dir or Path.cwd()).resolve()
    target_sources = _resolve_filtered_sources(config, source_filter=source_filter)
    resolved_baselines = validate_baseline_destinations(config, target_dir)
    protected_sources = _source_local_paths(list(config.sources), target_dir)

    staged_writes: List[Tuple[str, Path, BaselineModel, List[Path]]] = []
    for src in target_sources:
        b_path = resolved_baselines[src.name]
        other_baselines = [
            p for name, p in resolved_baselines.items() if name != src.name
        ]
        protected_for_src = list(protected_sources) + other_baselines

        dataset = fetch_source(
            src,
            base_dir=str(target_dir),
            http_client=http_client,
        )
        if not dataset.available:
            safe_err = redact_text(dataset.error_message or "unreachable")
            raise RuntimeError(
                f"Cannot update baseline for '{src.name}' ({dataset.redacted_endpoint}): {safe_err}"
            )
        if not dataset.rows:
            raise RuntimeError(
                f"Cannot update baseline for '{src.name}' ({dataset.redacted_endpoint}): "
                "source returned 0 rows (empty dataset)."
            )
        baseline = build_baseline(src, dataset)
        staged_writes.append((src.name, b_path, baseline, protected_for_src))

    updated: List[Tuple[str, Path, BaselineModel]] = []
    for src_name, b_path, baseline, protected_for_src in staged_writes:
        atomic_write_text_safe(
            target_path=b_path,
            content=json.dumps(baseline.to_dict(), indent=2) + "\n",
            protected_paths=protected_for_src,
            allow_overwrite_existing=True,
            label=f"baseline file for source '{src_name}'",
        )
        updated.append((src_name, b_path, baseline))
    return updated


def initialize_source(
    url: str,
    name: Optional[str] = None,
    fmt: Optional[str] = None,
    output_dir: Optional[Path] = None,
    force: bool = False,
    http_client: Optional[httpx.Client] = None,
) -> Tuple[Dict[str, Any], BaselineModel, Path, Path]:
    """Fetch a source, build its baseline profile, and generate a ready-to-use config dictionary."""
    target_dir = (output_dir or Path.cwd()).resolve()
    safe_url = redact_url(url)

    if has_plaintext_credentials(url):
        raise ValueError(
            f"Refusing to initialize with plaintext credentials in URL ({safe_url}). "
            "Pass secrets via environment-interpolated headers in upstream-check.yaml "
            "(e.g., headers: { Authorization: 'Bearer ${API_TOKEN}' }) or use ${API_KEY} in the URL."
        )

    resolved_target = resolve_source_target(url, base_dir=target_dir)
    if not resolved_target.is_remote and has_plaintext_credentials(
        resolved_target.expanded_url
    ):
        raise ValueError(
            "Refusing to initialize with plaintext credentials in expanded URL."
        )

    resolved_fmt = (fmt or infer_format_from_url(url)).lower()
    raw_name = name if name is not None else infer_name_from_url(url)
    resolved_name = validate_source_name(raw_name)
    baseline_rel_path = f"baselines/{resolved_name}.json"
    baseline_file = resolve_safe_baseline_path(baseline_rel_path, target_dir)

    protected_src = resolved_target.protected_paths()
    for sp in protected_src:
        if paths_refer_to_same_file(baseline_file, sp):
            raise ValueError(
                f"Baseline destination '{baseline_file}' for source '{resolved_name}' "
                f"collides with local source file '{sp}'."
            )

    if os.path.lexists(baseline_file) and not force:
        raise FileExistsError(
            f"Baseline file '{baseline_file}' already exists. Pass --force to overwrite."
        )

    temp_source = SourceConfig(
        name=resolved_name,
        url=url,
        format=resolved_fmt,
        schema=SchemaConfig(baseline=baseline_rel_path),
    )
    dataset = fetch_source(
        temp_source,
        base_dir=str(target_dir),
        http_client=http_client,
    )
    if not dataset.available:
        safe_err = redact_text(dataset.error_message or "unreachable")
        raise RuntimeError(
            f"Could not initialize source '{resolved_name}' from {safe_url}: {safe_err}"
        )
    if not dataset.rows:
        raise RuntimeError(
            f"Could not initialize source '{resolved_name}' from {safe_url}: "
            "source returned an empty dataset (0 rows)."
        )

    baseline = build_baseline(temp_source, dataset)

    freshness_col: Optional[str] = None
    for col_name in dataset.headers:
        sample_vals = [
            r.get(col_name) for r in dataset.rows[:10] if r.get(col_name) is not None
        ]
        if sample_vals and all(parse_timestamp(v) is not None for v in sample_vals):
            freshness_col = col_name
            break

    columns_cfg: Dict[str, Any] = {}
    for col_name, col_base in baseline.columns.items():
        col_entry: Dict[str, Any] = {
            "required": col_base.null_count < col_base.total_count,
        }
        if col_base.inferred_type != "null":
            col_entry["type"] = col_base.inferred_type
        columns_cfg[col_name] = col_entry

    persisted_url = url if "${" in url else safe_url
    source_dict: Dict[str, Any] = {
        "name": resolved_name,
        "url": persisted_url,
        "format": resolved_fmt,
    }
    if freshness_col:
        source_dict["freshness"] = {
            "column": freshness_col,
            "max_age": "36h",
        }
    source_dict["schema"] = {"baseline": baseline_rel_path}
    source_dict["columns"] = columns_cfg
    source_dict["quality"] = {
        "max_null_spike_pct": 20.0,
        "max_row_drop_pct": 50.0,
        "min_rows": 1,
    }

    config_dict: Dict[str, Any] = {
        "version": 1,
        "sources": [source_dict],
    }

    atomic_write_text_safe(
        target_path=baseline_file,
        content=json.dumps(baseline.to_dict(), indent=2) + "\n",
        protected_paths=protected_src,
        allow_overwrite_existing=force,
        label=f"baseline file for source '{resolved_name}'",
    )

    config_file = target_dir / "upstream-check.yaml"
    return config_dict, baseline, config_file, baseline_file
