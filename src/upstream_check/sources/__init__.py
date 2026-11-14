"""Data source connectors for HTTP CSV, HTTP JSON, and local files."""

from __future__ import annotations

import time
from typing import Optional
import httpx

from upstream_check.config.models import SourceConfig
from upstream_check.core.models import FetchedDataset
from upstream_check.core.types import (
    redact_text,
    redact_url,
    resolve_source_target,
)
from upstream_check.sources.http_csv import fetch_http_csv, parse_csv_content
from upstream_check.sources.http_json import fetch_http_json, parse_json_content
from upstream_check.sources.local_file import fetch_local_source


def fetch_source(
    source: SourceConfig,
    base_dir: Optional[str] = None,
    http_client: Optional[httpx.Client] = None,
) -> FetchedDataset:
    """Route a SourceConfig to the appropriate HTTP or local file fetcher via canonical resolution."""
    start = time.perf_counter()
    try:
        target = resolve_source_target(source.url, base_dir=base_dir)
    except Exception as exc:
        raw_redacted = redact_url(source.url)
        return FetchedDataset(
            source_name=source.name,
            endpoint=raw_redacted,
            redacted_endpoint=raw_redacted,
            available=False,
            status_code=500,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            error_message=redact_text(str(exc)),
        )
    if not target.is_remote:
        return fetch_local_source(source, base_dir=base_dir)
    if source.format == "csv":
        return fetch_http_csv(source, client=http_client)
    return fetch_http_json(source, client=http_client)


__all__ = [
    "fetch_http_csv",
    "fetch_http_json",
    "fetch_local_source",
    "fetch_source",
    "parse_csv_content",
    "parse_json_content",
]
