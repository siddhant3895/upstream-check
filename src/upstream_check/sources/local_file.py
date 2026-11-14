"""Local file and file:// URI connector backed by canonical source resolution and non-blocking descriptor I/O."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from upstream_check.config.models import SourceConfig
from upstream_check.core.models import FetchedDataset
from upstream_check.core.types import (
    redact_text,
    redact_url,
    resolve_source_target,
    safe_read_regular_file_bytes,
)
from upstream_check.sources.http_csv import (
    ResponseTooLargeError,
    decode_payload_bytes,
    parse_csv_content,
)
from upstream_check.sources.http_json import parse_json_content


def _resolve_local_path(url: str, base_dir: Optional[str] = None) -> Path:
    """Resolve a local path or file:// URI using the shared canonical source resolver."""
    target = resolve_source_target(url, base_dir=base_dir)
    if target.is_remote or target.local_path is None:
        raise ValueError(
            f"Source URL '{redact_url(url)}' is a remote endpoint, not a local file."
        )
    return target.local_path


def fetch_local_source(
    source: SourceConfig, base_dir: Optional[str] = None
) -> FetchedDataset:
    """Read a local CSV or JSON dataset via non-blocking descriptor-verified regular-file I/O."""
    start = time.perf_counter()
    raw_redacted = redact_url(source.url)
    try:
        target = resolve_source_target(source.url, base_dir=base_dir)
        resolved_url = target.expanded_url
        if target.is_remote or target.local_path is None:
            raise ValueError(
                f"Source '{source.name}' resolved to remote URL '{redact_url(resolved_url)}', "
                "not a local file."
            )
        path = target.local_path
        try:
            raw_bytes, stat_res = safe_read_regular_file_bytes(
                path,
                max_bytes=source.max_response_bytes,
                label=f"source '{source.name}'",
            )
        except FileNotFoundError:
            return FetchedDataset(
                source_name=source.name,
                endpoint=resolved_url,
                redacted_endpoint=redact_url(resolved_url),
                available=False,
                status_code=404,
                latency_ms=(time.perf_counter() - start) * 1000.0,
                error_message=f"File not found: {path}",
            )
        except ValueError as val_exc:
            msg = str(val_exc)
            if "exceeds max_response_bytes" in msg:
                raise ResponseTooLargeError(msg) from val_exc
            if "not a regular file" in msg:
                return FetchedDataset(
                    source_name=source.name,
                    endpoint=resolved_url,
                    redacted_endpoint=redact_url(resolved_url),
                    available=False,
                    status_code=400,
                    latency_ms=(time.perf_counter() - start) * 1000.0,
                    error_message=msg,
                )
            raise

        raw_text = decode_payload_bytes(raw_bytes)
        mtime_iso = datetime.fromtimestamp(
            stat_res.st_mtime, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        dup_headers = []
        malformed_rows = []
        if source.format == "csv":
            headers, rows, dup_headers, malformed_rows = parse_csv_content(
                raw_text, delimiter=source.delimiter
            )
        else:
            headers, rows = parse_json_content(
                raw_text,
                records_path=source.json_records_path,
                flatten=source.flatten_json,
            )
        latency_ms = (time.perf_counter() - start) * 1000.0
        return FetchedDataset(
            source_name=source.name,
            endpoint=resolved_url,
            redacted_endpoint=redact_url(resolved_url),
            available=True,
            status_code=200,
            latency_ms=latency_ms,
            content_type="text/csv" if source.format == "csv" else "application/json",
            last_modified=mtime_iso,
            headers=headers,
            duplicate_headers=dup_headers,
            malformed_rows=malformed_rows,
            rows=rows,
            raw_byte_size=len(raw_bytes),
        )
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000.0
        return FetchedDataset(
            source_name=source.name,
            endpoint=raw_redacted,
            redacted_endpoint=raw_redacted,
            available=False,
            status_code=500,
            latency_ms=latency_ms,
            error_message=redact_text(str(exc)),
        )
