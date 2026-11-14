"""HTTP JSON API source connector with RFC 8259 compliance, collision-safe flattening, and duplicate-key rejection."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from upstream_check.config.models import SourceConfig
from upstream_check.core.models import (
    FetchedDataset,
    reject_nonstandard_json_constant,
)
from upstream_check.core.types import (
    expand_env_vars,
    redact_text,
    redact_url,
)
from upstream_check.sources.http_csv import (
    _resolve_headers,
    fetch_bounded_response,
)


def _reject_duplicate_json_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Reject JSON objects that define the exact same key multiple times in raw JSON."""
    result: Dict[str, Any] = {}
    for k, v in pairs:
        if k in result:
            raise ValueError(f"Duplicate JSON object key '{k}' detected in payload")
        result[k] = v
    return result


def _flatten_record(
    record: Dict[str, Any], parent_key: str = "", max_depth: int = 3, depth: int = 0
) -> Dict[str, Any]:
    """Flatten nested JSON objects into dot-separated keys, raising ValueError on key collisions."""
    items: Dict[str, Any] = {}
    for k, v in record.items():
        key_str = str(k).strip()
        if not key_str:
            raise ValueError("Empty JSON object key is not allowed")
        new_key = f"{parent_key}.{key_str}" if parent_key else key_str
        if isinstance(v, dict) and v and depth < max_depth:
            nested = _flatten_record(
                v, parent_key=new_key, max_depth=max_depth, depth=depth + 1
            )
            for nk, nv in nested.items():
                if nk in items:
                    raise ValueError(
                        f"JSON key collision after flattening: '{nk}' appears both as a "
                        "literal dotted key and a nested object path"
                    )
                items[nk] = nv
        else:
            if new_key in items:
                raise ValueError(
                    f"JSON key collision after flattening: '{new_key}' appears both as a "
                    "literal dotted key and a nested object path"
                )
            items[new_key] = v
    return items


def _extract_records(
    payload: Any, records_path: Optional[str] = None, flatten: bool = True
) -> List[Dict[str, Any]]:
    """Extract a list of record dictionaries from a JSON API response."""
    target = payload
    if records_path:
        for part in records_path.split("."):
            if isinstance(target, dict) and part in target:
                target = target[part]
            else:
                raise ValueError(
                    f"JSON records path '{records_path}' not found in payload"
                )
    elif isinstance(target, dict):
        for candidate in (
            "data",
            "results",
            "items",
            "records",
            "rows",
            "entries",
            "features",
        ):
            if candidate in target and isinstance(target[candidate], list):
                target = target[candidate]
                break
        else:
            target = [target]

    if not isinstance(target, list):
        raise ValueError(
            f"Expected JSON array of records or object envelope, got {type(target).__name__}"
        )

    rows: List[Dict[str, Any]] = []
    for item in target:
        if isinstance(item, dict):
            rows.append(_flatten_record(item) if flatten else dict(item))
        else:
            raise ValueError(
                f"Expected JSON records to be objects, found {type(item).__name__}"
            )
    return rows


def parse_json_content(
    text: str, records_path: Optional[str] = None, flatten: bool = True
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Parse raw JSON text into ordered column headers and record dictionaries, rejecting NaN/Infinity."""
    if not text.strip():
        return [], []
    payload = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=reject_nonstandard_json_constant,
    )
    rows = _extract_records(payload, records_path=records_path, flatten=flatten)
    headers: List[str] = []
    seen = set()
    for row in rows:
        for k in row.keys():
            if k not in seen:
                seen.add(k)
                headers.append(k)
    return headers, rows


def fetch_http_json(
    source: SourceConfig, client: Optional[httpx.Client] = None
) -> FetchedDataset:
    """Fetch and inspect an external JSON API endpoint over HTTP/HTTPS."""
    start = time.perf_counter()
    raw_redacted = redact_url(source.url)
    close_client = False
    try:
        resolved_url = expand_env_vars(source.url)
        redacted = redact_url(resolved_url)
        req_headers = _resolve_headers(source.headers)
        if client is None:
            client = httpx.Client(timeout=source.timeout_seconds, follow_redirects=True)
            close_client = True
        status_code, resp_headers, raw_bytes, text = fetch_bounded_response(
            client=client,
            url=resolved_url,
            headers=req_headers,
            retries=source.retries,
            backoff_seconds=source.retry_backoff_seconds,
            max_bytes=source.max_response_bytes,
        )
        latency_ms = (time.perf_counter() - start) * 1000.0
        content_type = resp_headers.get("content-type", "")
        last_modified = resp_headers.get("last-modified")
        if status_code >= 400:
            return FetchedDataset(
                source_name=source.name,
                endpoint=redacted,
                redacted_endpoint=redacted,
                available=False,
                status_code=status_code,
                latency_ms=latency_ms,
                content_type=content_type,
                last_modified=last_modified,
                error_message=f"HTTP {status_code} response received",
                raw_byte_size=len(raw_bytes),
            )
        headers, rows = parse_json_content(
            text,
            records_path=source.json_records_path,
            flatten=source.flatten_json,
        )
        return FetchedDataset(
            source_name=source.name,
            endpoint=redacted,
            redacted_endpoint=redacted,
            available=True,
            status_code=status_code,
            latency_ms=latency_ms,
            content_type=content_type,
            last_modified=last_modified,
            headers=headers,
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
            latency_ms=latency_ms,
            error_message=redact_text(str(exc)),
        )
    finally:
        if close_client and client is not None:
            client.close()
