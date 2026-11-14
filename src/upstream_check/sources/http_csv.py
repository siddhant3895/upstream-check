"""HTTP CSV source connector with ragged row-width detection, HTML error-page rejection, and streaming byte caps."""

from __future__ import annotations

import csv
import io
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from upstream_check.config.models import SourceConfig
from upstream_check.core.models import FetchedDataset
from upstream_check.core.types import (
    expand_env_vars,
    redact_text,
    redact_url,
)

RETRYABLE_STATUS_CODES = {429, 502, 503, 504}


class ResponseTooLargeError(ValueError):
    """Raised when an HTTP or local payload exceeds max_response_bytes."""


def _resolve_headers(raw_headers: Dict[str, str]) -> Dict[str, str]:
    """Expand ${ENV_VAR} placeholders anywhere inside request header values without persisting secrets."""
    resolved: Dict[str, str] = {}
    for k, v in raw_headers.items():
        resolved[k] = expand_env_vars(str(v))
    return resolved


def decode_payload_bytes(
    raw_bytes: bytes, declared_encoding: Optional[str] = None
) -> str:
    """Decode payload bytes using declared/UTF-8 encoding first, falling back cleanly to CP1252."""
    candidates = []
    if declared_encoding:
        candidates.append(declared_encoding)
    if "utf-8" not in [c.lower() for c in candidates]:
        candidates.append("utf-8")
    for enc in candidates:
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("cp1252", errors="replace")


def _detect_delimiter(
    sample_text: str, explicit_delimiter: Optional[str] = None
) -> str:
    if explicit_delimiter:
        return "\t" if explicit_delimiter == "\\t" else explicit_delimiter
    first_lines = "\n".join(sample_text.splitlines()[:5])
    if not first_lines.strip():
        return ","
    try:
        dialect = csv.Sniffer().sniff(first_lines, delimiters=",;\t|")
        return dialect.delimiter
    except Exception:
        return ","


def parse_csv_content(
    text: str, delimiter: Optional[str] = None
) -> Tuple[List[str], List[Dict[str, Any]], List[str], List[Tuple[int, int, int]]]:
    """Parse raw CSV text without mutating values, rejecting HTML error pages and detecting ragged rows."""
    cleaned = text.lstrip("\ufeff")
    stripped_lead = cleaned.lstrip()
    if not stripped_lead:
        return [], [], [], []
    low_lead = stripped_lead[:64].lower()
    if low_lead.startswith("<!doctype html") or low_lead.startswith("<html"):
        raise ValueError(
            "Received HTML document instead of CSV payload (upstream endpoint may have returned an error page)"
        )

    delim = _detect_delimiter(cleaned, explicit_delimiter=delimiter)
    stream = io.StringIO(cleaned)
    reader = csv.reader(stream, delimiter=delim)
    try:
        raw_headers = next(reader)
    except StopIteration:
        return [], [], [], []

    headers: List[str] = []
    duplicate_headers: List[str] = []
    seen = set()
    for h in raw_headers:
        clean_h = h.strip()
        if clean_h in seen and clean_h not in duplicate_headers:
            duplicate_headers.append(clean_h)
        seen.add(clean_h)
        headers.append(clean_h)

    expected_width = len(headers)
    rows: List[Dict[str, Any]] = []
    malformed_rows: List[Tuple[int, int, int]] = []

    for row_idx, raw_row in enumerate(reader, start=2):
        if not raw_row or all(cell.strip() == "" for cell in raw_row):
            continue
        actual_width = len(raw_row)
        if actual_width != expected_width:
            malformed_rows.append((row_idx, expected_width, actual_width))
        row_dict: Dict[str, Any] = {}
        for idx, col_name in enumerate(headers):
            row_dict[col_name] = raw_row[idx] if idx < actual_width else None
        rows.append(row_dict)
    return headers, rows, duplicate_headers, malformed_rows


def fetch_bounded_response(
    client: httpx.Client,
    url: str,
    headers: Dict[str, str],
    retries: int = 2,
    backoff_seconds: float = 0.25,
    max_bytes: int = 52_428_800,
) -> Tuple[int, Dict[str, str], bytes, str]:
    """Perform an HTTP GET with retries and enforce a strict maximum byte limit."""
    last_exc: Optional[Exception] = None
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        try:
            with client.stream("GET", url, headers=headers) as response:
                status_code = response.status_code
                if (
                    status_code in RETRYABLE_STATUS_CODES
                    and attempt < attempts - 1
                ):
                    time.sleep(backoff_seconds * (2**attempt))
                    continue

                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                content_len = resp_headers.get("content-length")
                if content_len and content_len.isdigit():
                    if int(content_len) > max_bytes:
                        raise ResponseTooLargeError(
                            f"Response Content-Length ({content_len} bytes) exceeds "
                            f"max_response_bytes ({max_bytes} bytes)"
                        )

                chunks: List[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise ResponseTooLargeError(
                            f"Response payload exceeded max_response_bytes ({max_bytes} bytes)"
                        )
                    chunks.append(chunk)
                raw_bytes = b"".join(chunks)
                text = decode_payload_bytes(
                    raw_bytes, declared_encoding=response.encoding
                )
                return status_code, resp_headers, raw_bytes, text
        except ResponseTooLargeError:
            raise
        except Exception as exc:
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(backoff_seconds * (2**attempt))
            else:
                raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Request failed after retries")


def fetch_http_csv(
    source: SourceConfig, client: Optional[httpx.Client] = None
) -> FetchedDataset:
    """Fetch and inspect an external CSV URL over HTTP/HTTPS."""
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
        headers, rows, dup_headers, malformed_rows = parse_csv_content(
            text, delimiter=source.delimiter
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
            latency_ms=latency_ms,
            error_message=redact_text(str(exc)),
        )
    finally:
        if close_client and client is not None:
            client.close()
