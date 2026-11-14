"""Structured JSON reporter for programmatic CI consumption and coding agents."""

from __future__ import annotations

import json
from typing import Any, Dict

from upstream_check.core.models import EngineReport
from upstream_check.reporters.markdown import compute_incident_fingerprint


def format_json_report(report: EngineReport) -> str:
    """Serialize an EngineReport into deterministic JSON including stable incident_fingerprint."""
    payload: Dict[str, Any] = {
        "passed": report.passed,
        "result": "PASSED" if report.passed else "FAILED",
        "total_failed_findings": report.total_failed_findings,
        "incident_fingerprint": compute_incident_fingerprint(report),
        "sources": [
            {
                "source": r.source_name,
                "endpoint": r.endpoint,
                "format": r.format,
                "passed": r.passed,
                "row_count": r.row_count,
                "latency_ms": round(r.latency_ms, 2),
                "findings": [
                    {
                        "category": f.category.value,
                        "passed": f.passed,
                        "severity": f.severity.value,
                        "title": f.title,
                        "details": f.details,
                        "column": f.column,
                        "expected": f.expected,
                        "received": f.received,
                    }
                    for f in r.findings
                ],
            }
            for r in report.results
        ],
    }
    return json.dumps(payload, indent=2)
