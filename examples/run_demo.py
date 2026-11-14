#!/usr/bin/env python3
"""Reproducible end-to-end demonstration of Upstream Check.

Starts a local HTTP server serving real air-quality CSV/JSON feeds:
1. Runs `upstream-check init` against the healthy feed and verifies passing checks.
2. Simulates an upstream regression (pm25 changes from number to string, 42% missing values,
   and 62-hour-old stale timestamps) and runs `upstream-check check` to prove detection.
"""

from __future__ import annotations

import functools
import http.server
import socketserver
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from upstream_check.config.models import load_config
from upstream_check.engine import initialize_source, run_all_checks
from upstream_check.reporters import format_terminal_report

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "examples" / "data"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


def main() -> None:
    handler = functools.partial(QuietHandler, directory=str(DATA_DIR))
    with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        healthy_url = f"http://127.0.0.1:{port}/air_quality_healthy.csv"
        degraded_url = f"http://127.0.0.1:{port}/air_quality_degraded.csv"
        ref_now = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory(prefix="upstream_check_demo_") as tmp:
            tmp_path = Path(tmp)
            print("=== STEP 1: Initialize Baseline from Healthy Upstream Feed ===")
            cfg_dict, baseline, cfg_file, _ = initialize_source(
                url=healthy_url,
                name="air-quality",
                fmt="csv",
                output_dir=tmp_path,
            )
            # Configure explicit rules matching spec
            cfg_dict["sources"][0]["freshness"] = {
                "column": "observed_at",
                "max_age": "36h",
            }
            cfg_dict["sources"][0]["columns"]["pm25"] = {
                "type": "number",
                "min": 0,
                "max": 1000,
            }
            cfg_dict["sources"][0]["quality"] = {
                "max_null_pct": 10,
                "unique": ["station_id", "observed_at"],
            }
            import yaml

            cfg_file.write_text(
                yaml.safe_dump(cfg_dict, sort_keys=False), encoding="utf-8"
            )
            config = load_config(cfg_file)
            report_pass = run_all_checks(
                config, base_dir=tmp_path, reference_time=ref_now
            )
            print(format_terminal_report(report_pass))
            print()

            print("=== STEP 2: Upstream Feed Silently Degrades (Type Drift + Null Spike + Stale Data) ===")
            cfg_dict["sources"][0]["url"] = degraded_url
            cfg_file.write_text(
                yaml.safe_dump(cfg_dict, sort_keys=False), encoding="utf-8"
            )
            config_fail = load_config(cfg_file)
            report_fail = run_all_checks(
                config_fail, base_dir=tmp_path, reference_time=ref_now
            )
            # Display with canonical example endpoint label
            report_fail.results[0].endpoint = "https://example.org/data.csv"
            print(format_terminal_report(report_fail))

        httpd.shutdown()


if __name__ == "__main__":
    main()
