"""Comprehensive unit, security, wheel-packaging, and regression tests for Upstream Check v0.2.9."""

from __future__ import annotations

import functools
import http.server
import json
import os
import stat
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from click.testing import CliRunner
import yaml

from upstream_check.checks.availability import run_availability_checks
from upstream_check.checks.freshness import run_freshness_checks
from upstream_check.checks.quality import run_quality_checks
from upstream_check.checks.schema import build_baseline, run_schema_checks
from upstream_check.cli.app import app
from upstream_check.config.models import (
    ColumnRuleConfig,
    FreshnessConfig,
    QualityConfig,
    SchemaConfig,
    SourceConfig,
    UpstreamCheckConfig,
    load_config,
)
from upstream_check.core.models import (
    BaselineModel,
    ColumnBaseline,
    EngineReport,
    FetchedDataset,
    parse_strict_json_object,
)
from upstream_check.core.types import (
    expand_env_vars,
    has_plaintext_credentials,
    infer_column_type,
    parse_duration_seconds,
    parse_timestamp,
    redact_text,
    redact_url,
    resolve_safe_baseline_path,
    resolve_source_target,
    safe_append_text_verified,
    safe_read_regular_file_bytes,
    verify_open_fd_safe,
    to_float,
    types_compatible,
    validate_source_name,
)
from upstream_check.engine import (
    initialize_source,
    run_all_checks,
    run_source_checks,
    update_baselines,
)
from upstream_check.mcp import handle_mcp_request
from upstream_check.reporters import (
    compute_execution_error_fingerprint,
    compute_incident_fingerprint,
    format_execution_error_markdown,
    format_json_report,
    format_markdown_report,
    format_terminal_report,
)
from upstream_check.sources.http_csv import _resolve_headers, parse_csv_content
from upstream_check.sources.http_json import parse_json_content
from upstream_check.sources.local_file import _resolve_local_path, fetch_local_source

REPO_ROOT = Path(__file__).resolve().parent.parent


class QuietHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


class SpecCompliantMCP2026Client:
    """Reference MCP 2026-07-28 stateless client that attaches required _meta and validates server responses."""

    def __init__(
        self,
        proc: subprocess.Popen[str],
        client_name: str = "mcp-reference-client",
        client_version: str = "1.0.0",
        capabilities: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.proc = proc
        self.client_name = client_name
        self.client_version = client_version
        self.capabilities = capabilities if capabilities is not None else {}
        self._next_id = 1

    def _build_meta(self) -> Dict[str, Any]:
        return {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": dict(self.capabilities),
            "io.modelcontextprotocol/clientInfo": {
                "name": self.client_name,
                "version": self.client_version,
            },
        }

    def raw_rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        raw_line = self.proc.stdout.readline()
        if not raw_line:
            raise RuntimeError(f"MCP server closed stdout unexpectedly on {method}")
        resp = json.loads(raw_line)
        if resp.get("jsonrpc") != "2.0" or resp.get("id") != req_id:
            raise AssertionError(f"Invalid JSON-RPC envelope: {resp}")
        return resp

    def _validate_modern_result_envelope(
        self, result: Dict[str, Any], is_list_or_discover: bool = False
    ) -> None:
        if result.get("resultType") not in ("complete", "input_required"):
            raise AssertionError(f"Missing or invalid resultType in 2026-07-28 response: {result}")
        meta = result.get("_meta")
        if not isinstance(meta, dict):
            raise AssertionError(f"Missing _meta in 2026-07-28 response: {result}")
        srv_info = meta.get("io.modelcontextprotocol/serverInfo")
        if not isinstance(srv_info, dict) or not srv_info.get("name") or not srv_info.get("version"):
            raise AssertionError(f"Invalid serverInfo in _meta: {meta}")
        if is_list_or_discover:
            if not isinstance(result.get("ttlMs"), int) or result["ttlMs"] < 0:
                raise AssertionError(f"Missing or invalid ttlMs in response: {result}")
            if result.get("cacheScope") not in ("public", "private"):
                raise AssertionError(f"Missing or invalid cacheScope in response: {result}")

    def discover(self) -> Dict[str, Any]:
        resp = self.raw_rpc("server/discover", {"_meta": self._build_meta()})
        if "error" in resp:
            raise AssertionError(f"server/discover failed: {resp['error']}")
        res = resp["result"]
        self._validate_modern_result_envelope(res, is_list_or_discover=True)
        if not isinstance(res.get("supportedVersions"), list) or "2026-07-28" not in res["supportedVersions"]:
            raise AssertionError(f"Invalid supportedVersions in discovery: {res}")
        if not isinstance(res.get("capabilities"), dict):
            raise AssertionError(f"Invalid capabilities in discovery: {res}")
        if "tools" in res:
            raise AssertionError("server/discover must not embed tool definitions directly")
        return res

    def list_tools(self) -> List[Dict[str, Any]]:
        resp = self.raw_rpc("tools/list", {"_meta": self._build_meta()})
        if "error" in resp:
            raise AssertionError(f"tools/list failed: {resp['error']}")
        res = resp["result"]
        self._validate_modern_result_envelope(res, is_list_or_discover=True)
        tools = res.get("tools")
        if not isinstance(tools, list):
            raise AssertionError(f"Expected tools list in tools/list response: {res}")
        return tools

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        resp = self.raw_rpc(
            "tools/call",
            {"_meta": self._build_meta(), "name": name, "arguments": arguments},
        )
        if "error" in resp:
            raise AssertionError(f"tools/call failed with RPC error: {resp['error']}")
        res = resp["result"]
        self._validate_modern_result_envelope(res, is_list_or_discover=False)
        if not isinstance(res.get("content"), list) or not isinstance(res.get("isError"), bool):
            raise AssertionError(f"Invalid CallToolResult structure: {res}")
        return res


class SpecCompliantMCPLegacyClient:
    """Reference legacy MCP (2025-11-25 / 2025-06-18 / 2024-11-05) stateful client enforcing handshake rules."""

    def __init__(
        self,
        proc: subprocess.Popen[str],
        protocol_version: str = "2025-11-25",
        client_name: str = "legacy-mcp-client",
        client_version: str = "1.0.0",
    ) -> None:
        self.proc = proc
        self.protocol_version = protocol_version
        self.client_name = client_name
        self.client_version = client_version
        self._next_id = 1

    def request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        assert self.proc.stdin is not None
        assert self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        raw_line = self.proc.stdout.readline()
        if not raw_line:
            raise RuntimeError(f"MCP server closed stdout unexpectedly on {method}")
        resp = json.loads(raw_line)
        if resp.get("id") != req_id:
            raise AssertionError(f"Mismatched JSON-RPC id: expected {req_id}, got {resp.get('id')}")
        return resp

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def connect_and_handshake(self) -> Dict[str, Any]:
        resp = self.request(
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": self.client_name,
                    "version": self.client_version,
                },
            },
        )
        if "error" in resp:
            raise AssertionError(f"Legacy initialize failed: {resp['error']}")
        res = resp["result"]
        if not isinstance(res.get("protocolVersion"), str):
            raise AssertionError(f"Missing protocolVersion in InitializeResult: {res}")
        if not isinstance(res.get("capabilities"), dict) or not isinstance(res.get("serverInfo"), dict):
            raise AssertionError(f"Invalid InitializeResult structure: {res}")
        self.notify("notifications/initialized")
        return res


class TestCoreTypesAndSecurity(unittest.TestCase):
    """Test duration parsing, timestamp handling, type inference, path containment, and secret redaction."""

    def test_redact_url_and_redact_text_never_leak_secrets_including_fragments(self) -> None:
        raw = "https://user:supersecret@api.example.org/v1/feed.csv?api_key=12345&station=nagpur&token=abcdef"
        redacted = redact_url(raw)
        self.assertNotIn("supersecret", redacted)
        self.assertNotIn("12345", redacted)
        self.assertNotIn("abcdef", redacted)
        self.assertIn("api_key=REDACTED", redacted)
        self.assertIn("token=REDACTED", redacted)
        self.assertIn("station=nagpur", redacted)

        frag_url = "https://example.org/feed.json#access_token=LEAK_ME&theme=dark"
        self.assertTrue(has_plaintext_credentials(frag_url))
        redacted_frag = redact_url(frag_url)
        self.assertNotIn("LEAK_ME", redacted_frag)
        self.assertIn("access_token=REDACTED", redacted_frag)
        self.assertIn("theme=dark", redacted_frag)

        spa_frag_url = "https://example.org/app#/callback?id_token=SECRET_JWT"
        self.assertTrue(has_plaintext_credentials(spa_frag_url))
        self.assertNotIn("SECRET_JWT", redact_url(spa_frag_url))

        err_msg = f"Failed to connect to {frag_url} after 2 retries"
        safe_msg = redact_text(err_msg)
        self.assertNotIn("LEAK_ME", safe_msg)

    def test_unresolved_or_empty_env_var_raises_value_error(self) -> None:
        os.environ.pop("UPSTREAM_CHECK_INTENTIONALLY_MISSING", None)
        with self.assertRaises(ValueError) as ctx:
            expand_env_vars("https://api.example.com/${UPSTREAM_CHECK_INTENTIONALLY_MISSING}/records")
        self.assertIn("UPSTREAM_CHECK_INTENTIONALLY_MISSING", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx_cfg:
            SourceConfig(
                name="missing-env",
                url="https://api.example.com/${UPSTREAM_CHECK_INTENTIONALLY_MISSING}/records",
                format="json",
            )
        self.assertIn("UPSTREAM_CHECK_INTENTIONALLY_MISSING", str(ctx_cfg.exception))

        with tempfile.TemporaryDirectory() as tmp:
            cfg_p = Path(tmp) / "upstream-check.yaml"
            cfg_p.write_text(
                (
                    "version: 1\nsources:\n  - name: s\n"
                    "    url: https://api.example.com/${UPSTREAM_CHECK_INTENTIONALLY_MISSING}/records\n"
                ),
                encoding="utf-8",
            )
            runner = CliRunner()
            res_cli = runner.invoke(app, ["check", "--config", str(cfg_p)])
            self.assertEqual(res_cli.exit_code, 2)
            self.assertIn("Configuration error", res_cli.output)
            self.assertIn("UPSTREAM_CHECK_INTENTIONALLY_MISSING", res_cli.output)

    def test_malformed_and_unclosed_env_placeholders_rejected(self) -> None:
        for bad_expr in (
            "https://api.example.com/${BAD-NAME}/data.json",
            "https://api.example.com/${123_INVALID}/data.json",
            "https://api.example.com/${}/data.json",
            "https://api.example.com/${UNCLOSED_VAR/data.json",
            "https://api.example.com/${SPACE VAR}/data.json",
        ):
            with self.assertRaises(ValueError):
                expand_env_vars(bad_expr)
            with self.assertRaises(ValueError):
                SourceConfig(name="bad-env", url=bad_expr, format="json")

        with self.assertRaises(ValueError):
            SourceConfig(
                name="bad-hdr-env",
                url="https://api.example.com/data.json",
                headers={"Authorization": "Bearer ${BAD-HEADER-VAR}"},
            )

    def test_rfc8259_strict_json_rejects_nan_and_infinity_in_feeds_and_baselines(self) -> None:
        for bad_json in (
            '[{"id": "1", "val": NaN}]',
            '[{"id": "1", "val": Infinity}]',
            '[{"id": "1", "val": -Infinity}]',
        ):
            with self.assertRaises(ValueError) as ctx:
                parse_json_content(bad_json)
            self.assertIn("RFC 8259", str(ctx.exception))

        with self.assertRaises(ValueError):
            parse_strict_json_object('{"version": 1, "null_pct": NaN}')

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            nan_json_file = tmp_path / "nan_feed.json"
            nan_json_file.write_text('[{"id": "1", "val": NaN}]\n', encoding="utf-8")
            src = SourceConfig(
                name="nan-json-src",
                url=str(nan_json_file),
                format="json",
            )
            res = run_source_checks(src, base_dir=tmp_path)
            self.assertFalse(res.passed)
            self.assertIn("RFC 8259", res.failed_findings[0].details[0])

    def test_html_error_page_masquerading_as_csv_rejected(self) -> None:
        for html_payload in (
            "<!DOCTYPE html>\n<html><body>502 Bad Gateway</body></html>",
            "<html>\n<head><title>Login</title></head><body>Please sign in</body></html>",
        ):
            with self.assertRaises(ValueError) as ctx:
                parse_csv_content(html_payload)
            self.assertIn("HTML document instead of CSV", str(ctx.exception))

    def test_huge_1001_digit_json_integer_does_not_crash_with_overflow_error(self) -> None:
        huge_int = int("9" * 1001)
        self.assertIsNone(to_float(huge_int))
        self.assertIsNone(parse_timestamp(huge_int))
        self.assertEqual(infer_column_type([huge_int], from_csv=False).value, "string")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            huge_json = tmp_path / "huge.json"
            huge_json.write_text(f'[{{"id": "1", "val": {"9" * 1001}}}]\n', encoding="utf-8")
            src = SourceConfig(
                name="huge-int-src",
                url=str(huge_json),
                format="json",
                columns={"val": ColumnRuleConfig(type="number", min=0, max=100)},
                freshness=FreshnessConfig(column="val", max_age="24h"),
            )
            res = run_source_checks(src, base_dir=tmp_path)
            self.assertFalse(res.passed)

    def test_corrupted_or_mismatched_baseline_files_rejected_loudly(self) -> None:
        corrupted_audit_payload = {
            "version": 999,
            "source_name": "some-other-source",
            "format": "json",
            "row_count": -1,
            "columns": {
                "value": {
                    "inferred_type": "number",
                    "null_pct": float("nan"),
                    "null_count": -1,
                }
            },
        }
        with self.assertRaises(ValueError):
            BaselineModel.from_dict(corrupted_audit_payload)

        valid_base = {
            "version": 1,
            "source_name": "my-csv",
            "endpoint": "data.csv",
            "format": "csv",
            "captured_at": "2026-11-13T12:00:00Z",
            "row_count": 10,
            "column_order": ["value"],
            "columns": {
                "value": {
                    "name": "value",
                    "inferred_type": "number",
                    "null_count": 2,
                    "total_count": 10,
                    "null_pct": 20.0,
                    "min_value": 1.0,
                    "max_value": 10.0,
                    "distinct_count": 8,
                }
            },
        }
        self.assertIsNotNone(BaselineModel.from_dict(valid_base))

        bad_nan = json.loads(json.dumps(valid_base))
        bad_nan["columns"]["value"]["null_pct"] = float("nan")
        with self.assertRaises(ValueError):
            BaselineModel.from_dict(bad_nan)

        bad_counts = json.loads(json.dumps(valid_base))
        bad_counts["columns"]["value"]["null_count"] = 12
        with self.assertRaises(ValueError):
            BaselineModel.from_dict(bad_counts)

        bad_pct = json.loads(json.dumps(valid_base))
        bad_pct["columns"]["value"]["null_pct"] = 95.0
        with self.assertRaises(ValueError):
            BaselineModel.from_dict(bad_pct)

        bad_minmax = json.loads(json.dumps(valid_base))
        bad_minmax["columns"]["value"]["min_value"] = 50.0
        bad_minmax["columns"]["value"]["max_value"] = 10.0
        with self.assertRaises(ValueError):
            BaselineModel.from_dict(bad_minmax)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            csv_path = tmp_path / "data.csv"
            csv_path.write_text("value\n10\n\n", encoding="utf-8")
            b_dir = tmp_path / "baselines"
            b_dir.mkdir()
            b_file = b_dir / "corrupt.json"
            mismatched = json.loads(json.dumps(valid_base))
            mismatched["source_name"] = "wrong-source-name"
            b_file.write_text(json.dumps(mismatched), encoding="utf-8")

            src = SourceConfig(
                name="my-csv",
                url=str(csv_path),
                format="csv",
                schema=SchemaConfig(baseline="baselines/corrupt.json"),
                quality=QualityConfig(max_null_spike_pct=0.0, max_row_drop_pct=0.0),
            )
            res = run_source_checks(src, base_dir=tmp_path)
            self.assertFalse(res.passed)
            self.assertTrue(
                any("Invalid or corrupted baseline file" in f.title for f in res.failed_findings)
            )

    def test_json_flattening_collision_and_duplicate_keys_rejected(self) -> None:
        collision_json = json.dumps([{"a.b": 1, "a": {"b": 2}}])
        with self.assertRaises(ValueError) as ctx:
            parse_json_content(collision_json, flatten=True)
        self.assertIn("JSON key collision after flattening", str(ctx.exception))

        rev_collision_json = json.dumps([{"a": {"b": 2}, "a.b": 1}])
        with self.assertRaises(ValueError):
            parse_json_content(rev_collision_json, flatten=True)

        dup_key_json = '[{"id": 1, "id": 2}]'
        with self.assertRaises(ValueError) as ctx_dup:
            parse_json_content(dup_key_json, flatten=True)
        self.assertIn("Duplicate JSON object key 'id'", str(ctx_dup.exception))

    def test_empty_csv_header_column_name_fails_schema_check(self) -> None:
        raw_csv = "id,,pm25\n1,extra,25.0\n"
        headers, rows, dup, malformed = parse_csv_content(raw_csv)
        src = SourceConfig(name="empty-hdr", url="u", format="csv")
        ds = FetchedDataset(
            source_name="empty-hdr",
            endpoint="u",
            redacted_endpoint="u",
            available=True,
            headers=headers,
            duplicate_headers=dup,
            malformed_rows=malformed,
            rows=rows,
        )
        findings = run_schema_checks(src, ds)
        self.assertTrue(
            any("Empty CSV header column name" in f.title for f in findings if not f.passed)
        )

    def test_initialize_source_rejects_plaintext_credentials_and_allows_env_placeholder(self) -> None:
        for secret_url in (
            "https://example.org/data.csv?api_key=UPSTREAM_DEMO_SECRET_91273",
            "https://example.org/feed.json#access_token=LEAK_ME",
        ):
            self.assertTrue(has_plaintext_credentials(secret_url))
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                with self.assertRaises(ValueError) as ctx:
                    initialize_source(url=secret_url, name="air-quality", output_dir=tmp_path)
                self.assertNotIn("UPSTREAM_DEMO_SECRET_91273", str(ctx.exception))
                self.assertNotIn("LEAK_ME", str(ctx.exception))
                self.assertFalse((tmp_path / "upstream-check.yaml").exists())

                runner = CliRunner()
                cfg_file = tmp_path / "upstream-check.yaml"
                res = runner.invoke(
                    app,
                    ["init", secret_url, "--name", "air-quality", "--config", str(cfg_file)],
                )
                self.assertEqual(res.exit_code, 2)
                self.assertNotIn("UPSTREAM_DEMO_SECRET_91273", res.output)
                self.assertNotIn("LEAK_ME", res.output)
                self.assertFalse(cfg_file.exists())

        env_url = "https://example.org/data.csv?api_key=${MY_SECRET_KEY}"
        self.assertFalse(has_plaintext_credentials(env_url))

    def test_init_followed_by_check_succeeds_on_high_null_feed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            high_null_csv = tmp_path / "high_nulls.csv"
            high_null_csv.write_text(
                "\n".join(
                    [
                        "id,optional_notes,all_empty",
                        "1,hello,",
                        "2,,",
                        "3,,",
                        "4,world,",
                        "5,,",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            cfg_file = tmp_path / "upstream-check.yaml"
            runner = CliRunner()
            res_init = runner.invoke(
                app,
                ["init", str(high_null_csv), "--name", "high-nulls", "--config", str(cfg_file)],
            )
            self.assertEqual(res_init.exit_code, 0, msg=res_init.output)

            res_check = runner.invoke(
                app,
                ["check", "--config", str(cfg_file)],
            )
            self.assertEqual(res_check.exit_code, 0, msg=res_check.output)
            self.assertIn("RESULT: PASSED", res_check.output)

    def test_init_and_baseline_update_reject_empty_zero_row_datasets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            empty_csv = tmp_path / "empty.csv"
            empty_csv.write_text("id,val\n", encoding="utf-8")

            with self.assertRaises(RuntimeError) as ctx:
                initialize_source(url=str(empty_csv), name="empty-src", output_dir=tmp_path)
            self.assertIn("empty dataset (0 rows)", str(ctx.exception))

            cfg = UpstreamCheckConfig(
                version=1,
                sources=[SourceConfig(name="empty-src", url=str(empty_csv), format="csv")],
            )
            with self.assertRaises(RuntimeError) as ctx_up:
                update_baselines(cfg, base_dir=tmp_path)
            self.assertIn("0 rows", str(ctx_up.exception))

    def test_init_does_not_overwrite_existing_baseline_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sample_csv = tmp_path / "data.csv"
            sample_csv.write_text("id,val\n1,10\n2,20\n", encoding="utf-8")

            baselines_dir = tmp_path / "baselines"
            baselines_dir.mkdir(parents=True, exist_ok=True)
            existing_baseline = baselines_dir / "my-src.json"
            existing_baseline.write_text('{"custom": "do-not-overwrite"}\n', encoding="utf-8")

            runner = CliRunner()
            cfg_file = tmp_path / "upstream-check.yaml"
            res = runner.invoke(
                app,
                ["init", str(sample_csv), "--name", "my-src", "--config", str(cfg_file)],
            )
            self.assertEqual(res.exit_code, 2)
            self.assertIn("already exists", res.output)
            self.assertIn("do-not-overwrite", existing_baseline.read_text(encoding="utf-8"))

            res_force = runner.invoke(
                app,
                ["init", str(sample_csv), "--name", "my-src", "--config", str(cfg_file), "--force"],
            )
            self.assertEqual(res_force.exit_code, 0, msg=res_force.output)
            self.assertNotIn("do-not-overwrite", existing_baseline.read_text(encoding="utf-8"))

    def test_init_never_generates_hard_min_max_bounds_or_string_extrema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            csv_file = tmp_path / "sample.csv"
            csv_file.write_text("id,value\n001,10\n002,20\n", encoding="utf-8")

            cfg_dict, baseline, cfg_file, _ = initialize_source(
                url=str(csv_file), name="sample", output_dir=tmp_path
            )
            cfg_file.write_text(yaml.safe_dump(cfg_dict, sort_keys=False), encoding="utf-8")

            self.assertEqual(baseline.columns["id"].inferred_type, "string")
            self.assertIsNone(baseline.columns["id"].min_value)
            self.assertIsNone(baseline.columns["id"].max_value)

            self.assertEqual(baseline.columns["value"].min_value, 10.0)
            self.assertEqual(baseline.columns["value"].max_value, 20.0)
            self.assertNotIn("min", cfg_dict["sources"][0]["columns"]["id"])
            self.assertNotIn("max", cfg_dict["sources"][0]["columns"]["id"])
            self.assertNotIn("min", cfg_dict["sources"][0]["columns"]["value"])
            self.assertNotIn("max", cfg_dict["sources"][0]["columns"]["value"])

            csv_file.write_text("id,value\n001,10\n002,20\n003,30\n", encoding="utf-8")
            loaded_cfg = load_config(cfg_file)
            report = run_all_checks(loaded_cfg, base_dir=tmp_path)
            self.assertTrue(report.passed, msg=str(report.results[0].findings))

    def test_source_name_and_baseline_path_traversal_blocked(self) -> None:
        for bad_name in ("../../escaped", "../outside", "a/b", "a\\b", ".hidden", ""):
            with self.assertRaises(ValueError):
                validate_source_name(bad_name)
            with self.assertRaises(ValueError):
                SourceConfig(name=bad_name, url="https://example.org/data.csv")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with self.assertRaises(ValueError):
                resolve_safe_baseline_path("baselines/../../escaped.json", tmp_path)
            with self.assertRaises(ValueError):
                resolve_safe_baseline_path("/etc/passwd", tmp_path)

            runner = CliRunner()
            res = runner.invoke(
                app,
                [
                    "init",
                    str(REPO_ROOT / "examples" / "data" / "air_quality_healthy.csv"),
                    "--name",
                    "../../escaped",
                    "--config",
                    str(tmp_path / "upstream-check.yaml"),
                ],
            )
            self.assertEqual(res.exit_code, 2)
            self.assertIn("Invalid source name", res.output)

            src_escape = SourceConfig(
                name="safe-name",
                url=str(REPO_ROOT / "examples" / "data" / "air_quality_healthy.csv"),
                format="csv",
                schema=SchemaConfig(baseline="../../escaped.json"),
            )
            check_res = run_source_checks(src_escape, base_dir=tmp_path)
            self.assertFalse(check_res.passed)
            self.assertTrue(
                any("Unsafe baseline path rejected" in f.title for f in check_res.failed_findings)
            )

    def test_embedded_env_var_header_interpolation_and_windows_uri(self) -> None:
        os.environ["UPSTREAM_TEST_TOKEN"] = "xyz987"
        resolved = _resolve_headers({"Authorization": "Bearer ${UPSTREAM_TEST_TOKEN}"})
        self.assertEqual(resolved["Authorization"], "Bearer xyz987")

        win_path = _resolve_local_path("file:///C:/Users/siddhant/data.csv")
        self.assertFalse(str(win_path).startswith("/C:"))

    def test_strict_config_validation_rejects_nan_inf_bools_unknown_fields_and_invalid_bounds(self) -> None:
        for non_finite in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                QualityConfig(max_null_pct=non_finite)
            with self.assertRaises(ValueError):
                QualityConfig(max_null_spike_pct=non_finite)
            with self.assertRaises(ValueError):
                QualityConfig(max_row_drop_pct=non_finite)
            with self.assertRaises(ValueError):
                ColumnRuleConfig(min=non_finite)
            with self.assertRaises(ValueError):
                ColumnRuleConfig(max=non_finite)
            with self.assertRaises(ValueError):
                ColumnRuleConfig(max_null_pct=non_finite)
            with self.assertRaises(ValueError):
                FreshnessConfig(column="ts", max_invalid_pct=non_finite)
            with self.assertRaises(ValueError):
                SourceConfig(name="s", url="u", timeout_seconds=non_finite)
            with self.assertRaises(ValueError):
                SourceConfig(name="s", url="u", retry_backoff_seconds=non_finite)
            with self.assertRaises(ValueError):
                parse_duration_seconds(non_finite)

        with tempfile.TemporaryDirectory() as tmp:
            bad_yaml = Path(tmp) / "nan_cfg.yaml"
            bad_yaml.write_text(
                "version: 1\nsources:\n  - name: s\n    url: u\n    quality:\n      max_null_pct: .nan\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(bad_yaml)

        with self.assertRaises(ValueError):
            QualityConfig(min_rows=True)
        with self.assertRaises(ValueError):
            QualityConfig(unique=["id", "id"])
        with self.assertRaises(ValueError):
            QualityConfig(unique=[""])
        with self.assertRaises(ValueError):
            FreshnessConfig(column="  ")
        with self.assertRaises(ValueError):
            SourceConfig(name="s", url="u", retries=True)
        with self.assertRaises(ValueError):
            SourceConfig(name="s", url="u", max_response_bytes=True)
        with self.assertRaises(ValueError):
            ColumnRuleConfig(min=True)

        with self.assertRaises(ValueError):
            QualityConfig(max_null_pct=150)
        with self.assertRaises(ValueError):
            QualityConfig(max_row_drop_pct=-20)
        with self.assertRaises(ValueError):
            QualityConfig(min_rows=-5)
        with self.assertRaises(ValueError):
            QualityConfig(min_rows=100, max_rows=10)
        with self.assertRaises(ValueError):
            ColumnRuleConfig(min=10, max=1)
        with self.assertRaises(ValueError):
            ColumnRuleConfig(max_null_pct=130)
        with self.assertRaises(ValueError):
            QualityConfig(**{"max_null_perc": 10})
        with self.assertRaises(ValueError):
            SourceConfig(**{"name": "s", "url": "u", "unknown_option": True})
        with self.assertRaises(ValueError):
            UpstreamCheckConfig(**{"version": 1, "sources": [], "extra_root": 1})

    def test_to_float_rejects_infinite_values(self) -> None:
        self.assertIsNone(to_float("inf"))
        self.assertIsNone(to_float("-inf"))
        self.assertIsNone(to_float("Infinity"))
        self.assertIsNone(to_float(float("inf")))
        self.assertEqual(to_float("42.5"), 42.5)

    def test_parse_duration_seconds(self) -> None:
        self.assertEqual(parse_duration_seconds("36h"), 36 * 3600)
        self.assertEqual(parse_duration_seconds("2d"), 2 * 86400)
        self.assertEqual(parse_duration_seconds("1d 12h"), 36 * 3600)
        self.assertEqual(parse_duration_seconds("30m"), 1800)
        with self.assertRaises(ValueError):
            parse_duration_seconds("invalid_duration")

    def test_parse_timestamp_formats_including_rfc2822(self) -> None:
        dt_iso = parse_timestamp("2026-11-13T10:30:00Z")
        self.assertIsNotNone(dt_iso)
        self.assertEqual(dt_iso.year, 2026)
        dt_epoch = parse_timestamp(1794565800)
        self.assertIsNotNone(dt_epoch)
        dt_http = parse_timestamp("Fri, 13 Nov 2026 10:00:00 GMT")
        self.assertIsNotNone(dt_http)
        self.assertEqual(dt_http.year, 2026)
        self.assertIsNone(parse_timestamp("not-a-timestamp"))
        self.assertIsNone(parse_timestamp(float("inf")))

    def test_infer_column_type_and_all_null_incompatibility(self) -> None:
        self.assertEqual(
            infer_column_type(["12.5", "44.0", "", "100"], from_csv=True).value,
            "number",
        )
        self.assertEqual(
            infer_column_type(["12.5", "sensor_err", "44.0"], from_csv=True).value,
            "string",
        )
        self.assertEqual(
            infer_column_type([10, 20, 30], from_csv=False).value,
            "integer",
        )
        self.assertFalse(types_compatible("number", "null"))
        self.assertFalse(types_compatible("string", "null"))


class TestChecksAndEngine(unittest.TestCase):
    """Test all core capabilities and v0.2.9 hardening fixes."""

    def setUp(self) -> None:
        self.ref_now = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)

    def test_unknown_source_filter_raises_value_error_and_cli_exits_nonzero(self) -> None:
        cfg = load_config(REPO_ROOT / "upstream-check.yaml")
        with self.assertRaises(ValueError):
            run_all_checks(cfg, source_filter="typo-source-name")
        with self.assertRaises(ValueError):
            update_baselines(cfg, source_filter="typo-source-name")

        runner = CliRunner()
        res = runner.invoke(
            app,
            [
                "check",
                "--config",
                str(REPO_ROOT / "upstream-check.yaml"),
                "--source",
                "typo-source-name",
            ],
        )
        self.assertEqual(res.exit_code, 2)
        self.assertIn("Unknown source 'typo-source-name'", res.output)

    def test_summary_file_never_overwrites_config_baseline_or_source_files_across_all_paths(self) -> None:
        """Verify Critical Issue 1: --summary-file & $GITHUB_STEP_SUMMARY never overwrite protected files."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            # Setup custom.yaml, data.csv, and baselines/safe-src.json
            csv_bytes = b"id,val\n1,10\n2,20\n"
            csv_file = tmp_path / "data.csv"
            csv_file.write_bytes(csv_bytes)
            cfg_file = tmp_path / "custom.yaml"
            res_init = runner.invoke(
                app,
                ["init", str(csv_file), "--name", "safe-src", "--config", str(cfg_file)],
            )
            self.assertEqual(res_init.exit_code, 0)
            cfg_bytes = cfg_file.read_bytes()
            baseline_file = tmp_path / "baselines" / "safe-src.json"
            baseline_bytes = baseline_file.read_bytes()

            # 1-3. Unknown CLI option (--bogus) + summary path equals config, source CSV, or baseline
            for protected_target in (cfg_file, csv_file, baseline_file):
                res_bogus_prot = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(cfg_file),
                        "--bogus",
                        "--summary-file",
                        str(protected_target),
                    ],
                )
                self.assertEqual(res_bogus_prot.exit_code, 2)

            self.assertEqual(cfg_file.read_bytes(), cfg_bytes)
            self.assertEqual(csv_file.read_bytes(), csv_bytes)
            self.assertEqual(baseline_file.read_bytes(), baseline_bytes)

            # 4. Malformed YAML + summary path equals the YAML file
            broken_bytes = b"version: 1\nsources: [unclosed_yaml\n"
            broken_yaml = tmp_path / "broken.yaml"
            broken_yaml.write_bytes(broken_bytes)
            res_malformed_alias = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(broken_yaml),
                    "--summary-file",
                    str(broken_yaml),
                ],
            )
            self.assertEqual(res_malformed_alias.exit_code, 2)
            self.assertEqual(broken_yaml.read_bytes(), broken_bytes)

            # 5. Missing configuration + existing summary destination (fail-closed protection)
            existing_note = tmp_path / "existing_notes.md"
            note_bytes = b"# User Notes\nDo not overwrite me.\n"
            existing_note.write_bytes(note_bytes)
            res_missing_existing = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(tmp_path / "nonexistent.yaml"),
                    "--summary-file",
                    str(existing_note),
                ],
            )
            self.assertEqual(res_missing_existing.exit_code, 2)
            self.assertEqual(existing_note.read_bytes(), note_bytes)

            # 6. Valid configuration + successful run + unsafe summary destination
            for protected_target in (cfg_file, csv_file, baseline_file):
                res_valid_prot = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(cfg_file),
                        "--summary-file",
                        str(protected_target),
                    ],
                )
                self.assertEqual(res_valid_prot.exit_code, 2)
            self.assertEqual(cfg_file.read_bytes(), cfg_bytes)
            self.assertEqual(csv_file.read_bytes(), csv_bytes)
            self.assertEqual(baseline_file.read_bytes(), baseline_bytes)

            # 7-8. Invalid CLI option (--bogus) & malformed configuration + $GITHUB_STEP_SUMMARY
            for protected_target in (cfg_file, csv_file, baseline_file, existing_note):
                env_gh = {**os.environ, "GITHUB_STEP_SUMMARY": str(protected_target)}
                runner.invoke(
                    app,
                    ["check", "--config", str(cfg_file), "--bogus"],
                    env=env_gh,
                )
                runner.invoke(
                    app,
                    ["check", "--config", str(broken_yaml)],
                    env=env_gh,
                )

            self.assertEqual(cfg_file.read_bytes(), cfg_bytes)
            self.assertEqual(csv_file.read_bytes(), csv_bytes)
            self.assertEqual(baseline_file.read_bytes(), baseline_bytes)
            self.assertEqual(existing_note.read_bytes(), note_bytes)

    def test_hardlinks_and_symlinks_never_bypass_file_protection(self) -> None:
        """Verify Critical Issue 2: hard links and symlinks to config, source, or baseline are blocked."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            csv_bytes = b"id,val\n1,100\n2,200\n"
            csv_file = tmp_path / "data.csv"
            csv_file.write_bytes(csv_bytes)
            cfg_file = tmp_path / "custom.yaml"

            res_init = runner.invoke(
                app,
                ["init", str(csv_file), "--name", "hl-src", "--config", str(cfg_file)],
            )
            self.assertEqual(res_init.exit_code, 0)
            cfg_bytes = cfg_file.read_bytes()
            baseline_file = tmp_path / "baselines" / "hl-src.json"
            baseline_bytes = baseline_file.read_bytes()

            # Create hard links with .md extensions pointing to config, CSV, and baseline
            hl_cfg = tmp_path / "summary_cfg.md"
            hl_csv = tmp_path / "summary_csv.md"
            hl_base = tmp_path / "summary_base.md"
            try:
                os.link(cfg_file, hl_cfg)
                os.link(csv_file, hl_csv)
                os.link(baseline_file, hl_base)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Filesystem does not support hard links: {exc}")

            # 1-4. Normal check targeting hard links to config, source CSV, and baseline
            for hl_target in (hl_cfg, hl_csv, hl_base):
                res_hl = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(cfg_file),
                        "--summary-file",
                        str(hl_target),
                    ],
                )
                self.assertEqual(res_hl.exit_code, 2)
                self.assertIn("Refusing to write", res_hl.output)

            # 5. Diagnostic fallback (--bogus) targeting hard links
            for hl_target in (hl_cfg, hl_csv, hl_base):
                res_hl_fb = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(cfg_file),
                        "--bogus",
                        "--summary-file",
                        str(hl_target),
                    ],
                )
                self.assertEqual(res_hl_fb.exit_code, 2)

            self.assertEqual(cfg_file.read_bytes(), cfg_bytes)
            self.assertEqual(csv_file.read_bytes(), csv_bytes)
            self.assertEqual(baseline_file.read_bytes(), baseline_bytes)

            # 6. Symbolic links resolving to protected files
            sym_csv = tmp_path / "symlink_summary.md"
            try:
                os.symlink(csv_file, sym_csv)
                res_sym = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(cfg_file),
                        "--summary-file",
                        str(sym_csv),
                    ],
                )
                self.assertEqual(res_sym.exit_code, 2)
                self.assertEqual(csv_file.read_bytes(), csv_bytes)
            except (OSError, NotImplementedError):
                pass

            # 7. Independent regular summary file still works normally
            indep_summary = tmp_path / "independent_summary.md"
            res_ok = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(cfg_file),
                    "--summary-file",
                    str(indep_summary),
                ],
            )
            self.assertEqual(res_ok.exit_code, 0)
            self.assertTrue(indep_summary.exists())
            self.assertIn("## Upstream Check Report — PASSED", indep_summary.read_text(encoding="utf-8"))
            self.assertEqual(cfg_file.read_bytes(), cfg_bytes)
            self.assertEqual(csv_file.read_bytes(), csv_bytes)
            self.assertEqual(baseline_file.read_bytes(), baseline_bytes)

    def test_early_cli_check_failures_and_invalid_cli_flags_write_diagnostic_summary(self) -> None:
        """Verify malformed YAML, missing config, AND unknown CLI options (--bogus) write new report.md."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bad_yaml = tmp_path / "broken.yaml"
            bad_yaml.write_text("version: 1\nsources: [unclosed_yaml\n", encoding="utf-8")
            report_md = tmp_path / "report.md"
            gh_summary = tmp_path / "gh_step_summary.md"

            env = {**os.environ, "GITHUB_STEP_SUMMARY": str(gh_summary)}
            res = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(bad_yaml),
                    "--summary-file",
                    str(report_md),
                ],
                env=env,
            )
            self.assertEqual(res.exit_code, 2)
            self.assertTrue(report_md.exists())
            self.assertTrue(gh_summary.exists())
            self.assertIn("EXECUTION ERROR", report_md.read_text(encoding="utf-8"))

            bogus_report = tmp_path / "bogus_report.md"
            res_bogus = runner.invoke(
                app,
                ["check", "--bogus", "--summary-file", str(bogus_report)],
            )
            self.assertEqual(res_bogus.exit_code, 2)
            self.assertTrue(bogus_report.exists())
            bogus_text = bogus_report.read_text(encoding="utf-8")
            self.assertIn("No such option: --bogus", bogus_text)
            self.assertIn("<!-- upstream-check-fingerprint:", bogus_text)

    def test_scheduled_workflow_failure_deduplication_missing_report_and_recovery(self) -> None:
        """Execute .github/workflows/upstream-check-schedule.yml across all failure, missing-report & recovery paths."""
        wf_path = REPO_ROOT / ".github" / "workflows" / "upstream-check-schedule.yml"
        wf_data = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
        steps = wf_data["jobs"]["verify-sources"]["steps"]
        failure_step_script = [s["run"] for s in steps if "Deduplicate" in s["name"]][0]
        recovery_step_script = [s["run"] for s in steps if "Recovery" in s["name"]][0]

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            state_file = tmp_path / "gh_issues.json"
            state_file.write_text("[]", encoding="utf-8")

            gh_mock_py = tmp_path / "gh_mock.py"
            gh_mock_py.write_text(
                f"""import json, pathlib, sys

state_path = pathlib.Path({str(state_file)!r})
issues = json.loads(state_path.read_text(encoding="utf-8"))
args = sys.argv[1:]

if args[:2] == ["issue", "list"]:
    open_issues = [i for i in issues if i["state"] == "open"]
    print(open_issues[0]["number"] if open_issues else "null")
elif args[:2] == ["issue", "view"]:
    num = int(args[2])
    issue = [i for i in issues if i["number"] == num][0]
    bodies = [issue["body"]] + [c["body"] for c in issue["comments"]]
    print(chr(10).join(bodies))
elif args[:2] == ["issue", "create"]:
    title = args[args.index("--title") + 1]
    body_file = args[args.index("--body-file") + 1]
    body = pathlib.Path(body_file).read_text(encoding="utf-8")
    issues.append({{"number": len(issues) + 1, "state": "open", "title": title, "body": body, "comments": []}})
    state_path.write_text(json.dumps(issues), encoding="utf-8")
elif args[:2] == ["issue", "comment"]:
    num = int(args[2])
    body_file = args[args.index("--body-file") + 1]
    body = pathlib.Path(body_file).read_text(encoding="utf-8")
    for i in issues:
        if i["number"] == num:
            i["comments"].append({{"body": body}})
    state_path.write_text(json.dumps(issues), encoding="utf-8")
elif args[:2] == ["issue", "close"]:
    num = int(args[2])
    comment = args[args.index("--comment") + 1]
    for i in issues:
        if i["number"] == num:
            i["state"] = "closed"
            i["comments"].append({{"body": comment}})
    state_path.write_text(json.dumps(issues), encoding="utf-8")
""",
                encoding="utf-8",
            )

            gh_preamble = (
                f'cd "{tmp_path}"\n'
                f'gh() {{ "{sys.executable}" "{gh_mock_py}" "$@"; }}\n'
            )
            env = {
                k: v
                for k, v in os.environ.items()
                if k != "BASH_ENV"
            }
            env["PYTHONPATH"] = str(REPO_ROOT / "src")
            env["GH_REPO"] = "siddhant3895/upstream-check"
            runner = CliRunner()
            report_file = tmp_path / "report.md"

            # Step 1: Degraded feed at T=62h fails and opens Issue #1
            res1 = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(REPO_ROOT / "examples" / "upstream-check.degraded.yaml"),
                    "--now",
                    "2026-11-13T12:00:00Z",
                    "--summary-file",
                    str(report_file),
                ],
            )
            self.assertEqual(res1.exit_code, 1)
            proc1 = subprocess.run(
                ["bash", "--norc", "--noprofile", "-e", "-c", gh_preamble + failure_step_script],
                cwd=str(tmp_path),
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc1.returncode, 1)
            issues = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(len(issues), 1)

            # Step 2: Human posts a comment on Issue #1, then 6h later (T=68h) cron runs again on same incident
            issues[0]["comments"].append({"body": "Investigating with upstream team."})
            state_file.write_text(json.dumps(issues), encoding="utf-8")

            res2 = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(REPO_ROOT / "examples" / "upstream-check.degraded.yaml"),
                    "--now",
                    "2026-11-13T18:00:00Z",
                    "--summary-file",
                    str(report_file),
                ],
            )
            self.assertEqual(res2.exit_code, 1)
            proc2 = subprocess.run(
                ["bash", "--norc", "--noprofile", "-e", "-c", gh_preamble + failure_step_script],
                cwd=str(tmp_path),
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc2.returncode, 1)
            self.assertIn("skipping duplicate comment", proc2.stdout)
            issues = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(len(issues[0]["comments"]), 1)

            # Step 3: Simulate CLI process crashing BEFORE report.md is created (runner-level fallback branch)
            report_file.unlink()
            (tmp_path / "check_stderr.log").write_text(
                "Fatal Python error: runner killed at PID 4129\n", encoding="utf-8"
            )
            proc_missing = subprocess.run(
                ["bash", "--norc", "--noprofile", "-e", "-c", gh_preamble + failure_step_script],
                cwd=str(tmp_path),
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc_missing.returncode, 1)
            self.assertTrue(report_file.exists(), "Runner fallback must synthesize report.md")
            issues = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(len(issues[0]["comments"]), 2)
            self.assertIn("Fatal Python error", issues[0]["comments"][-1]["body"])

            # Step 4: Same runner crash with different PID normalizes to same fingerprint -> deduplicated
            report_file.unlink()
            (tmp_path / "check_stderr.log").write_text(
                "Fatal Python error: runner killed at PID 9881\n", encoding="utf-8"
            )
            proc_missing_dup = subprocess.run(
                ["bash", "--norc", "--noprofile", "-e", "-c", gh_preamble + failure_step_script],
                cwd=str(tmp_path),
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc_missing_dup.returncode, 1)
            self.assertIn("skipping duplicate comment", proc_missing_dup.stdout)
            issues = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(len(issues[0]["comments"]), 2)

            # Step 5: Healthy feed passes -> auto-closes Issue #1
            report_file.unlink()
            res4 = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(REPO_ROOT / "upstream-check.yaml"),
                    "--now",
                    "2026-11-13T12:00:00Z",
                    "--summary-file",
                    str(report_file),
                ],
            )
            self.assertEqual(res4.exit_code, 0)
            subprocess.run(
                ["bash", "--norc", "--noprofile", "-e", "-c", gh_preamble + recovery_step_script],
                cwd=str(tmp_path),
                env=env,
                check=True,
            )
            issues = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(issues[0]["state"], "closed")

    def test_empty_dataset_triggers_baseline_row_drop_and_direct_min_rows(self) -> None:
        src = SourceConfig(
            name="drop-test",
            url="https://example.org/empty.csv",
            format="csv",
            quality=QualityConfig(min_rows=0, max_row_drop_pct=50.0),
        )
        base = BaselineModel(
            version=1,
            source_name="drop-test",
            endpoint_redacted=src.url,
            format="csv",
            captured_at="2026-11-13T00:00:00Z",
            row_count=10,
            column_order=["id", "val"],
            columns={
                "id": ColumnBaseline("id", "string", 0, 10, 0.0),
                "val": ColumnBaseline("val", "number", 0, 10, 0.0),
            },
        )
        empty_ds = FetchedDataset(
            source_name="drop-test",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=["id", "val"],
            rows=[],
        )
        q_findings = run_quality_checks(src, empty_ds, baseline=base)
        failed = [f for f in q_findings if not f.passed]
        self.assertEqual(len(failed), 1)
        self.assertIn("Row count dropped by 100% (0 vs 10)", failed[0].title)

        src_min5 = SourceConfig(
            name="min5-test",
            url="https://example.org/empty.csv",
            format="csv",
            quality=QualityConfig(min_rows=5),
        )
        q_min5 = [f for f in run_quality_checks(src_min5, empty_ds) if not f.passed]
        self.assertEqual(len(q_min5), 1)
        self.assertEqual(q_min5[0].title, "Row count below minimum: 0")

    def test_metric_invariant_incident_fingerprint_is_stable_across_staleness_hours(self) -> None:
        src = SourceConfig(
            name="air-quality",
            url="https://example.org/data.csv",
            format="csv",
            freshness=FreshnessConfig(column="observed_at", max_age="36h"),
        )
        ds = FetchedDataset(
            source_name="air-quality",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=["station_id", "observed_at"],
            rows=[{"station_id": "ST1", "observed_at": "2026-11-10T22:00:00Z"}],
        )
        f_62h = run_freshness_checks(src, ds, reference_time=self.ref_now)
        f_74h = run_freshness_checks(
            src,
            ds,
            reference_time=datetime(2026, 11, 14, 0, 0, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(f_62h[0].title, "Data is 62 hours old")
        self.assertEqual(f_74h[0].title, "Data is 74 hours old")

        from upstream_check.core.models import SourceCheckResult

        rep_62h = EngineReport(
            results=[SourceCheckResult("air-quality", src.url, "csv", findings=f_62h)]
        )
        rep_74h = EngineReport(
            results=[SourceCheckResult("air-quality", src.url, "csv", findings=f_74h)]
        )
        fp_62h = compute_incident_fingerprint(rep_62h)
        fp_74h = compute_incident_fingerprint(rep_74h)
        self.assertTrue(len(fp_62h) == 64)
        self.assertEqual(fp_62h, fp_74h)

        md_out = format_markdown_report(rep_62h)
        self.assertIn(f"<!-- upstream-check-fingerprint:{fp_62h} -->", md_out)
        json_out = json.loads(format_json_report(rep_62h))
        self.assertEqual(json_out["incident_fingerprint"], fp_62h)

        fp_err1 = compute_execution_error_fingerprint("YAML syntax error at line 4, column 12", 2)
        fp_err2 = compute_execution_error_fingerprint("YAML syntax error at line 19, column 3", 2)
        self.assertEqual(fp_err1, fp_err2)
        self.assertIn(fp_err1, format_execution_error_markdown("YAML syntax error at line 4, column 12", 2))

    def test_zero_tolerance_thresholds_pass_unchanged_and_fail_over_threshold(self) -> None:
        src_zero = SourceConfig(
            name="zero-tol",
            url="https://example.org/data.csv",
            format="csv",
            quality=QualityConfig(max_null_spike_pct=0.0, max_row_drop_pct=0.0),
        )
        ds = FetchedDataset(
            source_name="zero-tol",
            endpoint=src_zero.url,
            redacted_endpoint=src_zero.url,
            available=True,
            headers=["id", "val"],
            rows=[{"id": "1", "val": "10"}, {"id": "2", "val": "20"}],
        )
        base = build_baseline(src_zero, ds, captured_at=self.ref_now)

        findings_same = run_quality_checks(src_zero, ds, baseline=base)
        self.assertTrue(all(f.passed for f in findings_same))

        src_50 = SourceConfig(
            name="exact-50",
            url="https://example.org/data.csv",
            format="csv",
            quality=QualityConfig(max_null_spike_pct=50.0, max_row_drop_pct=50.0),
        )
        ds_1row_null = FetchedDataset(
            source_name="exact-50",
            endpoint=src_50.url,
            redacted_endpoint=src_50.url,
            available=True,
            headers=["id", "val"],
            rows=[{"id": "1", "val": "10"}, {"id": "2", "val": ""}],
        )
        findings_exact = run_quality_checks(src_50, ds_1row_null, baseline=base)
        self.assertTrue(all(f.passed for f in findings_exact))

        src_49 = SourceConfig(
            name="over-49",
            url="https://example.org/data.csv",
            format="csv",
            quality=QualityConfig(max_null_spike_pct=49.9, max_row_drop_pct=49.9),
        )
        ds_dropped = FetchedDataset(
            source_name="over-49",
            endpoint=src_49.url,
            redacted_endpoint=src_49.url,
            available=True,
            headers=["id", "val"],
            rows=[{"id": "1", "val": ""}],
        )
        findings_over = [f for f in run_quality_checks(src_49, ds_dropped, baseline=base) if not f.passed]
        self.assertEqual(len(findings_over), 2)

    def test_non_numeric_and_infinite_values_fail_numeric_range_rules(self) -> None:
        src = SourceConfig(
            name="range-test",
            url="https://example.org/data.csv",
            format="csv",
            columns={"value": ColumnRuleConfig(min=0, max=100)},
        )
        for bad_cell in ("not-a-number", "inf", "-Infinity"):
            ds = FetchedDataset(
                source_name="range-test",
                endpoint=src.url,
                redacted_endpoint=src.url,
                available=True,
                headers=["value"],
                rows=[{"value": bad_cell}],
            )
            findings = [f for f in run_quality_checks(src, ds) if not f.passed]
            self.assertEqual(len(findings), 1)
            self.assertIn("non-numeric value(s) violating numeric bounds", findings[0].title)

    def test_realistic_usgs_live_config_and_complete_30_column_baseline(self) -> None:
        live_cfg_path = REPO_ROOT / "examples" / "real-world" / "upstream-check.live.yaml"
        cfg = load_config(live_cfg_path)
        usgs_src = cfg.sources[0]

        baseline_data = json.loads(
            (
                REPO_ROOT
                / "examples"
                / "real-world"
                / "baselines"
                / "usgs-earthquakes-hourly.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(len(baseline_data["column_order"]), 30)
        self.assertEqual(len(baseline_data["columns"]), 30)
        baseline = BaselineModel.from_dict(baseline_data)

        features = []
        for i in range(7):
            features.append(
                {
                    "type": "Feature",
                    "id": f"us7000eq{i}",
                    "properties": {
                        "mag": 1.2 + i * 0.4,
                        "place": f"{10 + i}km S of Ridgecrest, CA",
                        "time": 1794570000000 + i * 60000,
                        "updated": 1794570100000 + i * 60000,
                        "tz": None,
                        "url": f"https://earthquake.usgs.gov/earthquakes/eventpage/us7000eq{i}",
                        "detail": f"https://earthquake.usgs.gov/fdsnws/event/1/query?eventid=us7000eq{i}",
                        "felt": None,
                        "cdi": None,
                        "mmi": None,
                        "alert": None,
                        "status": "automatic",
                        "tsunami": 0,
                        "sig": 22 + i,
                        "net": "ci",
                        "code": f"7000eq{i}",
                        "ids": f",us7000eq{i},",
                        "sources": ",ci,",
                        "types": ",origin,phase-data,",
                        "nst": 18,
                        "dmin": 0.04,
                        "rms": 0.12,
                        "gap": 65,
                        "magType": "ml",
                        "type": "earthquake",
                        "title": f"M {1.2 + i * 0.4:.1f} - {10 + i}km S of Ridgecrest, CA",
                    },
                    "geometry": {
                        "type": "Point",
                        "coordinates": [-117.6, 35.7, 8.2],
                    },
                }
            )
        raw_usgs_json = json.dumps({"type": "FeatureCollection", "features": features})
        headers, rows = parse_json_content(
            raw_usgs_json,
            records_path=usgs_src.json_records_path,
            flatten=usgs_src.flatten_json,
        )
        ds = FetchedDataset(
            source_name=usgs_src.name,
            endpoint=usgs_src.url,
            redacted_endpoint=usgs_src.url,
            available=True,
            status_code=200,
            headers=headers,
            rows=rows,
        )

        s_findings = run_schema_checks(usgs_src, ds, baseline=baseline)
        q_findings = run_quality_checks(usgs_src, ds, baseline=baseline)
        f_findings = run_freshness_checks(
            usgs_src,
            ds,
            reference_time=datetime.fromtimestamp(1794570600, tz=timezone.utc),
        )
        all_failed = [
            f for f in (s_findings + q_findings + f_findings) if not f.passed
        ]
        self.assertEqual(len(all_failed), 0, msg=f"Unexpected failures: {all_failed}")

    def test_csv_ragged_row_widths_and_all_null_columns_fail_schema(self) -> None:
        ragged_csv = "id,value\n1,ok,UNEXPECTED\n2,ok\n"
        headers, rows, dup_headers, malformed = parse_csv_content(ragged_csv)
        self.assertEqual(len(malformed), 1)
        self.assertEqual(malformed[0], (2, 2, 3))

        src = SourceConfig(
            name="ragged-test",
            url="https://example.org/ragged.csv",
            format="csv",
            columns={"id": ColumnRuleConfig(type="string"), "value": ColumnRuleConfig(type="number")},
        )
        ds = FetchedDataset(
            source_name="ragged-test",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=headers,
            malformed_rows=malformed,
            rows=[{"id": "1", "value": ""}, {"id": "2", "value": None}],
        )
        findings = run_schema_checks(src, ds)
        failed_titles = [f.title for f in findings if not f.passed]
        self.assertIn("Malformed CSV row width in 1 row(s)", failed_titles)
        self.assertIn("Column value contains only null values", failed_titles)

    def test_empty_dataset_with_headers_still_validates_schema_columns(self) -> None:
        src = SourceConfig(
            name="empty-rows-test",
            url="https://example.org/empty.csv",
            format="csv",
            columns={
                "station_id": ColumnRuleConfig(required=True, type="string"),
                "pm25": ColumnRuleConfig(required=True, type="number"),
            },
            quality=QualityConfig(min_rows=0),
        )
        ds = FetchedDataset(
            source_name="empty-rows-test",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=["station_id"],
            rows=[],
        )
        findings = run_schema_checks(src, ds)
        failed_titles = [f.title for f in findings if not f.passed]
        self.assertIn("Missing required column: pm25", failed_titles)

    def test_max_response_bytes_limit_enforced(self) -> None:
        src = SourceConfig(
            name="oversized",
            url=str(REPO_ROOT / "examples" / "data" / "air_quality_healthy.csv"),
            format="csv",
            max_response_bytes=100,
        )
        ds = fetch_local_source(src, base_dir=str(REPO_ROOT))
        self.assertFalse(ds.available)
        self.assertIn("exceeds max_response_bytes", ds.error_message or "")

    def test_availability_unreachable_and_empty(self) -> None:
        src = SourceConfig(name="test-src", url="https://example.org/data.csv", format="csv")
        unreachable_ds = FetchedDataset(
            source_name="test-src",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=False,
            status_code=503,
            error_message="HTTP 503 response received",
        )
        findings = run_availability_checks(src, unreachable_ds)
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0].passed)

        empty_ds = FetchedDataset(
            source_name="test-src",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            status_code=200,
            headers=["a", "b"],
            rows=[],
        )
        findings_empty = run_availability_checks(src, empty_ds)
        self.assertEqual(len(findings_empty), 2)
        self.assertTrue(findings_empty[0].passed)
        self.assertFalse(findings_empty[1].passed)
        self.assertIn("empty dataset", findings_empty[1].title)

    def test_schema_detects_type_change_missing_renamed_optional_and_duplicate_headers(self) -> None:
        src = SourceConfig(
            name="air-quality",
            url="https://example.org/data.csv",
            format="csv",
            columns={
                "station_id": ColumnRuleConfig(required=True, type="string"),
                "pm25": ColumnRuleConfig(required=True, type="number"),
            },
        )
        healthy_csv = "\n".join(
            [
                "station_id,pm25,city",
                "ST1,25.4,Nagpur",
                "ST2,31.0,Delhi",
            ]
        )
        healthy_headers, healthy_rows, _, _ = parse_csv_content(healthy_csv)
        healthy_ds = FetchedDataset(
            source_name="air-quality",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=healthy_headers,
            rows=healthy_rows,
        )
        baseline = build_baseline(src, healthy_ds, captured_at=self.ref_now)

        bad_csv = "\n".join(
            [
                "station_id,pm25,location",
                "ST1,invalid_str,Nagpur",
                "ST2,40.0,Delhi",
            ]
        )
        bad_headers, bad_rows, _, _ = parse_csv_content(bad_csv)
        bad_ds = FetchedDataset(
            source_name="air-quality",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=bad_headers,
            rows=bad_rows,
        )
        findings = run_schema_checks(src, bad_ds, baseline=baseline)
        failed_titles = [f.title for f in findings if not f.passed]
        self.assertIn("Column city renamed to location", failed_titles)
        self.assertIn("Column pm25 changed type", failed_titles)

        opt_src = SourceConfig(
            name="s",
            url="u",
            format="csv",
            columns={"opt_col": ColumnRuleConfig(required=False)},
        )
        opt_base = BaselineModel(
            version=1,
            source_name="s",
            endpoint_redacted="u",
            format="csv",
            captured_at="now",
            row_count=1,
            column_order=["id", "opt_col"],
            columns={
                "id": ColumnBaseline("id", "string", 0, 1, 0.0),
                "opt_col": ColumnBaseline("opt_col", "string", 0, 1, 0.0),
            },
        )
        opt_ds = FetchedDataset(
            source_name="s",
            endpoint="u",
            redacted_endpoint="u",
            available=True,
            headers=["id"],
            rows=[{"id": "101"}],
        )
        opt_findings = [
            f for f in run_schema_checks(opt_src, opt_ds, baseline=opt_base) if not f.passed
        ]
        self.assertEqual(len(opt_findings), 0)

        dup_csv = "station_id,pm25,pm25\nST1,10,20\n"
        dup_headers, dup_rows, dup_list, _ = parse_csv_content(dup_csv)
        self.assertEqual(dup_list, ["pm25"])
        dup_ds = FetchedDataset(
            source_name="air-quality",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=dup_headers,
            duplicate_headers=dup_list,
            rows=dup_rows,
        )
        dup_findings = run_schema_checks(src, dup_ds)
        self.assertTrue(
            any("Duplicate CSV header" in f.title for f in dup_findings if not f.passed)
        )

    def test_nested_json_flattening_and_semicolon_csv(self) -> None:
        raw_json = json.dumps(
            {
                "features": [
                    {
                        "id": "eq-1",
                        "properties": {"mag": 4.6, "place": "Nagpur"},
                        "geometry": {"type": "Point"},
                    }
                ]
            }
        )
        headers, rows = parse_json_content(raw_json, flatten=True)
        self.assertIn("properties.mag", headers)
        self.assertIn("properties.place", headers)
        self.assertEqual(rows[0]["properties.mag"], 4.6)

        semi_csv = "station_id;pm25;city\nST1;42.5;Nagpur\nST2;55.0;Mumbai\n"
        c_headers, c_rows, _, _ = parse_csv_content(semi_csv)
        self.assertEqual(c_headers, ["station_id", "pm25", "city"])
        self.assertEqual(c_rows[0]["pm25"], "42.5")

    def test_missing_baseline_file_fails_loudly(self) -> None:
        src = SourceConfig(
            name="air-quality",
            url=str(REPO_ROOT / "examples" / "data" / "air_quality_healthy.csv"),
            format="csv",
            schema=SchemaConfig(baseline="baselines/does_not_exist.json"),
        )
        res = run_source_checks(src, base_dir=REPO_ROOT, reference_time=self.ref_now)
        self.assertFalse(res.passed)
        titles = [f.title for f in res.failed_findings]
        self.assertIn(
            "Configured baseline file not found: baselines/does_not_exist.json",
            titles,
        )

    def test_quality_detects_multi_column_nulls_row_drop_missing_unique_and_allowed_values(self) -> None:
        src = SourceConfig(
            name="air-quality",
            url="https://example.org/data.csv",
            format="json",
            columns={
                "pm25": ColumnRuleConfig(type="number", min=0, max=500),
                "status": ColumnRuleConfig(type="string", allowed_values=["ok", "maintenance"]),
            },
            quality=QualityConfig(
                max_null_pct=10,
                max_row_drop_pct=50.0,
                unique=["station_id", "meta"],
            ),
        )
        rows = [
            {"station_id": "ST1", "pm25": 550, "pm10": None, "status": "ok", "meta": {"v": 1}},
            {"station_id": "ST1", "pm25": None, "pm10": None, "status": "corrupt", "meta": {"v": 1}},
            {"station_id": "ST3", "pm25": None, "pm10": 40, "status": "ok", "meta": {"v": 2}},
            {"station_id": "ST4", "pm25": 40, "pm10": 50, "status": "ok", "meta": {"v": 3}},
        ]
        ds = FetchedDataset(
            source_name="air-quality",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=["station_id", "pm25", "pm10", "status", "meta"],
            rows=rows,
        )
        baseline = build_baseline(src, ds, captured_at=self.ref_now)
        baseline.row_count = 20

        findings = run_quality_checks(src, ds, baseline=baseline)
        failed = [f for f in findings if not f.passed]
        titles = " | ".join(f.title for f in failed)
        self.assertIn("Missing values in pm25: 50%", titles)
        self.assertIn("Missing values in pm10: 50%", titles)
        self.assertIn("outside allowed range", titles)
        self.assertIn("disallowed value(s)", titles)
        self.assertIn("Duplicate records detected: 1", titles)
        self.assertIn("Row count dropped by 80%", titles)

        src_missing_u = SourceConfig(
            name="s", url="u", quality=QualityConfig(unique=["non_existent_id"])
        )
        findings_u = run_quality_checks(src_missing_u, ds)
        self.assertTrue(
            any("Unique key column(s) missing" in f.title for f in findings_u if not f.passed)
        )

    def test_freshness_detects_stale_future_and_corrupted_timestamp_ratios(self) -> None:
        src = SourceConfig(
            name="air-quality",
            url="https://example.org/data.csv",
            format="csv",
            freshness=FreshnessConfig(column="observed_at", max_age="36h"),
        )
        raw_csv = "station_id,observed_at\nST1,2026-11-10T22:00:00Z\n"
        headers, rows, _, _ = parse_csv_content(raw_csv)
        ds = FetchedDataset(
            source_name="air-quality",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=headers,
            rows=rows,
        )
        findings = run_freshness_checks(src, ds, reference_time=self.ref_now)
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0].passed)
        self.assertEqual(findings[0].title, "Data is 62 hours old")

        future_ds = FetchedDataset(
            source_name="air-quality",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=["station_id", "observed_at"],
            rows=[{"station_id": "ST1", "observed_at": "2036-11-13T12:00:00Z"}],
        )
        future_findings = run_freshness_checks(src, future_ds, reference_time=self.ref_now)
        self.assertEqual(len(future_findings), 1)
        self.assertFalse(future_findings[0].passed)
        self.assertIn("in the future", future_findings[0].title)

        corrupt_ds = FetchedDataset(
            source_name="air-quality",
            endpoint=src.url,
            redacted_endpoint=src.url,
            available=True,
            headers=["station_id", "observed_at"],
            rows=[
                {"station_id": "ST1", "observed_at": "2026-11-13T11:30:00Z"},
                {"station_id": "ST2", "observed_at": "corrupt_date"},
                {"station_id": "ST3", "observed_at": "bad_ts"},
                {"station_id": "ST4", "observed_at": ""},
            ],
        )
        corrupt_findings = run_freshness_checks(src, corrupt_ds, reference_time=self.ref_now)
        self.assertTrue(
            any("invalid or missing timestamps" in f.title for f in corrupt_findings if not f.passed)
        )

    def test_end_to_end_degraded_fixture_matches_canonical_cli_output(self) -> None:
        cfg = load_config(REPO_ROOT / "examples" / "upstream-check.degraded.yaml")
        report = run_all_checks(
            cfg,
            base_dir=(REPO_ROOT / "examples").resolve(),
            reference_time=self.ref_now,
        )
        self.assertFalse(report.passed)
        self.assertEqual(report.total_failed_findings, 3)

        report.results[0].endpoint = "https://example.org/data.csv"
        terminal_out = format_terminal_report(report, color=False)
        expected_block = """UPSTREAM CHECK

Source: air-quality
Endpoint: https://example.org/data.csv

SOURCE AVAILABILITY
  ✓ HTTP response received

SCHEMA VALIDATION
  ✓ Required columns present
  ✗ Column pm25 changed type
    Expected: number
    Received: string

DATA QUALITY
  ✗ Missing values: 42%
    Previous baseline: 2%

FRESHNESS
  ✗ Data is 62 hours old
    Maximum allowed: 36 hours

--------------------------------
RESULT: FAILED
3 findings require attention."""
        self.assertEqual(terminal_out.strip(), expected_block.strip())

    def test_mcp_2026_07_28_and_legacy_strict_request_and_version_validation(self) -> None:
        """Verify MCP error schemas, unknown-tool -32602, falsey/null arguments, and legacy negotiation."""
        for bad_disc in (
            {"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
            {"jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": {"_meta": {}}},
        ):
            resp = handle_mcp_request(bad_disc)
            assert resp is not None
            self.assertEqual(resp["error"]["code"], -32602)

        unsup_resp = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "1900-01-01",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            }
        )
        assert unsup_resp is not None
        self.assertEqual(unsup_resp["error"]["code"], -32022)
        self.assertEqual(unsup_resp["error"]["data"]["requested"], "1900-01-01")
        self.assertIn("2026-07-28", unsup_resp["error"]["data"]["supported"])
        self.assertNotIn("supportedVersions", unsup_resp["error"]["data"])

        hybrid_legacy = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            }
        )
        assert hybrid_legacy is not None
        self.assertEqual(hybrid_legacy["error"]["code"], -32022)
        self.assertEqual(hybrid_legacy["error"]["data"]["requested"], "2025-11-25")
        self.assertEqual(hybrid_legacy["error"]["data"]["supported"], ["2026-07-28"])

        modern_meta = {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        unk_tool = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "_meta": modern_meta,
                    "name": "nonexistent_tool",
                    "arguments": {},
                },
            }
        )
        assert unk_tool is not None
        self.assertIn("error", unk_tool)
        self.assertNotIn("result", unk_tool)
        self.assertEqual(unk_tool["error"]["code"], -32602)
        self.assertIn("Unknown tool: nonexistent_tool", unk_tool["error"]["message"])

        init_2025_06 = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1.0.0"},
                },
            }
        )
        assert init_2025_06 is not None
        self.assertEqual(init_2025_06["result"]["protocolVersion"], "2025-06-18")

        init_negotiate = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-10-07",
                    "capabilities": {},
                    "clientInfo": {"name": "c", "version": "1.0.0"},
                },
            }
        )
        assert init_negotiate is not None
        self.assertEqual(init_negotiate["result"]["protocolVersion"], "2025-11-25")

    def test_mcp_arguments_omitted_vs_null_and_invalid_types_never_execute_tools(self) -> None:
        """Verify Critical Issue 3: arguments: null, [], '', 0, false are rejected without executing tools."""
        modern_meta = {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        legacy_session = {"mode": "legacy", "protocolVersion": "2025-11-25"}

        invalid_argument_values = [
            None,
            [],
            "",
            0,
            False,
            True,
            42,
            {"source": None},
            {"config_path": None},
            {"unknown_field": "x"},
        ]

        with mock.patch("upstream_check.mcp.load_config") as mock_load_cfg, mock.patch(
            "upstream_check.mcp.run_all_checks"
        ) as mock_run_checks:
            for bad_val in invalid_argument_values:
                # 1. Modern 2026-07-28 mode
                resp_mod = handle_mcp_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 100,
                        "method": "tools/call",
                        "params": {
                            "_meta": modern_meta,
                            "name": "check_upstream_sources",
                            "arguments": bad_val,
                        },
                    }
                )
                assert resp_mod is not None
                self.assertIn("error", resp_mod, f"Modern mode must reject arguments={bad_val!r}")
                self.assertNotIn("result", resp_mod)
                self.assertEqual(resp_mod["error"]["code"], -32602)

                # 2. Legacy initialized session mode
                resp_leg = handle_mcp_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 101,
                        "method": "tools/call",
                        "params": {
                            "name": "check_upstream_sources",
                            "arguments": bad_val,
                        },
                    },
                    session=legacy_session,
                )
                assert resp_leg is not None
                self.assertIn("error", resp_leg, f"Legacy mode must reject arguments={bad_val!r}")
                self.assertNotIn("result", resp_leg)
                self.assertEqual(resp_leg["error"]["code"], -32602)

            mock_load_cfg.assert_not_called()
            mock_run_checks.assert_not_called()

        # Verify valid cases: arguments omitted, arguments: {}, and populated arguments object
        orig_cwd = os.getcwd()
        try:
            os.chdir(REPO_ROOT)
            for valid_params_mod in (
                {"_meta": modern_meta, "name": "check_upstream_sources"},
                {"_meta": modern_meta, "name": "check_upstream_sources", "arguments": {}},
                {
                    "_meta": modern_meta,
                    "name": "check_upstream_sources",
                    "arguments": {
                        "config_path": str(REPO_ROOT / "upstream-check.yaml"),
                        "source": "air-quality",
                    },
                },
            ):
                ok_mod = handle_mcp_request(
                    {"jsonrpc": "2.0", "id": 200, "method": "tools/call", "params": valid_params_mod}
                )
                assert ok_mod is not None
                self.assertIn("result", ok_mod)
                self.assertEqual(ok_mod["result"]["resultType"], "complete")

            for valid_params_leg in (
                {"name": "check_upstream_sources"},
                {"name": "check_upstream_sources", "arguments": {}},
                {
                    "name": "check_upstream_sources",
                    "arguments": {
                        "config_path": str(REPO_ROOT / "upstream-check.yaml"),
                        "source": "air-quality",
                    },
                },
            ):
                ok_leg = handle_mcp_request(
                    {"jsonrpc": "2.0", "id": 201, "method": "tools/call", "params": valid_params_leg},
                    session=legacy_session,
                )
                assert ok_leg is not None
                self.assertIn("result", ok_leg)
                self.assertIn("content", ok_leg["result"])
        finally:
            os.chdir(orig_cwd)

    def test_mcp_stdio_interoperability_with_strict_2026_and_legacy_clients(self) -> None:
        """Verify separate spec-enforcing 2026-07-28 and legacy 2025-06-18 clients over real stdio pipes."""
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}

        proc_modern = subprocess.Popen(
            [sys.executable, "-m", "upstream_check", "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            modern_client = SpecCompliantMCP2026Client(proc_modern)
            disc_res = modern_client.discover()
            self.assertEqual(
                disc_res["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
                "0.2.13",
            )
            tools = modern_client.list_tools()
            self.assertEqual(len(tools), 2)
            call_res = modern_client.call_tool(
                "inspect_baseline",
                {
                    "config_path": str(REPO_ROOT / "upstream-check.yaml"),
                    "source": "air-quality",
                },
            )
            self.assertFalse(call_res["isError"])
            baseline_json = json.loads(call_res["content"][0]["text"])
            self.assertEqual(baseline_json["source_name"], "air-quality")
        finally:
            for stream in (proc_modern.stdin, proc_modern.stdout, proc_modern.stderr):
                if stream:
                    stream.close()
            proc_modern.wait(timeout=5)

        proc_legacy = subprocess.Popen(
            [sys.executable, "-m", "upstream_check", "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            legacy_client = SpecCompliantMCPLegacyClient(
                proc_legacy, protocol_version="2025-06-18"
            )
            init_res = legacy_client.connect_and_handshake()
            self.assertEqual(init_res["protocolVersion"], "2025-06-18")
            self.assertEqual(init_res["serverInfo"]["version"], "0.2.13")
            ping_res = legacy_client.request("ping")
            self.assertEqual(ping_res["result"], {})
            legacy_call = legacy_client.request(
                "tools/call",
                {
                    "name": "inspect_baseline",
                    "arguments": {
                        "config_path": str(REPO_ROOT / "upstream-check.yaml"),
                        "source": "air-quality",
                    },
                },
            )
            self.assertFalse(legacy_call["result"]["isError"])
            self.assertNotIn("resultType", legacy_call["result"])
        finally:
            for stream in (proc_legacy.stdin, proc_legacy.stdout, proc_legacy.stderr):
                if stream:
                    stream.close()
            proc_legacy.wait(timeout=5)

    def test_wheel_build_and_entry_point_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    f"import setuptools.build_meta as bm; print(bm.build_wheel({tmp!r}))",
                ],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            whl_name = proc.stdout.strip().splitlines()[-1]
            whl_path = Path(tmp) / whl_name
            self.assertTrue(whl_path.exists())
            with zipfile.ZipFile(whl_path, "r") as zf:
                names = zf.namelist()
                self.assertIn("upstream_check/__init__.py", names)
                self.assertIn("upstream_check/cli/app.py", names)
                self.assertTrue(any(n.endswith("entry_points.txt") for n in names))

    def test_live_http_server_env_url_interpolation_and_cli_commands(self) -> None:
        data_dir = REPO_ROOT / "examples" / "data"
        handler = functools.partial(QuietHTTPHandler, directory=str(data_dir))
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()

            runner = CliRunner()
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                cfg_path = tmp_path / "upstream-check.yaml"
                summary_path = tmp_path / "step_summary.md"

                os.environ["DEMO_API_TOKEN"] = "live_token_abc"
                json_url = (
                    f"http://127.0.0.1:{port}/air_quality_api_healthy.json?api_key=${{DEMO_API_TOKEN}}"
                )
                res_init = runner.invoke(
                    app,
                    [
                        "init",
                        json_url,
                        "--name",
                        "air-quality-json",
                        "--config",
                        str(cfg_path),
                    ],
                )
                self.assertEqual(res_init.exit_code, 0, msg=res_init.output)
                yaml_text = cfg_path.read_text(encoding="utf-8")
                self.assertNotIn("live_token_abc", yaml_text)
                self.assertIn("${DEMO_API_TOKEN}", yaml_text)

                res_b_update = runner.invoke(
                    app,
                    ["baseline", "update", "--config", str(cfg_path)],
                )
                self.assertEqual(res_b_update.exit_code, 0, msg=res_b_update.output)

                res_check = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(cfg_path),
                        "--now",
                        "2026-11-13T12:00:00Z",
                        "--summary-file",
                        str(summary_path),
                    ],
                )
                self.assertEqual(res_check.exit_code, 0, msg=res_check.output)
                self.assertNotIn("live_token_abc", res_check.output)
                self.assertIn("RESULT: PASSED", res_check.output)

            httpd.shutdown()

    def test_rename_disambiguation_encoding_fallback_and_concurrent_sources(self) -> None:
        s = SourceConfig(name="t", url="u", format="csv")
        b_ds = FetchedDataset(
            "t",
            "u",
            "u",
            True,
            headers=["id", "unit_ratio", "city"],
            rows=[
                {"id": "1", "unit_ratio": "0.5", "city": "Nagpur"},
                {"id": "2", "unit_ratio": "0.8", "city": "Mumbai"},
            ],
        )
        base = build_baseline(s, b_ds, captured_at=self.ref_now)
        new_ds = FetchedDataset(
            "t",
            "u",
            "u",
            True,
            headers=["id", "population", "city"],
            rows=[
                {"id": "1", "population": "2500000", "city": "Nagpur"},
                {"id": "2", "population": "12000000", "city": "Mumbai"},
            ],
        )
        s_findings = [f.title for f in run_schema_checks(s, new_ds, baseline=base) if not f.passed]
        self.assertIn("Missing required column: unit_ratio", s_findings)
        self.assertIn("Unexpected new column: population", s_findings)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            latin_csv = tmp_path / "latin.csv"
            latin_csv.write_bytes("id,city\n1,Montr\xe9al\n".encode("latin-1"))
            src_latin = SourceConfig(name="latin-src", url=str(latin_csv), format="csv")
            ds_latin = fetch_local_source(src_latin, base_dir=str(tmp_path))
            self.assertTrue(ds_latin.available)
            self.assertEqual(ds_latin.rows[0]["city"], "Montréal")

            cfg_multi = UpstreamCheckConfig(
                version=1,
                sources=[
                    SourceConfig(name="src-1", url=str(latin_csv), format="csv"),
                    SourceConfig(name="src-2", url=str(latin_csv), format="csv"),
                    SourceConfig(name="src-3", url=str(latin_csv), format="csv"),
                ],
            )
            rep_multi = run_all_checks(cfg_multi, base_dir=tmp_path, max_workers=3)
            self.assertTrue(rep_multi.passed)
            self.assertEqual([r.source_name for r in rep_multi.results], ["src-1", "src-2", "src-3"])


    def test_canonical_local_source_resolver_matrix(self) -> None:
        """Verify Section 9 local-source representation classification matrix across all 11 forms."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            sub_dir = tmp_path / "data"
            sub_dir.mkdir(parents=True, exist_ok=True)
            csv_file = sub_dir / "input.csv"
            csv_file.write_text("id,val\n1,10\n", encoding="utf-8")
            spaced_file = sub_dir / "air quality #1.csv"
            spaced_file.write_text("id,val\n1,20\n", encoding="utf-8")

            # 1. Relative path -> Local
            rel_t = resolve_source_target("data/input.csv", base_dir=tmp_path)
            self.assertFalse(rel_t.is_remote)
            self.assertEqual(rel_t.scheme, "file")
            self.assertEqual(rel_t.canonical_path, csv_file.resolve())

            # 2. Absolute POSIX path -> Local
            abs_t = resolve_source_target(str(csv_file), base_dir=tmp_path)
            self.assertFalse(abs_t.is_remote)
            self.assertEqual(abs_t.scheme, "file")
            self.assertEqual(abs_t.canonical_path, csv_file.resolve())

            # 3. Absolute Windows path & UNC path -> Local
            win_t = resolve_source_target(r"C:\data\project\input.csv", base_dir=tmp_path)
            self.assertFalse(win_t.is_remote)
            self.assertEqual(win_t.scheme, "file")
            self.assertEqual(str(win_t.local_path), r"C:\data\project\input.csv")

            unc_t = resolve_source_target(r"\\fileserver\share\input.csv", base_dir=tmp_path)
            self.assertFalse(unc_t.is_remote)
            self.assertEqual(unc_t.scheme, "file")

            # 4. file:// URI -> Local
            uri_t = resolve_source_target(csv_file.as_uri(), base_dir=tmp_path)
            self.assertFalse(uri_t.is_remote)
            self.assertEqual(uri_t.scheme, "file")
            self.assertEqual(uri_t.canonical_path, csv_file.resolve())

            localhost_uri = f"file://localhost{csv_file.as_posix()}"
            lh_t = resolve_source_target(localhost_uri, base_dir=tmp_path)
            self.assertFalse(lh_t.is_remote)
            self.assertEqual(lh_t.canonical_path, csv_file.resolve())

            # 5. URI-encoded file URI -> Local
            enc_uri = spaced_file.as_uri()
            self.assertIn("%20", enc_uri)
            self.assertIn("%23", enc_uri)
            enc_t = resolve_source_target(enc_uri, base_dir=tmp_path)
            self.assertFalse(enc_t.is_remote)
            self.assertEqual(enc_t.canonical_path, spaced_file.resolve())

            # Encoded path separators (%2F, %5C) and null bytes (%00) must be rejected
            for bad_uri in (
                f"file://{tmp_path.as_posix()}/data%2Finput.csv",
                f"file://{tmp_path.as_posix()}/data%5Cinput.csv",
                f"file://{tmp_path.as_posix()}/data%00input.csv",
                "file://remotehost/data/input.csv",
                "file:data/input.csv",
                f"{csv_file.as_uri()}?query=1",
                f"{csv_file.as_uri()}#frag",
            ):
                with self.assertRaises(ValueError, msg=f"Expected rejection for {bad_uri}"):
                    resolve_source_target(bad_uri, base_dir=tmp_path)

            # 6-8. Environment-expanded relative path, absolute path, and file:// URI -> Local
            old_rel = os.environ.get("UC_TEST_REL_SOURCE")
            old_abs = os.environ.get("UC_TEST_ABS_SOURCE")
            old_uri = os.environ.get("UC_TEST_URI_SOURCE")
            old_https = os.environ.get("UC_TEST_HTTPS_SOURCE")
            try:
                os.environ["UC_TEST_REL_SOURCE"] = "data/input.csv"
                os.environ["UC_TEST_ABS_SOURCE"] = str(csv_file)
                os.environ["UC_TEST_URI_SOURCE"] = enc_uri
                os.environ["UC_TEST_HTTPS_SOURCE"] = "https://api.example.com/v1/data.json"

                env_rel_t = resolve_source_target("${UC_TEST_REL_SOURCE}", base_dir=tmp_path)
                self.assertFalse(env_rel_t.is_remote)
                self.assertEqual(env_rel_t.canonical_path, csv_file.resolve())

                env_abs_t = resolve_source_target("${UC_TEST_ABS_SOURCE}", base_dir=tmp_path)
                self.assertFalse(env_abs_t.is_remote)
                self.assertEqual(env_abs_t.canonical_path, csv_file.resolve())

                env_uri_t = resolve_source_target("${UC_TEST_URI_SOURCE}", base_dir=tmp_path)
                self.assertFalse(env_uri_t.is_remote)
                self.assertEqual(env_uri_t.canonical_path, spaced_file.resolve())

                # 9-10. HTTPS and HTTP URLs (direct and environment-expanded) -> Remote
                https_t = resolve_source_target("https://api.example.com/data.json", base_dir=tmp_path)
                self.assertTrue(https_t.is_remote)
                self.assertEqual(https_t.scheme, "https")
                self.assertIsNone(https_t.local_path)

                http_t = resolve_source_target("http://api.example.com/data.csv", base_dir=tmp_path)
                self.assertTrue(http_t.is_remote)
                self.assertEqual(http_t.scheme, "http")
                self.assertIsNone(http_t.local_path)

                env_https_t = resolve_source_target("${UC_TEST_HTTPS_SOURCE}", base_dir=tmp_path)
                self.assertTrue(env_https_t.is_remote)
                self.assertEqual(env_https_t.scheme, "https")
                self.assertIsNone(env_https_t.local_path)
            finally:
                for k, v in (
                    ("UC_TEST_REL_SOURCE", old_rel),
                    ("UC_TEST_ABS_SOURCE", old_abs),
                    ("UC_TEST_URI_SOURCE", old_uri),
                    ("UC_TEST_HTTPS_SOURCE", old_https),
                ):
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

            # 11. Unsupported schemes -> Explicit rejection
            for unsupported in (
                "ftp://ftp.example.com/data.csv",
                "s3://my-bucket/data.csv",
                "gs://my-bucket/data.json",
                "postgres://localhost:5432/db",
                "ws://example.com/stream",
                "C:relative_drive_path.csv",
            ):
                with self.assertRaises(ValueError, msg=f"Expected rejection for {unsupported}"):
                    resolve_source_target(unsupported, base_dir=tmp_path)
                with self.assertRaises(ValueError, msg=f"Expected SourceConfig rejection for {unsupported}"):
                    SourceConfig(name="bad-scheme", url=unsupported, format="csv")

    def test_summary_output_protection_across_file_uri_and_env_expanded_sources(self) -> None:
        """Verify Scenarios A, B, D, E & Section 9 Summary-Output Protection matrix."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            csv_bytes = b"station_id,pm25\nST01,12.5\nST02,15.0\n"

            rel_src = tmp_path / "rel_feed.txt"
            abs_src = tmp_path / "abs_feed.txt"
            uri_src = tmp_path / "uri_feed.csv"
            enc_src = tmp_path / "uri spaced feed.txt"
            env_src = tmp_path / "env_feed.txt"
            env_uri_src = tmp_path / "env_uri_feed.csv"

            for f in (rel_src, abs_src, uri_src, enc_src, env_src, env_uri_src):
                f.write_bytes(csv_bytes)

            env_map = {
                **os.environ,
                "UPSTREAM_DATA_FILE": str(env_src),
                "UPSTREAM_FILE_URI": env_uri_src.as_uri(),
            }

            cases = [
                ("rel-src", "rel_feed.txt", rel_src),
                ("abs-src", str(abs_src), abs_src),
                ("uri-src", uri_src.as_uri(), uri_src),
                ("enc-src", enc_src.as_uri(), enc_src),
                ("env-src", "${UPSTREAM_DATA_FILE}", env_src),
                ("env-uri-src", "${UPSTREAM_FILE_URI}", env_uri_src),
            ]

            for name, raw_url, target_file in cases:
                cfg_file = tmp_path / f"cfg_{name}.yaml"
                res_init = runner.invoke(
                    app,
                    [
                        "init",
                        raw_url,
                        "--name",
                        name,
                        "--format",
                        "csv",
                        "--config",
                        str(cfg_file),
                    ],
                    env=env_map,
                )
                self.assertEqual(res_init.exit_code, 0, msg=res_init.output)

                # 1. Normal check with --summary-file targeting the resolved local source
                res_sum = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(cfg_file),
                        "--summary-file",
                        str(target_file),
                    ],
                    env=env_map,
                )
                self.assertEqual(res_sum.exit_code, 2, msg=f"Failed for {name}: {res_sum.output}")
                self.assertIn("aliases protected file", res_sum.output)
                self.assertEqual(target_file.read_bytes(), csv_bytes)

                # 2. Normal check with $GITHUB_STEP_SUMMARY targeting the resolved local source (Scenario D)
                res_gh = runner.invoke(
                    app,
                    ["check", "--config", str(cfg_file)],
                    env={**env_map, "GITHUB_STEP_SUMMARY": str(target_file)},
                )
                self.assertEqual(res_gh.exit_code, 2, msg=f"Failed GH summary for {name}: {res_gh.output}")
                self.assertIn("aliases protected file", res_gh.output)
                self.assertEqual(target_file.read_bytes(), csv_bytes)

                # 3. Invalid CLI option fallback (--bogus) targeting the resolved local source
                res_bogus = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(cfg_file),
                        "--bogus",
                        "--summary-file",
                        str(target_file),
                    ],
                    env=env_map,
                )
                self.assertEqual(res_bogus.exit_code, 2)
                self.assertIn("aliases protected file", res_bogus.output)
                self.assertEqual(target_file.read_bytes(), csv_bytes)

            # Scenario E: Malformed configuration fallback with file:// and ${UPSTREAM_DATA_FILE} sources
            malformed_cfg = tmp_path / "malformed_sources.yaml"
            malformed_cfg.write_text(
                f"version: 1\nsources:\n"
                f"  - name: uri-src\n    url: {uri_src.as_uri()}\n    format: csv\n"
                f"  - name: env-src\n    url: ${{UPSTREAM_DATA_FILE}}\n    format: csv\n"
                f"    unknown_broken_field: [unclosed\n",
                encoding="utf-8",
            )
            for target_file in (uri_src, env_src):
                res_mal = runner.invoke(
                    app,
                    [
                        "check",
                        "--config",
                        str(malformed_cfg),
                        "--summary-file",
                        str(target_file),
                    ],
                    env=env_map,
                )
                self.assertEqual(res_mal.exit_code, 2)
                self.assertIn("aliases protected file", res_mal.output)
                self.assertEqual(target_file.read_bytes(), csv_bytes)

            # Verify a safe fallback report is written when target is safe
            safe_diag = tmp_path / "safe_diagnostic_report.md"
            res_safe_mal = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(malformed_cfg),
                    "--summary-file",
                    str(safe_diag),
                ],
                env=env_map,
            )
            self.assertEqual(res_safe_mal.exit_code, 2)
            self.assertTrue(safe_diag.exists())
            self.assertIn("## Upstream Check Report — EXECUTION ERROR", safe_diag.read_text(encoding="utf-8"))

            leftover_tmps = list(tmp_path.rglob(".upstream-check-*.tmp"))
            self.assertEqual(leftover_tmps, [])

    def test_baseline_update_collision_protection_across_all_source_and_baseline_aliases(self) -> None:
        """Verify Defect 1B, Defect 2, Scenario C & all 7 Section 9 Baseline-Update Protection cases."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            json_bytes = b'[{"id": 1, "val": 10}, {"id": 2, "val": 20}]\n'
            other_bytes = b'[{"id": 1, "val": 99}, {"id": 2, "val": 88}]\n'

            ord_json = tmp_path / "ordinary.json"
            uri_json = tmp_path / "uri_data.json"
            env_json = tmp_path / "env_data.json"
            env_uri_json = tmp_path / "env_uri_data.json"
            other_json = tmp_path / "other_source.json"

            for f in (ord_json, uri_json, env_json, env_uri_json):
                f.write_bytes(json_bytes)
            other_json.write_bytes(other_bytes)

            env_map = {
                **os.environ,
                "UPSTREAM_JSON_FILE": str(env_json),
                "UPSTREAM_JSON_URI": env_uri_json.as_uri(),
            }

            # Cases 1-3: Baseline equals ordinary local source, file:// source, or env-expanded source
            direct_collision_cases = [
                ("ord-src", "ordinary.json", "ordinary.json", ord_json),
                ("file-uri-source", uri_json.as_uri(), "uri_data.json", uri_json),
                ("env-source", "${UPSTREAM_JSON_FILE}", "env_data.json", env_json),
                ("env-uri-source", "${UPSTREAM_JSON_URI}", "env_uri_data.json", env_uri_json),
            ]

            for src_name, url_str, base_rel, src_file in direct_collision_cases:
                cfg_p = tmp_path / f"cfg_{src_name}.yaml"
                cfg_p.write_text(
                    f"version: 1\nsources:\n  - name: {src_name}\n    url: {url_str}\n"
                    f"    format: json\n    schema:\n      baseline: {base_rel}\n",
                    encoding="utf-8",
                )
                for cmd_args in (
                    ["check", "--config", str(cfg_p), "--update-baseline"],
                    ["baseline", "update", "--config", str(cfg_p)],
                ):
                    res = runner.invoke(app, cmd_args, env=env_map)
                    self.assertEqual(res.exit_code, 2, msg=f"Failed for {src_name} {cmd_args}: {res.output}")
                    self.assertIn(src_name, res.output)
                    self.assertIn("collides with its own local source file", res.output)
                    self.assertEqual(src_file.read_bytes(), json_bytes)

            # Case 4: Baseline is a hard link to source
            baselines_dir = tmp_path / "baselines"
            baselines_dir.mkdir(parents=True, exist_ok=True)
            hl_base = baselines_dir / "hl_to_source.json"
            try:
                os.link(uri_json, hl_base)
                cfg_hl = tmp_path / "cfg_hl_base.yaml"
                cfg_hl.write_text(
                    f"version: 1\nsources:\n  - name: hl-base-src\n    url: {uri_json.as_uri()}\n"
                    f"    format: json\n    schema:\n      baseline: baselines/hl_to_source.json\n",
                    encoding="utf-8",
                )
                res_hl = runner.invoke(
                    app, ["check", "--config", str(cfg_hl), "--update-baseline"], env=env_map
                )
                self.assertEqual(res_hl.exit_code, 2, msg=res_hl.output)
                self.assertIn("hl-base-src", res_hl.output)
                self.assertIn("collides with its own local source file", res_hl.output)
                self.assertEqual(uri_json.read_bytes(), json_bytes)
            except (OSError, NotImplementedError):
                pass

            # Case 5: Baseline is a symbolic link to source
            sym_base = baselines_dir / "sym_to_source.json"
            try:
                os.symlink(uri_json, sym_base)
                cfg_sym = tmp_path / "cfg_sym_base.yaml"
                cfg_sym.write_text(
                    f"version: 1\nsources:\n  - name: sym-base-src\n    url: {uri_json.as_uri()}\n"
                    f"    format: json\n    schema:\n      baseline: baselines/sym_to_source.json\n",
                    encoding="utf-8",
                )
                res_sym = runner.invoke(
                    app, ["check", "--config", str(cfg_sym), "--update-baseline"], env=env_map
                )
                self.assertEqual(res_sym.exit_code, 2, msg=res_sym.output)
                self.assertIn("sym-base-src", res_sym.output)
                self.assertEqual(uri_json.read_bytes(), json_bytes)
            except (OSError, NotImplementedError):
                pass

            # Case 6: Baseline of src-two aliases src-one data file (no partial baseline write)
            src1_base = baselines_dir / "src-one.json"
            if src1_base.exists():
                src1_base.unlink()
            cfg_cross = tmp_path / "cfg_cross_source.yaml"
            cfg_cross.write_text(
                f"version: 1\nsources:\n"
                f"  - name: src-one\n    url: {other_json.as_uri()}\n    format: json\n"
                f"    schema:\n      baseline: baselines/src-one.json\n"
                f"  - name: src-two\n    url: {uri_json.as_uri()}\n    format: json\n"
                f"    schema:\n      baseline: other_source.json\n",
                encoding="utf-8",
            )
            res_cross = runner.invoke(
                app, ["check", "--config", str(cfg_cross), "--update-baseline"], env=env_map
            )
            self.assertEqual(res_cross.exit_code, 2, msg=res_cross.output)
            self.assertIn("src-two", res_cross.output)
            self.assertIn("src-one", res_cross.output)
            self.assertIn("collides with local source file", res_cross.output)
            self.assertEqual(other_json.read_bytes(), other_bytes)
            self.assertFalse(
                src1_base.exists(),
                "First source baseline must not be written when batch validation fails",
            )

            # Case 7: Two baseline destinations alias one another
            shared_base = baselines_dir / "shared.json"
            if shared_base.exists():
                shared_base.unlink()
            cfg_dup_base = tmp_path / "cfg_dup_baselines.yaml"
            cfg_dup_base.write_text(
                f"version: 1\nsources:\n"
                f"  - name: alpha-src\n    url: {ord_json.as_uri()}\n    format: json\n"
                f"    schema:\n      baseline: baselines/shared.json\n"
                f"  - name: beta-src\n    url: {uri_json.as_uri()}\n    format: json\n"
                f"    schema:\n      baseline: baselines/./shared.json\n",
                encoding="utf-8",
            )
            res_dup_base = runner.invoke(
                app, ["baseline", "update", "--config", str(cfg_dup_base)], env=env_map
            )
            self.assertEqual(res_dup_base.exit_code, 2, msg=res_dup_base.output)
            self.assertIn("beta-src", res_dup_base.output)
            self.assertIn("alpha-src", res_dup_base.output)
            self.assertIn("collides with baseline destination", res_dup_base.output)
            self.assertFalse(shared_base.exists())

            leftover_tmps = list(tmp_path.rglob(".upstream-check-*.tmp"))
            self.assertEqual(leftover_tmps, [])


    def test_v0_2_11_flow_yaml_and_fail_closed_unverified_summary_protection(self) -> None:
        """Verify all 8 mandatory v0.2.11 scenarios: flow-style YAML, unresolved env vars, and fail-closed summaries."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()

            # Create source files (including one starting with Markdown report header to prove header is never trusted)
            src_csv = tmp_path / "source_data.csv"
            src_csv_bytes = b"station_id,pm25\nST01,11.0\nST02,14.5\n"
            src_csv.write_bytes(src_csv_bytes)

            src_with_header = tmp_path / "header_spoofed_source.txt"
            src_header_bytes = b"## Upstream Check Report\nstation_id,pm25\nST01,11.0\n"
            src_with_header.write_bytes(src_header_bytes)

            # Initialize a valid config & baseline first so we have an existing baseline file
            valid_cfg = tmp_path / "valid.yaml"
            res_init = runner.invoke(
                app,
                [
                    "init",
                    str(src_csv),
                    "--name",
                    "feed",
                    "--format",
                    "csv",
                    "--config",
                    str(valid_cfg),
                ],
            )
            self.assertEqual(res_init.exit_code, 0, msg=res_init.output)
            baseline_file = tmp_path / "baselines" / "feed.json"
            baseline_bytes = baseline_file.read_bytes()

            # Legitimate existing GitHub summary file
            legit_gh_summary = tmp_path / "legit_existing_step_summary.md"
            legit_gh_bytes = b"## Upstream Check Report \xe2\x80\x94 PASSED\nPrior step summary.\n"
            legit_gh_summary.write_bytes(legit_gh_bytes)

            # 1. Malformed block-style YAML
            malformed_block = tmp_path / "malformed_block.yaml"
            malformed_block.write_text(
                "version: 1\nsources:\n  - name: feed\n    url: ${SRC}\n    format: csv\n  broken_block: [\n",
                encoding="utf-8",
            )
            for target_file, expected_bytes in (
                (src_csv, src_csv_bytes),
                (src_with_header, src_header_bytes),
                (baseline_file, baseline_bytes),
                (legit_gh_summary, legit_gh_bytes),
            ):
                res_b1 = runner.invoke(
                    app,
                    ["check", "--config", str(malformed_block), "--summary-file", str(target_file)],
                    env={**os.environ, "SRC": str(target_file)},
                )
                self.assertEqual(res_b1.exit_code, 2)
                self.assertEqual(target_file.read_bytes(), expected_bytes)

                res_b2 = runner.invoke(
                    app,
                    ["check", "--config", str(malformed_block)],
                    env={**os.environ, "SRC": str(target_file), "GITHUB_STEP_SUMMARY": str(target_file)},
                )
                self.assertEqual(res_b2.exit_code, 2)
                self.assertEqual(target_file.read_bytes(), expected_bytes)

            # 2. Malformed flow-style YAML containing an environment-backed local source
            malformed_flow = tmp_path / "malformed_flow.yaml"
            malformed_flow.write_text(
                'version: 1\nsources: [{name: feed, url: "${SRC}", format: csv}]\nbroken: [\n',
                encoding="utf-8",
            )
            for target_file, expected_bytes in (
                (src_csv, src_csv_bytes),
                (src_with_header, src_header_bytes),
                (baseline_file, baseline_bytes),
                (legit_gh_summary, legit_gh_bytes),
            ):
                res_f1 = runner.invoke(
                    app,
                    ["check", "--config", str(malformed_flow), "--summary-file", str(target_file)],
                    env={**os.environ, "SRC": str(target_file)},
                )
                self.assertEqual(res_f1.exit_code, 2)
                self.assertEqual(target_file.read_bytes(), expected_bytes)

                res_f2 = runner.invoke(
                    app,
                    ["check", "--config", str(malformed_flow)],
                    env={**os.environ, "SRC": str(target_file), "GITHUB_STEP_SUMMARY": str(target_file)},
                )
                self.assertEqual(res_f2.exit_code, 2)
                self.assertEqual(target_file.read_bytes(), expected_bytes)

            # 3. Unresolved environment variables
            unresolved_cfg = tmp_path / "unresolved_env.yaml"
            unresolved_cfg.write_text(
                'version: 1\nsources: [{name: feed, url: "${UNSET_UPSTREAM_SOURCE_PATH}", format: csv}]\n',
                encoding="utf-8",
            )
            clean_env = {k: v for k, v in os.environ.items() if k != "UNSET_UPSTREAM_SOURCE_PATH"}
            for target_file, expected_bytes in (
                (src_csv, src_csv_bytes),
                (src_with_header, src_header_bytes),
                (baseline_file, baseline_bytes),
                (legit_gh_summary, legit_gh_bytes),
            ):
                res_u1 = runner.invoke(
                    app,
                    ["check", "--config", str(unresolved_cfg), "--summary-file", str(target_file)],
                    env=clean_env,
                )
                self.assertEqual(res_u1.exit_code, 2)
                self.assertEqual(target_file.read_bytes(), expected_bytes)

                res_u2 = runner.invoke(
                    app,
                    ["check", "--config", str(unresolved_cfg)],
                    env={**clean_env, "GITHUB_STEP_SUMMARY": str(target_file)},
                )
                self.assertEqual(res_u2.exit_code, 2)
                self.assertEqual(target_file.read_bytes(), expected_bytes)

            # 4. Invalid CLI arguments (--bogus) with an existing source, baseline, or existing GH summary
            for target_file, expected_bytes in (
                (src_csv, src_csv_bytes),
                (src_with_header, src_header_bytes),
                (baseline_file, baseline_bytes),
                (legit_gh_summary, legit_gh_bytes),
            ):
                res_cli1 = runner.invoke(
                    app,
                    ["check", "--config", str(valid_cfg), "--bogus", "--summary-file", str(target_file)],
                )
                self.assertEqual(res_cli1.exit_code, 2)
                self.assertEqual(target_file.read_bytes(), expected_bytes)

                res_cli2 = runner.invoke(
                    app,
                    ["check", "--config", str(valid_cfg), "--bogus"],
                    env={**os.environ, "GITHUB_STEP_SUMMARY": str(target_file)},
                )
                self.assertEqual(res_cli2.exit_code, 2)
                self.assertEqual(target_file.read_bytes(), expected_bytes)

            # 5 & 6. Existing source or existing baseline used as $GITHUB_STEP_SUMMARY or --summary-file on valid config
            flow_valid_cfg = tmp_path / "flow_valid.yaml"
            flow_valid_cfg.write_text(
                (
                    'version: 1\nsources: [{name: feed, url: "${SRC}", '
                    'format: csv, schema: {baseline: baselines/feed.json}}]\n'
                ),
                encoding="utf-8",
            )
            for src_candidate, expected_bytes in (
                (src_csv, src_csv_bytes),
                (src_with_header, src_header_bytes),
            ):
                res_v_gh = runner.invoke(
                    app,
                    ["check", "--config", str(flow_valid_cfg)],
                    env={
                        **os.environ,
                        "SRC": str(src_candidate),
                        "GITHUB_STEP_SUMMARY": str(src_candidate),
                    },
                )
                self.assertEqual(res_v_gh.exit_code, 2)
                self.assertIn("aliases protected file", res_v_gh.output)
                self.assertEqual(src_candidate.read_bytes(), expected_bytes)

                res_v_sum = runner.invoke(
                    app,
                    ["check", "--config", str(flow_valid_cfg), "--summary-file", str(src_candidate)],
                    env={**os.environ, "SRC": str(src_candidate)},
                )
                self.assertEqual(res_v_sum.exit_code, 2)
                self.assertIn("aliases protected file", res_v_sum.output)
                self.assertEqual(src_candidate.read_bytes(), expected_bytes)

            for base_cmd in (
                ["check", "--config", str(valid_cfg), "--summary-file", str(baseline_file)],
                ["check", "--config", str(valid_cfg)],
            ):
                env_b = (
                    {**os.environ, "GITHUB_STEP_SUMMARY": str(baseline_file)}
                    if len(base_cmd) == 3
                    else os.environ
                )
                res_base = runner.invoke(app, base_cmd, env=env_b)
                self.assertEqual(res_base.exit_code, 2)
                self.assertIn("aliases protected file", res_base.output)
                self.assertEqual(baseline_file.read_bytes(), baseline_bytes)

            # 7. Confirm legitimate existing GitHub summary remained byte-for-byte unchanged across all unverified runs
            self.assertEqual(legit_gh_summary.read_bytes(), legit_gh_bytes)

            # 8. Safe new summary destination still works on both malformed config and valid config
            safe_new_diag = tmp_path / "safe_new_diag.md"
            safe_new_gh = tmp_path / "safe_new_gh.md"
            res_safe_unverified = runner.invoke(
                app,
                ["check", "--config", str(malformed_flow), "--summary-file", str(safe_new_diag)],
                env={**os.environ, "SRC": str(src_csv), "GITHUB_STEP_SUMMARY": str(safe_new_gh)},
            )
            self.assertEqual(res_safe_unverified.exit_code, 2)
            self.assertTrue(safe_new_diag.exists())
            self.assertTrue(safe_new_gh.exists())
            self.assertIn(
                "## Upstream Check Report — EXECUTION ERROR",
                safe_new_diag.read_text(encoding="utf-8"),
            )
            self.assertIn(
                "## Upstream Check Report — EXECUTION ERROR",
                safe_new_gh.read_text(encoding="utf-8"),
            )

            safe_valid_summary = tmp_path / "safe_valid_summary.md"
            safe_valid_gh = tmp_path / "safe_valid_gh.md"
            res_safe_valid = runner.invoke(
                app,
                [
                    "check",
                    "--config",
                    str(flow_valid_cfg),
                    "--summary-file",
                    str(safe_valid_summary),
                ],
                env={
                    **os.environ,
                    "SRC": str(src_csv),
                    "GITHUB_STEP_SUMMARY": str(safe_valid_gh),
                },
            )
            self.assertEqual(res_safe_valid.exit_code, 0, msg=res_safe_valid.output)
            self.assertTrue(safe_valid_summary.exists())
            self.assertTrue(safe_valid_gh.exists())
            self.assertIn(
                "## Upstream Check Report — PASSED",
                safe_valid_summary.read_text(encoding="utf-8"),
            )
            self.assertIn("## Upstream Check Report — PASSED", safe_valid_gh.read_text(encoding="utf-8"))


    def test_v0_2_12_toctou_descriptor_verified_summary_appending(self) -> None:
        """Verify all 7 mandatory v0.2.12 TOCTOU and descriptor-verification scenarios."""
        runner = CliRunner()
        cli_app_mod = sys.modules["upstream_check.cli.app"]
        types_mod = sys.modules["upstream_check.core.types"]

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            src_csv = tmp_path / "source.csv"
            src_bytes = b"station_id,pm25\nST01,10.5\nST02,14.0\n"
            src_csv.write_bytes(src_bytes)

            cfg_file = tmp_path / "upstream-check.yaml"
            res_init = runner.invoke(
                app,
                [
                    "init",
                    str(src_csv),
                    "--name",
                    "toctou-src",
                    "--format",
                    "csv",
                    "--config",
                    str(cfg_file),
                ],
            )
            self.assertEqual(res_init.exit_code, 0, msg=res_init.output)
            cfg_bytes = cfg_file.read_bytes()
            baseline_file = tmp_path / "baselines" / "toctou-src.json"
            baseline_bytes = baseline_file.read_bytes()

            # 1. Destination replaced with a symlink to config, source, or baseline after initial verification
            orig_validate = cli_app_mod._validate_safe_summary_target
            for protected_target, expected_bytes in (
                (src_csv, src_bytes),
                (cfg_file, cfg_bytes),
                (baseline_file, baseline_bytes),
            ):
                gh_sym_race = tmp_path / "gh_symlink_race.md"
                if gh_sym_race.exists() or os.path.lexists(gh_sym_race):
                    gh_sym_race.unlink()
                gh_sym_race.write_text("Prior safe content\n", encoding="utf-8")

                call_count = {"n": 0}

                def swap_with_symlink_on_write_validate(*args, **kwargs):
                    res_path = orig_validate(*args, **kwargs)
                    call_count["n"] += 1
                    # Second call is inside _write_summary_targets() right before safe_append_text_verified()
                    if call_count["n"] == 2 and res_path is not None:
                        if os.path.lexists(res_path):
                            res_path.unlink()
                        os.symlink(protected_target, res_path)
                    return res_path

                with mock.patch.object(
                    cli_app_mod,
                    "_validate_safe_summary_target",
                    side_effect=swap_with_symlink_on_write_validate,
                ):
                    res_race = runner.invoke(
                        app,
                        ["check", "--config", str(cfg_file)],
                        env={**os.environ, "GITHUB_STEP_SUMMARY": str(gh_sym_race)},
                    )
                self.assertEqual(res_race.exit_code, 2, msg=res_race.output)
                self.assertIn("symbolic link", res_race.output)
                self.assertEqual(protected_target.read_bytes(), expected_bytes)

            # 2. Destination replaced with a hard link to protected source (and hard-link + unlink race)
            for protected_target, expected_bytes in (
                (src_csv, src_bytes),
                (cfg_file, cfg_bytes),
                (baseline_file, baseline_bytes),
            ):
                gh_hl_race = tmp_path / "gh_hardlink_race.md"
                if os.path.lexists(gh_hl_race):
                    gh_hl_race.unlink()
                gh_hl_race.write_text("Prior safe content\n", encoding="utf-8")

                hl_calls = {"n": 0}

                def swap_with_hardlink_on_write_validate(*args, **kwargs):
                    res_path = orig_validate(*args, **kwargs)
                    hl_calls["n"] += 1
                    if hl_calls["n"] == 2 and res_path is not None:
                        if os.path.lexists(res_path):
                            res_path.unlink()
                        os.link(protected_target, res_path)
                    return res_path

                with mock.patch.object(
                    cli_app_mod,
                    "_validate_safe_summary_target",
                    side_effect=swap_with_hardlink_on_write_validate,
                ):
                    res_hl_race = runner.invoke(
                        app,
                        ["check", "--config", str(cfg_file)],
                        env={**os.environ, "GITHUB_STEP_SUMMARY": str(gh_hl_race)},
                    )
                self.assertEqual(res_hl_race.exit_code, 2, msg=res_hl_race.output)
                self.assertEqual(protected_target.read_bytes(), expected_bytes)

            # 3. Destination replaced between validation and os.open(), AND between os.open() and fstat()
            gh_open_race = tmp_path / "gh_open_race.md"
            if os.path.lexists(gh_open_race):
                gh_open_race.unlink()
            gh_open_race.write_text("Initial line\n", encoding="utf-8")

            orig_os_open = os.open

            def replace_right_after_os_open(path_str, flags, *args):
                fd = orig_os_open(path_str, flags, *args)
                if Path(path_str) == gh_open_race:
                    # Concurrent process replaces gh_open_race with a hard link to src_csv after os.open() returns fd
                    gh_open_race.unlink()
                    os.link(src_csv, gh_open_race)
                return fd

            with mock.patch("os.open", side_effect=replace_right_after_os_open):
                with self.assertRaises(ValueError) as ctx_race:
                    safe_append_text_verified(
                        target_path=gh_open_race,
                        content="Appended report\n",
                        protected_paths=[src_csv, cfg_file, baseline_file],
                        allow_existing=True,
                    )
            self.assertTrue(
                "opened file descriptor was unlinked" in str(ctx_race.exception)
                or "inode changed during open" in str(ctx_race.exception)
            )
            self.assertEqual(src_csv.read_bytes(), src_bytes)
            if os.path.lexists(gh_open_race):
                gh_open_race.unlink()

            # 4. Ordinary existing safe GitHub summary (legitimate append preserved when verified safe)
            safe_existing_gh = tmp_path / "legit_step_summary.md"
            initial_gh_text = "### Previous Workflow Step\nAll prerequisite checks green.\n"
            safe_existing_gh.write_text(initial_gh_text, encoding="utf-8")
            res_legit = runner.invoke(
                app,
                ["check", "--config", str(cfg_file)],
                env={**os.environ, "GITHUB_STEP_SUMMARY": str(safe_existing_gh)},
            )
            self.assertEqual(res_legit.exit_code, 0, msg=res_legit.output)
            combined_gh = safe_existing_gh.read_text(encoding="utf-8")
            self.assertTrue(combined_gh.startswith(initial_gh_text))
            self.assertIn("## Upstream Check Report — PASSED", combined_gh)

            # 5. New summary destination (both --summary-file and $GITHUB_STEP_SUMMARY)
            new_sum = tmp_path / "brand_new_summary.md"
            new_gh = tmp_path / "brand_new_gh.md"
            res_new = runner.invoke(
                app,
                ["check", "--config", str(cfg_file), "--summary-file", str(new_sum)],
                env={**os.environ, "GITHUB_STEP_SUMMARY": str(new_gh)},
            )
            self.assertEqual(res_new.exit_code, 0, msg=res_new.output)
            self.assertIn("## Upstream Check Report — PASSED", new_sum.read_text(encoding="utf-8"))
            self.assertIn("## Upstream Check Report — PASSED", new_gh.read_text(encoding="utf-8"))

            # 6. Direct configuration, source, and baseline collision attempts on safe_append_text_verified
            for prot_file, expected_bytes in (
                (cfg_file, cfg_bytes),
                (src_csv, src_bytes),
                (baseline_file, baseline_bytes),
            ):
                with self.assertRaises(ValueError):
                    safe_append_text_verified(
                        target_path=prot_file,
                        content="Should never write\n",
                        protected_paths=[cfg_file, src_csv, baseline_file],
                        allow_existing=True,
                    )
                self.assertEqual(prot_file.read_bytes(), expected_bytes)

            # 7. Platform-specific fail-closed behavior (zero st_ino/st_dev or Windows reparse attribute)
            dummy_target = tmp_path / "platform_test.md"
            dummy_target.write_text("safe\n", encoding="utf-8")
            real_fstat = os.fstat

            class ZeroInodeStat:
                def __init__(self, st: os.stat_result) -> None:
                    self.st_mode = st.st_mode
                    self.st_ino = 0
                    self.st_dev = 0
                    self.st_nlink = 1

            with mock.patch("os.fstat", side_effect=lambda fd: ZeroInodeStat(real_fstat(fd))):
                with self.assertRaises(ValueError) as ctx_zero:
                    safe_append_text_verified(
                        target_path=dummy_target,
                        content="Blocked on zero inode\n",
                        protected_paths=[src_csv],
                        allow_existing=True,
                    )
            self.assertIn("verifiable device/inode identity", str(ctx_zero.exception))
            self.assertEqual(dummy_target.read_text(encoding="utf-8"), "safe\n")

            class ReparsePointStat:
                def __init__(self, st: os.stat_result) -> None:
                    self.st_mode = st.st_mode
                    self.st_ino = st.st_ino
                    self.st_dev = st.st_dev
                    self.st_nlink = 1
                    self.st_file_attributes = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT

            orig_lstat = os.lstat
            with mock.patch(
                "os.lstat",
                side_effect=lambda p: (
                    ReparsePointStat(orig_lstat(p))
                    if Path(p) == dummy_target
                    else orig_lstat(p)
                ),
            ):
                with self.assertRaises(ValueError) as ctx_reparse:
                    safe_append_text_verified(
                        target_path=dummy_target,
                        content="Blocked on reparse point\n",
                        protected_paths=[src_csv],
                        allow_existing=True,
                    )
            self.assertIn("symbolic link", str(ctx_reparse.exception))
            self.assertEqual(dummy_target.read_text(encoding="utf-8"), "safe\n")


    def test_v0_2_13_fifo_and_special_file_nonblocking_rejection(self) -> None:
        """Verify FIFOs (with or without reader) and special files never block and are rejected cleanly."""
        if not hasattr(os, "mkfifo"):
            self.skipTest("Platform does not support os.mkfifo")

        runner = CliRunner()
        cli_app_mod = sys.modules["upstream_check.cli.app"]

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            csv_file = tmp_path / "healthy.csv"
            csv_bytes = b"station_id,pm25\nST01,10.0\nST02,12.0\n"
            csv_file.write_bytes(csv_bytes)

            cfg_file = tmp_path / "upstream-check.yaml"
            res_init = runner.invoke(
                app,
                [
                    "init",
                    str(csv_file),
                    "--name",
                    "fifo-guard",
                    "--format",
                    "csv",
                    "--config",
                    str(cfg_file),
                ],
            )
            self.assertEqual(res_init.exit_code, 0, msg=res_init.output)

            fifo_path = tmp_path / "summary.fifo"
            os.mkfifo(fifo_path)

            # 1. Subprocess timeout test (< 1.5s) on safe_append_text_verified with no FIFO reader
            sub_code = (
                "import sys; from pathlib import Path; "
                "from upstream_check.core.types import safe_append_text_verified\n"
                "try:\n"
                f"    safe_append_text_verified(Path({str(fifo_path)!r}), 'report\\n', allow_existing=True)\n"
                "    sys.exit(0)\n"
                "except ValueError as e:\n"
                "    print(str(e)); sys.exit(42)\n"
            )
            sub_res = subprocess.run(
                [sys.executable, "-c", sub_code],
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
                timeout=1.5,
                capture_output=True,
                text=True,
            )
            self.assertEqual(sub_res.returncode, 42, msg=sub_res.stderr)
            self.assertIn("not a regular file", sub_res.stdout)

            # 2. FIFO with an active reader attached is also rejected by S_ISREG before writing any byte
            r_fd = os.open(str(fifo_path), os.O_RDONLY | os.O_NONBLOCK)
            try:
                with self.assertRaises(ValueError) as ctx_reader:
                    safe_append_text_verified(
                        target_path=fifo_path,
                        content="should never be written\n",
                        allow_existing=True,
                    )
                self.assertIn("not a regular file", str(ctx_reader.exception))
                read_back = os.read(r_fd, 1024)
                self.assertEqual(read_back, b"")
            finally:
                os.close(r_fd)

            # 3. CLI check with --summary-file or $GITHUB_STEP_SUMMARY pointing to a FIFO (no reader)
            res_cli_sum = runner.invoke(
                app,
                ["check", "--config", str(cfg_file), "--summary-file", str(fifo_path)],
            )
            self.assertEqual(res_cli_sum.exit_code, 2, msg=res_cli_sum.output)
            self.assertIn("not a regular file", res_cli_sum.output)
            self.assertTrue(stat.S_ISFIFO(os.lstat(fifo_path).st_mode))

            res_cli_gh = runner.invoke(
                app,
                ["check", "--config", str(cfg_file)],
                env={**os.environ, "GITHUB_STEP_SUMMARY": str(fifo_path)},
            )
            self.assertEqual(res_cli_gh.exit_code, 2, msg=res_cli_gh.output)
            self.assertIn("not a regular file", res_cli_gh.output)

            # 4. TOCTOU swap to a FIFO after initial _validate_safe_summary_target()
            gh_swap_fifo = tmp_path / "swap_to_fifo.md"
            gh_swap_fifo.write_text("Initial regular file\n", encoding="utf-8")
            orig_validate = cli_app_mod._validate_safe_summary_target
            swap_calls = {"n": 0}

            def swap_regular_with_fifo(*args, **kwargs):
                res_p = orig_validate(*args, **kwargs)
                swap_calls["n"] += 1
                if swap_calls["n"] == 2 and res_p is not None:
                    if os.path.lexists(res_p):
                        res_p.unlink()
                    os.mkfifo(res_p)
                return res_p

            with mock.patch.object(
                cli_app_mod,
                "_validate_safe_summary_target",
                side_effect=swap_regular_with_fifo,
            ):
                res_toctou_fifo = runner.invoke(
                    app,
                    ["check", "--config", str(cfg_file)],
                    env={**os.environ, "GITHUB_STEP_SUMMARY": str(gh_swap_fifo)},
                )
            self.assertEqual(res_toctou_fifo.exit_code, 2, msg=res_toctou_fifo.output)
            self.assertIn("not a regular file", res_toctou_fifo.output)

            # 5. FIFO passed as --config, schema.baseline, or local source URL never blocks
            res_cfg_fifo = runner.invoke(
                app,
                ["check", "--config", str(fifo_path)],
            )
            self.assertEqual(res_cfg_fifo.exit_code, 2, msg=res_cfg_fifo.output)
            self.assertIn("not a regular file", res_cfg_fifo.output)

            fifo_src_cfg = tmp_path / "fifo_src.yaml"
            fifo_src_cfg.write_text(
                f"version: 1\nsources:\n  - name: fifo-s\n    url: {fifo_path}\n    format: csv\n",
                encoding="utf-8",
            )
            res_src_fifo = runner.invoke(
                app,
                ["check", "--config", str(fifo_src_cfg)],
            )
            self.assertEqual(res_src_fifo.exit_code, 1, msg=res_src_fifo.output)
            self.assertIn("not a regular file", res_src_fifo.output)

            # 6. Character device (/dev/null) rejected as non-regular file when present
            dev_null = Path("/dev/null")
            if dev_null.exists():
                with self.assertRaises(ValueError) as ctx_dev:
                    safe_append_text_verified(
                        target_path=dev_null,
                        content="blocked on /dev/null\n",
                        allow_existing=True,
                    )
                self.assertIn("not a regular file", str(ctx_dev.exception))


if __name__ == "__main__":
    unittest.main()
