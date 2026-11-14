"""CLI entry point for Upstream Check (`init`, `check`, `baseline update`, `mcp`)."""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple

import click
import yaml

from upstream_check import __version__
from upstream_check.config.models import (
    UpstreamCheckConfig,
    dump_config_yaml,
    load_config,
)
from upstream_check.core.types import (
    ANY_DOLLAR_BRACE_RE,
    ENV_INTERP_RE,
    atomic_write_text_safe,
    expand_env_vars,
    parse_timestamp,
    paths_refer_to_same_file,
    redact_text,
    resolve_source_target,
    safe_append_text_verified,
    safe_read_regular_file_bytes,
    verify_target_not_aliased_or_linked,
)
from upstream_check.engine import initialize_source, run_all_checks, update_baselines
from upstream_check.mcp import run_mcp_stdio_server
from upstream_check.reporters import (
    format_execution_error_markdown,
    format_json_report,
    format_markdown_report,
    format_terminal_report,
)

FORBIDDEN_SUMMARY_SUFFIXES = {
    ".yaml",
    ".yml",
    ".csv",
    ".tsv",
    ".json",
    ".geojson",
    ".py",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".sh",
    ".lock",
}

RAW_YAML_URL_RE = re.compile(
    r"(?:^|[\s{,])url\s*:\s*(?:'([^'\r\n]+)'|\"([^\"\r\n]+)\"|([^'\"#,\]}\r\n]+))",
    re.MULTILINE,
)
RAW_YAML_BASELINE_RE = re.compile(
    r"(?:^|[\s{,])baseline\s*:\s*(?:'([^'\r\n]+)'|\"([^\"\r\n]+)\"|([^'\"#,\]}\r\n]+))",
    re.MULTILINE,
)
RAW_YAML_NAME_RE = re.compile(
    r"(?:^|[\s{,-])name\s*:\s*(?:'([A-Za-z0-9._-]+)'|\"([A-Za-z0-9._-]+)\"|([A-Za-z0-9._-]+))",
    re.MULTILINE,
)


def _first_nonempty_group(match: re.Match[str]) -> str:
    for grp in match.groups():
        if grp is not None:
            return grp.strip()
    return ""


def _should_use_color(color_flag: Optional[bool]) -> bool:
    if color_flag is not None:
        return color_flag
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return False
    return sys.stdout.isatty()


def _add_protected_source_url(
    protected: Set[Path], raw_val: str, base_dir: Path
) -> bool:
    """Resolve a candidate source URL via the canonical resolver and add local paths to protected."""
    cleaned = raw_val.strip() if isinstance(raw_val, str) else ""
    if not cleaned:
        return True
    try:
        target = resolve_source_target(cleaned, base_dir=base_dir)
        for p in target.protected_paths():
            protected.add(p)
        return True
    except Exception:
        if "://" not in cleaned and "${" not in cleaned:
            cand = Path(cleaned)
            full = cand if cand.is_absolute() else (base_dir / cand)
            protected.add(full)
            try:
                protected.add(full.resolve())
            except OSError:
                pass
        return False


def _add_protected_baseline_path(
    protected: Set[Path], raw_val: str, base_dir: Path
) -> bool:
    """Resolve a candidate baseline path (expanding any ${ENV_VAR}) and add it to protected."""
    cleaned = raw_val.strip() if isinstance(raw_val, str) else ""
    if not cleaned:
        return True
    try:
        expanded = expand_env_vars(cleaned).strip()
        cand = Path(expanded)
        full = cand if cand.is_absolute() else (base_dir / cand)
        protected.add(full)
        try:
            protected.add(full.resolve())
        except OSError:
            pass
        return True
    except Exception:
        if "${" not in cleaned:
            cand = Path(cleaned)
            full = cand if cand.is_absolute() else (base_dir / cand)
            protected.add(full)
        return False


def _collect_protected_paths(
    config_path: str,
    loaded_config: Optional[UpstreamCheckConfig] = None,
) -> Tuple[Set[Path], bool]:
    """Collect all protected project paths via canonical resolution and return (protected_paths, config_verified)."""
    cfg_path = Path(config_path)
    base_dir = (
        cfg_path.parent.resolve()
        if cfg_path.parent != Path("")
        else Path.cwd().resolve()
    )
    protected: Set[Path] = {cfg_path}
    try:
        protected.add(cfg_path.resolve())
    except OSError:
        pass

    config_verified = loaded_config is not None
    has_unresolved_candidate = False

    effective_config = loaded_config
    if effective_config is None and os.path.lexists(cfg_path):
        try:
            effective_config = load_config(cfg_path)
        except Exception:
            effective_config = None

    if effective_config is not None:
        for src in effective_config.sources:
            raw_base = (
                src.schema_config.baseline
                if (src.schema_config and src.schema_config.baseline)
                else f"baselines/{src.name}.json"
            )
            if not _add_protected_baseline_path(protected, raw_base, base_dir):
                has_unresolved_candidate = True
            _add_protected_baseline_path(
                protected, f"baselines/{src.name}.json", base_dir
            )
            if not _add_protected_source_url(protected, src.url, base_dir):
                has_unresolved_candidate = True

    if os.path.lexists(cfg_path):
        try:
            raw_bytes, _ = safe_read_regular_file_bytes(
                cfg_path, max_bytes=10_485_760, label="configuration file"
            )
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            for url_match in RAW_YAML_URL_RE.finditer(raw_text):
                val = _first_nonempty_group(url_match)
                if val and not _add_protected_source_url(protected, val, base_dir):
                    has_unresolved_candidate = True
            for base_match in RAW_YAML_BASELINE_RE.finditer(raw_text):
                val = _first_nonempty_group(base_match)
                if val and not _add_protected_baseline_path(
                    protected, val, base_dir
                ):
                    has_unresolved_candidate = True
            for name_match in RAW_YAML_NAME_RE.finditer(raw_text):
                val = _first_nonempty_group(name_match)
                if val:
                    _add_protected_baseline_path(
                        protected, f"baselines/{val}.json", base_dir
                    )
            for env_match in ENV_INTERP_RE.finditer(raw_text):
                if not _add_protected_source_url(
                    protected, env_match.group(0), base_dir
                ):
                    has_unresolved_candidate = True
            for raw_brace in ANY_DOLLAR_BRACE_RE.finditer(raw_text):
                inner = raw_brace.group(1)
                if inner is None or not inner or not os.environ.get(inner):
                    has_unresolved_candidate = True

            parsed = yaml.safe_load(raw_text)
            if isinstance(parsed, dict) and isinstance(parsed.get("sources"), list):
                for item in parsed["sources"]:
                    if isinstance(item, dict):
                        if isinstance(item.get("url"), str):
                            if not _add_protected_source_url(
                                protected, item["url"], base_dir
                            ):
                                has_unresolved_candidate = True
                        if isinstance(item.get("name"), str):
                            _add_protected_baseline_path(
                                protected,
                                f"baselines/{item['name']}.json",
                                base_dir,
                            )
                        sch = item.get("schema") or item.get("schema_config")
                        if isinstance(sch, dict) and isinstance(
                            sch.get("baseline"), str
                        ):
                            if not _add_protected_baseline_path(
                                protected, sch["baseline"], base_dir
                            ):
                                has_unresolved_candidate = True
        except Exception:
            pass

    baselines_dir = base_dir / "baselines"
    if baselines_dir.exists() and baselines_dir.is_dir():
        for item in baselines_dir.rglob("*"):
            if item.is_file() or os.path.islink(item):
                protected.add(item)

    if has_unresolved_candidate:
        config_verified = False

    return protected, config_verified


def _validate_safe_summary_target(
    target_path_str: Optional[str],
    config_path: str,
    loaded_config: Optional[UpstreamCheckConfig] = None,
    label: str = "--summary-file",
) -> Optional[Path]:
    """Centralized fail-closed file-safety policy applied identically to --summary-file and $GITHUB_STEP_SUMMARY."""
    if not target_path_str:
        return None
    if not target_path_str.strip():
        raise ValueError(f"{label} path cannot be empty.")

    target_path = Path(target_path_str)
    if os.path.islink(target_path):
        raise ValueError(
            f"Refusing to write summary report ({label}) to '{target_path_str}': "
            "destination is a symbolic link."
        )

    target_resolved = target_path.resolve()
    if (
        (target_path.exists() and target_path.is_dir())
        or (target_resolved.exists() and target_resolved.is_dir())
    ):
        raise ValueError(
            f"Refusing to write summary report ({label}) to '{target_path_str}': "
            "path is a directory."
        )

    protected, config_verified = _collect_protected_paths(
        config_path, loaded_config=loaded_config
    )
    verify_target_not_aliased_or_linked(
        target_path,
        protected,
        label=f"summary report ({label})",
        forbid_symlinks=True,
        forbid_multiple_hardlinks=True,
    )

    for suffix in (target_path.suffix.lower(), target_resolved.suffix.lower()):
        if suffix in FORBIDDEN_SUMMARY_SUFFIXES:
            raise ValueError(
                f"Refusing to write Markdown summary report ({label}) to '{target_path_str}' "
                f"(protected file extension '{suffix}')."
            )

    if os.path.lexists(target_path) or os.path.lexists(target_resolved):
        if not config_verified:
            raise ValueError(
                f"Refusing to modify existing file '{target_path_str}' for {label} "
                "because configuration or protected-path verification failed (fail-closed protection)."
            )

    return target_path


def _write_summary_targets(
    summary_file: Optional[str],
    md_content: str,
    config_path: str = "upstream-check.yaml",
    loaded_config: Optional[UpstreamCheckConfig] = None,
) -> bool:
    """Write Markdown report to --summary-file and $GITHUB_STEP_SUMMARY using descriptor-verified I/O."""
    payload = md_content.rstrip("\n") + "\n"
    protected, config_verified = _collect_protected_paths(
        config_path, loaded_config=loaded_config
    )
    written_summary_path: Optional[Path] = None
    all_ok = True

    if summary_file:
        try:
            target_path = _validate_safe_summary_target(
                summary_file,
                config_path,
                loaded_config=loaded_config,
                label="--summary-file",
            )
            if target_path is not None:
                atomic_write_text_safe(
                    target_path=target_path,
                    content=payload,
                    protected_paths=protected,
                    allow_overwrite_existing=config_verified,
                    label="summary report (--summary-file)",
                )
                written_summary_path = target_path
        except Exception as exc:
            click.echo(f"Warning: Could not write summary file: {exc}", err=True)
            all_ok = False

    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh_summary:
        try:
            gh_path = _validate_safe_summary_target(
                gh_summary,
                config_path,
                loaded_config=loaded_config,
                label="$GITHUB_STEP_SUMMARY",
            )
            if gh_path is not None and (
                written_summary_path is None
                or not paths_refer_to_same_file(gh_path, written_summary_path)
            ):
                safe_append_text_verified(
                    target_path=gh_path,
                    content=payload,
                    protected_paths=protected,
                    allow_existing=config_verified,
                    label="step summary ($GITHUB_STEP_SUMMARY)",
                )
        except Exception as exc:
            click.echo(f"Warning: Could not write step summary: {exc}", err=True)
            all_ok = False

    return all_ok


def _fail_check_early(
    err_msg: str,
    exit_code: int,
    summary_file: Optional[str],
    config_path: str,
    loaded_config: Optional[UpstreamCheckConfig] = None,
) -> int:
    """Emit an error message to stderr and write a fallback diagnostic Markdown summary if target is safe."""
    safe_msg = redact_text(err_msg)
    click.echo(safe_msg, err=True)
    fallback_md = format_execution_error_markdown(
        error_message=safe_msg,
        exit_code=exit_code,
        config_path=config_path,
    )
    _write_summary_targets(
        summary_file,
        fallback_md,
        config_path=config_path,
        loaded_config=loaded_config,
    )
    return exit_code


def _extract_raw_cli_arg(args: List[str], flags: Tuple[str, ...]) -> Optional[str]:
    """Extract an option value from raw argv tokens before full Click parsing completes."""
    for idx, token in enumerate(args):
        for flag in flags:
            if token == flag and idx + 1 < len(args):
                return args[idx + 1]
            if token.startswith(f"{flag}="):
                return token.split("=", 1)[1]
    return None


class CheckCommandWithDiagnosticFallback(click.Command):
    """Custom Click Command that writes a diagnostic summary report safely even if CLI option parsing fails."""

    def make_context(
        self,
        info_name: Optional[str],
        args: List[str],
        parent: Optional[click.Context] = None,
        **extra: Any,
    ) -> click.Context:
        raw_snapshot = list(args)
        try:
            return super().make_context(
                info_name, args, parent=parent, **extra
            )
        except click.ClickException as exc:
            raw_summary = _extract_raw_cli_arg(raw_snapshot, ("--summary-file",))
            raw_config = (
                _extract_raw_cli_arg(raw_snapshot, ("--config", "-c"))
                or "upstream-check.yaml"
            )
            fallback_md = format_execution_error_markdown(
                error_message=f"CLI usage error: {redact_text(exc.format_message())}",
                exit_code=exc.exit_code,
                config_path=raw_config,
            )
            _write_summary_targets(
                raw_summary,
                fallback_md,
                config_path=raw_config,
                loaded_config=None,
            )
            raise


def _execute_init(
    url: str,
    name: Optional[str],
    fmt: Optional[str],
    config_path: str,
    force: bool,
) -> int:
    target_cfg = Path(config_path)
    out_dir = (
        target_cfg.parent.resolve()
        if target_cfg.parent != Path("")
        else Path.cwd().resolve()
    )
    if os.path.lexists(target_cfg) and not force:
        click.echo(
            f"Error: Configuration file '{target_cfg}' already exists. Pass --force to overwrite.",
            err=True,
        )
        return 2
    try:
        resolved_source = resolve_source_target(url, base_dir=out_dir)
        for sp in resolved_source.protected_paths():
            if paths_refer_to_same_file(target_cfg, sp):
                raise ValueError(
                    f"Configuration destination '{target_cfg}' collides with local source file '{sp}'."
                )

        config_dict, baseline, _, baseline_file = initialize_source(
            url=url,
            name=name,
            fmt=fmt,
            output_dir=out_dir,
            force=force,
        )
        protected_init: List[Path] = [baseline_file] + resolved_source.protected_paths()
        atomic_write_text_safe(
            target_path=target_cfg,
            content=dump_config_yaml(config_dict),
            protected_paths=protected_init,
            allow_overwrite_existing=force,
            label="configuration file",
        )
        click.echo("UPSTREAM CHECK INITIALIZED")
        click.echo("")
        click.echo(f"Source:   {baseline.source_name}")
        click.echo(f"Endpoint: {baseline.endpoint_redacted}")
        click.echo(
            f"Format:   {baseline.format} ({baseline.row_count} rows, {len(baseline.columns)} columns)"
        )
        click.echo(f"Baseline: {baseline_file}")
        click.echo(f"Config:   {target_cfg}")
        return 0
    except (ValueError, FileExistsError) as exc:
        click.echo(f"Configuration error: {redact_text(str(exc))}", err=True)
        return 2
    except Exception as exc:
        click.echo(f"Error initializing source: {redact_text(str(exc))}", err=True)
        return 1


def _execute_check(
    config_path: str,
    source_name: Optional[str],
    output_format: str,
    summary_file: Optional[str],
    reference_time_str: Optional[str],
    update_baseline_flag: bool,
    color_flag: Optional[bool],
) -> int:
    cfg_file = Path(config_path)
    gh_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    try:
        config = load_config(cfg_file)
    except Exception as exc:
        return _fail_check_early(
            f"Configuration error: {exc}",
            exit_code=2,
            summary_file=summary_file,
            config_path=config_path,
            loaded_config=None,
        )

    try:
        _validate_safe_summary_target(
            summary_file,
            config_path,
            loaded_config=config,
            label="--summary-file",
        )
        if gh_summary:
            _validate_safe_summary_target(
                gh_summary,
                config_path,
                loaded_config=config,
                label="$GITHUB_STEP_SUMMARY",
            )
    except ValueError as exc:
        click.echo(f"Configuration error: {redact_text(str(exc))}", err=True)
        return 2

    base_dir = (
        cfg_file.parent.resolve()
        if cfg_file.parent != Path("")
        else Path.cwd().resolve()
    )

    if update_baseline_flag:
        try:
            updated = update_baselines(
                config=config, base_dir=base_dir, source_filter=source_name
            )
            for src_name, b_path, b_model in updated:
                msg = (
                    f"Updated baseline for '{src_name}' "
                    f"({b_model.row_count} rows, {len(b_model.columns)} columns) -> {b_path}"
                )
                click.echo(msg)
        except ValueError as exc:
            return _fail_check_early(
                f"Configuration error: {exc}",
                exit_code=2,
                summary_file=summary_file,
                config_path=config_path,
                loaded_config=None,
            )
        except Exception as exc:
            return _fail_check_early(
                f"Error updating baseline: {exc}",
                exit_code=1,
                summary_file=summary_file,
                config_path=config_path,
                loaded_config=None,
            )

    ref_time: Optional[datetime] = None
    env_ref = reference_time_str or os.environ.get("UPSTREAM_CHECK_NOW")
    if env_ref:
        ref_time = parse_timestamp(env_ref)
        if ref_time is None:
            return _fail_check_early(
                f"Error: Invalid reference timestamp '{env_ref}'. Expected ISO-8601 format.",
                exit_code=2,
                summary_file=summary_file,
                config_path=config_path,
                loaded_config=None,
            )

    try:
        report = run_all_checks(
            config=config,
            base_dir=base_dir,
            source_filter=source_name,
            reference_time=ref_time,
        )
    except ValueError as exc:
        return _fail_check_early(
            f"Configuration error: {exc}",
            exit_code=2,
            summary_file=summary_file,
            config_path=config_path,
            loaded_config=None,
        )
    except Exception as exc:
        return _fail_check_early(
            f"Execution error: {exc}",
            exit_code=1,
            summary_file=summary_file,
            config_path=config_path,
            loaded_config=None,
        )

    fmt = output_format.lower().strip()
    if fmt == "json":
        rendered = format_json_report(report)
    elif fmt in ("markdown", "md"):
        rendered = format_markdown_report(report)
    else:
        rendered = format_terminal_report(
            report, color=_should_use_color(color_flag)
        )

    click.echo(rendered)
    summary_ok = _write_summary_targets(
        summary_file,
        format_markdown_report(report),
        config_path=config_path,
        loaded_config=config,
    )
    if not summary_ok:
        return 2

    return 0 if report.passed else 1


@click.group(
    name="upstream-check",
    help="Catch broken external data sources before they break your application.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(version=__version__, prog_name="upstream-check")
def app() -> None:
    """Root CLI command group."""


@app.command("init", help="Inspect an external source and generate a baseline + config.")
@click.argument("url")
@click.option("--name", "-n", default=None, help="Logical name for the upstream source.")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["csv", "json"], case_sensitive=False),
    default=None,
    help="Explicit source data format (auto-detected if omitted).",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    default="upstream-check.yaml",
    show_default=True,
    help="Path to write configuration file.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite existing configuration and baseline files if present.",
)
def init_cmd(
    url: str,
    name: Optional[str],
    fmt: Optional[str],
    config_path: str,
    force: bool,
) -> None:
    code = _execute_init(
        url=url, name=name, fmt=fmt, config_path=config_path, force=force
    )
    sys.exit(code)


@app.command(
    "check",
    cls=CheckCommandWithDiagnosticFallback,
    help="Run configured availability, schema, quality, and freshness checks.",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    default="upstream-check.yaml",
    show_default=True,
    help="Path to upstream-check.yaml configuration file.",
)
@click.option(
    "--source",
    "-s",
    "source_name",
    default=None,
    help="Run checks for a single named source only.",
)
@click.option(
    "--output",
    "-o",
    "output_format",
    type=click.Choice(["terminal", "json", "markdown"], case_sensitive=False),
    default="terminal",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--summary-file",
    default=None,
    help="Optional path to write a Markdown workflow summary (also appends to $GITHUB_STEP_SUMMARY if set).",
)
@click.option(
    "--now",
    "reference_time_str",
    default=None,
    help="Reference UTC timestamp (ISO-8601) for deterministic freshness evaluation.",
)
@click.option(
    "--update-baseline",
    "update_baseline_flag",
    is_flag=True,
    default=False,
    help="Re-fetch and update baseline JSON files before running checks (preserves YAML rules).",
)
@click.option(
    "--color/--no-color",
    "color_flag",
    default=None,
    help="Force enable or disable ANSI terminal colors.",
)
def check_cmd(
    config_path: str,
    source_name: Optional[str],
    output_format: str,
    summary_file: Optional[str],
    reference_time_str: Optional[str],
    update_baseline_flag: bool,
    color_flag: Optional[bool],
) -> None:
    code = _execute_check(
        config_path=config_path,
        source_name=source_name,
        output_format=output_format,
        summary_file=summary_file,
        reference_time_str=reference_time_str,
        update_baseline_flag=update_baseline_flag,
        color_flag=color_flag,
    )
    sys.exit(code)


@app.group(
    "baseline",
    help="Manage recorded schema and data quality baselines.",
)
def baseline_group() -> None:
    """Baseline command group."""


@baseline_group.command(
    "update",
    help="Refresh baseline JSON snapshots from live sources without overwriting YAML config rules.",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    default="upstream-check.yaml",
    show_default=True,
    help="Path to upstream-check.yaml configuration file.",
)
@click.option(
    "--source",
    "-s",
    "source_name",
    default=None,
    help="Update baseline for a single named source only.",
)
def baseline_update_cmd(config_path: str, source_name: Optional[str]) -> None:
    cfg_file = Path(config_path)
    base_dir = (
        cfg_file.parent.resolve()
        if cfg_file.parent != Path("")
        else Path.cwd().resolve()
    )
    try:
        config = load_config(cfg_file)
        updated = update_baselines(
            config=config,
            base_dir=base_dir,
            source_filter=source_name,
        )
        for src_name, b_path, b_model in updated:
            msg = (
                f"Updated baseline for '{src_name}' "
                f"({b_model.row_count} rows, {len(b_model.columns)} columns) -> {b_path}"
            )
            click.echo(msg)
        sys.exit(0)
    except ValueError as exc:
        click.echo(f"Configuration error: {redact_text(str(exc))}", err=True)
        sys.exit(2)
    except Exception as exc:
        click.echo(f"Error updating baseline: {redact_text(str(exc))}", err=True)
        sys.exit(1)


@app.command(
    "mcp",
    help="Start the Model Context Protocol (MCP) stdio server for coding agents.",
)
def mcp_cmd() -> None:
    run_mcp_stdio_server()


def main() -> None:
    """Entry point for console_scripts."""
    app()


if __name__ == "__main__":
    main()
