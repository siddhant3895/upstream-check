# Changelog

All notable changes to **Upstream Check** are documented in this file.

## [0.2.13] — 2026-11-14 (Non-Blocking FIFO & Special-File Descriptor Hardening Release)

### Security & Filesystem Reliability Hardening
- **Non-blocking FIFO and special-file rejection in `safe_append_text_verified()` and `verify_target_not_aliased_or_linked()` (`src/upstream_check/core/types.py`)**:
  - Added `os.O_NONBLOCK` (where supported) to `os.open()` in `safe_append_text_verified()` so named pipes (FIFOs) without a reader fail immediately (`ENXIO`) instead of hanging the CLI, and FIFOs with a reader or special device nodes (`/dev/null`, sockets, block/character devices) are rejected by `stat.S_ISREG(fd_stat.st_mode)` in `verify_open_fd_safe()` before any write occurs, clearing `O_NONBLOCK` via `fcntl` once `S_ISREG` is verified.
  - Updated `verify_target_not_aliased_or_linked()` to reject existing non-regular files (`not stat.S_ISREG(st.st_mode)`) upfront across `--summary-file`, `$GITHUB_STEP_SUMMARY`, `init`, and `baseline update`.
- **Non-blocking regular-file reader across config, baseline, and local source loaders (`src/upstream_check/core/types.py`, `src/upstream_check/config/models.py`, `src/upstream_check/engine.py`, `src/upstream_check/sources/local_file.py`, `src/upstream_check/cli/app.py`)**:
  - Added `safe_read_regular_file_bytes()` opening files with `os.O_RDONLY | O_NONBLOCK` and verifying `stat.S_ISREG(os.fstat(fd).st_mode)` before reading, eliminating potential FIFO hangs and check-then-read windows when reading configuration files, baseline JSON files, or local CSV/JSON data sources.

## [0.2.12] — 2026-11-14 (TOCTOU-Hardened Descriptor-Verified Summary Appending Release)
- Replaced pathname-based `open(gh_path, "a")` in `_write_summary_targets()` with descriptor-verified `safe_append_text_verified()` and `verify_open_fd_safe()` (`O_APPEND | O_NOFOLLOW`, `os.fstat(fd)` device/inode/link-count checks, pre/post-open protected stat snapshots, and direct `os.write(fd, ...)` + `os.fsync(fd)`).

## [0.2.11] — 2026-11-14 (Fail-Closed Unverified Summary Protection & Flow-Style YAML Scanner Release)
- Unified `--summary-file` and `$GITHUB_STEP_SUMMARY` under identical fail-closed rules when configuration or protected-path verification fails, removed the `## Upstream Check Report` header heuristic, and expanded raw YAML fallback regexes to extract inline flow-style mappings (`sources: [{name: feed, url: "${SRC}", format: csv}]`) and standalone `${ENV_VAR}` placeholders.

## [0.2.10] — 2026-11-14 (Canonical Local-Source Resolution & Baseline/Summary Collision Hardening Release)
- Added `ResolvedSourceTarget` and `resolve_source_target()` as the single source of truth for classifying and resolving local and remote data sources (`relative`, `absolute`, Windows drive/UNC, `file://`, percent-encoded `file://`, `${ENV_VAR}`, `${ENV_FILE_URI}`, and remote `http://`/`https://`), and added `validate_baseline_destinations()` upfront audit.

## [0.2.9] — 2026-11-14 (Inode-Aware File-Safety Hardening, Atomic Writes & Sentinel MCP Validation Release)
- Added `paths_refer_to_same_file()`, `verify_target_not_aliased_or_linked()`, and `atomic_write_text_safe()` using `os.path.samefile()`, `os.path.samestat()` (`st_dev`, `st_ino`), `os.path.islink()`, and hard-link count checks (`st_nlink > 1`), plus `_MISSING = object()` sentinel in `src/upstream_check/mcp.py` rejecting `"arguments": null` with `-32602`.

## [0.2.8] — 2026-11-14 (Destructive Path Guards, Spec-Exact MCP Errors & Workflow Fallback Release)
- Added initial `--summary-file` path guard, `CheckCommandWithDiagnosticFallback`, spec-exact `-32022` `UnsupportedProtocolVersionError` (`supported`/`requested`), `-32602` for unknown MCP tools and falsey arguments, `2025-06-18` legacy negotiation, and stderr-fingerprinted workflow fallback.

## [0.2.7] — 2026-11-14
- Required `2026-07-28` `_meta` on `server/discover`, rejected legacy versions inside modern `_meta`, required `protocolVersion`, `capabilities`, and `clientInfo` on legacy `initialize`, and added early-failure diagnostic summary generation.

## [0.2.6] — 2026-11-14
- Added MCP `2026-07-28` response envelopes (`resultType`, `ttlMs`, `cacheScope`, `_meta`), rejected RFC 8259-invalid `NaN`/`Infinity` JSON constants, validated `${ENV_VAR}` placeholder syntax, added metric-invariant incident fingerprints, and rejected HTML error pages masquerading as CSV feeds.

## [0.2.5] — 2026-11-14
- Added strict baseline integrity validation (`BaselineModel.from_dict`), JSON flattening key-collision detection, 1,001-digit integer `OverflowError` guards, loud missing `${ENV_VAR}` checks, bounded concurrent multi-source execution (`ThreadPoolExecutor`), magnitude-aware column rename disambiguation, and CP1252/Latin-1 CSV decoding fallbacks.

## [0.2.4] — 2026-11-13
- Removed hardcoded `max_null_pct: 10` from `init`, rejected `NaN`/`inf` and boolean-as-number config values, prevented 0-row payloads from overwriting baselines, added MCP `ping`, and completed all 30 column profiles in the USGS baseline.

## [0.2.3] — 2026-11-13
- Scoped `max_null_pct` on live USGS feed, stopped auto-generating brittle `min`/`max` rules during `init`, fixed empty datasets bypassing baseline row-drop checks, changed `>=` to `>` on `0%` thresholds, rejected non-numeric values under `min`/`max`, closed URL-fragment credential leakage, and protected existing baselines from overwrite without `--force`.

## [0.2.2] — 2026-11-13
- Prevented plaintext credential persistence in `upstream-check.yaml`, added `${ENV_VAR}` URL interpolation, blocked source-name and baseline path traversal, pointed scheduled workflow at live USGS config, and standardized wheel builds on `setuptools.build_meta`.

## [0.2.1] — 2026-11-13
- Fixed GitHub Action shell injection (`action.yml`), unknown `--source` filter validation, ragged CSV row-width detection, future-dated and corrupted timestamp detection, all-null column rejection, strict configuration schema validation, and bounded HTTP response streaming (`max_response_bytes`).
