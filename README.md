# Upstream Check

**External data reliability for developers.**

Monitor external JSON APIs, CSV feeds, and public datasets directly from your development workflow.
No database infrastructure. No hosted account. No vendor lock-in.

`MIT License` · `Python 3.11 | 3.12 | 3.13` · `CLI` · `GitHub Actions`

Your data sources change. Your application shouldn't find out the hard way.

## Why Upstream Check?

Data-warehouse platforms (like Great Expectations or Soda Core) are built for internal SQL tables and data teams. OpenAPI diff tools (like `oasdiff`) only compare static API specs.

**Upstream Check** is built for **application developers** whose backends, cron jobs, or dashboards depend on third-party JSON APIs and public CSV feeds that silently break:

1. **Connect source** → Point at any JSON/GeoJSON endpoint or CSV URL.

2. **Generate baseline** → Commit a deterministic schema & data-quality snapshot (`baselines/<name>.json`).

3. **Run checks** → Validate availability, schema drift, null spikes, row-count drops, and timestamp freshness in one command.

4. **Catch regressions in GitHub Actions** → Fail CI or open an automated GitHub Issue before bad upstream data reaches production.

## Quickstart

Choose **Track A** to monitor any live URL immediately, or **Track B** to clone this repository and run the self-contained offline regression demo.

### Track A: Monitor a Live Public API (Standalone CLI)

Install the CLI and initialize a baseline against a live public endpoint (such as the USGS Earthquakes GeoJSON feed):

```
pipx install upstream-check

upstream-check init https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson \
  --name usgs-hourly

upstream-check check
```

### Track B: Run the Reproducible Regression Demo (From Source Clone)

Clone the repository and run `examples/run_demo.py` (starts a local HTTP server, initializes a baseline from a healthy 50-row air-quality CSV feed, and then introduces three controlled upstream regressions):

```
git clone https://github.com/siddhant3895/upstream-check.git
cd upstream-check
pip install -e ".[dev]"

python examples/run_demo.py
```

Output when the upstream feed degrades:

```
UPSTREAM CHECK

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
3 findings require attention.
```

You can also run the pre-configured live USGS check included in the repository:

```
upstream-check check --config examples/real-world/upstream-check.live.yaml
```

## Configuration Reference (`upstream-check.yaml`)

Unknown YAML keys and invalid source names (`..`, `/`, `\`) are strictly rejected so configuration typos or unsafe paths never fail silently.

```
version: 1

sources:
  - name: air-quality
    url: examples/data/air_quality_healthy.csv
    format: csv
    max_response_bytes: 52428800  # 50 MB cap

    freshness:
      column: observed_at
      max_age: 36h
      max_future_skew: 5m
      max_invalid_pct: 0

    schema:
      baseline: baselines/air-quality.json
      allow_extra_columns: false

    columns:
      station_id:
        required: true
        type: string

      pm25:
        required: true
        type: number
        min: 0
        max: 1000
        max_null_pct: 10

    quality:
      max_null_pct: 10
      max_null_spike_pct: 20
      max_row_drop_pct: 50
      min_rows: 1
      unique:
        - station_id
        - observed_at
```

### Supported Rules & Defaults

| Section / Field | Type | Default | Description |
| ----- | ----- | ----- | ----- |
| `sources[].name` | `slug` | Required | Safe identifier (`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`). |
| `sources[].format` | `csv \| json` | `"csv"` | Source payload format. |
| `sources[].delimiter` | `string` | Auto-sniffed | Explicit CSV delimiter (`","`, `";"`, `"\t"`, `"\|"`). |
| `sources[].flatten_json` | `bool` | `true` | Flatten nested JSON objects into dot-notation columns (up to depth 3). |
| `sources[].json_records_path` | `string` | Auto-detected | Dot path to the record array in JSON responses (e.g., `data.stations`, `features`). |
| `sources[].retries` | `0..10` | `2` | Automatic retries with exponential backoff on HTTP `429`/`502`/`503`/`504`. |
| `sources[].timeout_seconds` | `float > 0` | `15.0` | HTTP request timeout in seconds. |
| `sources[].max_response_bytes` | `int > 0` | `52428800` | Maximum allowed payload size in bytes (50 MB default) before aborting. |
| `freshness.column` | `string` | `null` | Timestamp column to evaluate (ISO-8601, `YYYY-MM-DD`, or Unix epoch). |
| `freshness.max_age` | `duration` | `"24h"` | Maximum age of the newest record (`"36h"`, `"2d"`, `"90m"`). |
| `freshness.max_future_skew` | `duration` | `"5m"` | Maximum allowed future clock skew before flagging future-dated timestamps. |
| `freshness.max_invalid_pct` | `0..100` | `0.0` | Maximum percentage of rows allowed to have missing or unparseable timestamps. |
| `schema.baseline` | `path` | `null` | Relative path to baseline JSON snapshot (must remain inside project directory and never alias a source file). |
| `schema.allow_extra_columns` | `bool` | `false` | Whether unrecorded new columns are permitted without failing schema checks. |
| `columns.<name>.required` | `bool` | `true` | Require column presence and at least one non-null observation. |
| `columns.<name>.type` | `string` | `null` | Expected type (`string`, `number`, `integer`, `boolean`, `datetime`, `object`, `array`). |
| `columns.<name>.min` / `max` | `float` | `null` | Inclusive numerical bounds (`min <= max` enforced). |
| `columns.<name>.allowed_values` | `list` | `null` | Allowed enum values for categorical columns. |
| `quality.max_null_pct` | `0..100` | `null` | Maximum allowed null percentage across columns. |
| `quality.max_null_spike_pct` | `0..100` | `20.0` | Maximum percentage-point null increase allowed over the baseline snapshot. |
| `quality.max_row_drop_pct` | `0..100` | `50.0` | Maximum percentage drop in row count compared to the baseline snapshot. |
| `quality.unique` | `list[str]` | `[]` | Single or composite column names that must be unique across non-null rows. |
| `quality.min_rows` / `max_rows` | `int >= 0` | `1` / `null` | Minimum and maximum allowed row counts. |

### Passing API Credentials Safely

`upstream-check init` refuses to write plaintext API keys or passwords into `upstream-check.yaml`. Always use `${ENV_VAR}` placeholders in `headers` or `url` so secrets remain in your environment or GitHub Secrets:

```
sources:
  - name: weather-stations
    url: https://api.example.org/v1/stations.json?api_key=${WEATHER_API_KEY}
    format: json
    headers:
      Authorization: "Bearer ${WEATHER_API_TOKEN}"
```

## CLI Reference

| Command | Description |
| ----- | ----- |
| `upstream-check init <url> [--name <slug>] [--format csv\|json]` | Fetch a source, write `baselines/<name>.json`, and scaffold `upstream-check.yaml`. |
| `upstream-check check [--config upstream-check.yaml] [--source <name>]` | Run all checks (`0` = passed, `1` = check failed, `2` = config/CLI error). |
| `upstream-check baseline update [--source <name>]` | Refresh `baselines/*.json` from live sources without overwriting custom YAML rules. |
| `upstream-check check --output json` | Emit machine-readable JSON for CI pipelines or scripts. |
| `upstream-check check --output markdown` | Emit a Markdown summary table (auto-appended to `$GITHUB_STEP_SUMMARY` in GitHub Actions). |
| `upstream-check mcp` | Start the JSON-RPC 2.0 stdio MCP server (spec-compliant with both stateless `2026-07-28` `server/discover` and legacy `2025-11-25`/`2025-06-18`/`2024-11-05` `initialize`/`ping` handshakes). |

## GitHub Actions Integration

Add `.github/workflows/upstream-check.yml` to run on a schedule or on pull requests:

```
name: Upstream Data Check

on:
  schedule:
    - cron: "0 */6 * * *"
  pull_request:

jobs:
  upstream-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: siddhant3895/upstream-check@v0.2.13
        with:
          config: upstream-check.yaml
```

See `.github/workflows/upstream-check-schedule.yml` for a complete workflow that checks `examples/real-world/upstream-check.live.yaml` every 6 hours and opens or comments on a GitHub Issue if a check or configuration load fails.

## Format Limitations & Edge Cases

* **CSV Dialect & Widths**: Standard RFC-4180 CSV/TSV files with a single header row are supported. Multi-line merged headers, HTML error pages, or ragged rows (rows with more or fewer cells than the header row) are flagged as failures.

* **JSON Structure**: Strict RFC 8259 JSON is enforced (`NaN`, `Infinity`, and `-Infinity` tokens are rejected). JSON payloads must be either an array of record objects (`[{...}, {...}]`) or an object envelope containing a record list (auto-detected under `data`, `results`, `items`, `records`, `rows`, `entries`, `features`, or specified via `json_records_path`). Nested objects are flattened with dot-notation up to depth 3; nested lists remain `array` values.

* **Payload Size**: Responses are streamed up to `max_response_bytes` (default 50 MB). For multi-gigabyte parquet or warehouse dumps, use a dedicated warehouse tool.

* **Timestamps**: Supports ISO-8601 strings, `YYYY-MM-DD[ HH:MM[:SS]]`, RFC-2822 HTTP `Last-Modified` dates, and Unix epoch seconds/milliseconds (between years 2000 and 2100). Locale-ambiguous dates like `03/04/2026` (`MM/DD/YYYY` vs `DD/MM/YYYY`) are intentionally rejected.

## Troubleshooting

* **Exit code `2` (`Refusing to initialize with plaintext credentials in URL`)**: Replace the literal API key in the URL with `${YOUR_ENV_VAR}` or configure `headers:` in `upstream-check.yaml`.

* **Exit code `2` (`Invalid source name` / `Baseline path escapes project directory`)**: Ensure `--name` only contains alphanumeric characters, `.`, `_`, or `-`, and that `schema.baseline` is a relative path inside your project directory.

* **Exit code `2` (`Unknown configuration field...`)**: Check `upstream-check.yaml` for misspelled rule names (e.g. `max_null_perc` instead of `max_null_pct`).

* **Exit code `2` (`Unknown source '<name>'`)**: The `--source` flag did not match any `sources[].name` entry in `upstream-check.yaml`.

## License

MIT License — see [LICENSE](LICENSE) and [CHANGELOG.md](CHANGELOG.md).
