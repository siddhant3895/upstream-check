# Contributing to Upstream Check

Thank you for helping make external data sources safer to depend on!

## Local Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/siddhant3895/upstream-check.git
   cd upstream-check
   ```
2. Install in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Run tests and the end-to-end demo:
   ```bash
   python -m unittest discover -s tests -v
   python examples/run_demo.py
   ```

## Architecture Guidelines

- Keep `src/upstream_check/checks/` modules pure and deterministic: each check function accepts a `SourceConfig`, a `FetchedDataset`, and an optional `BaselineModel` or `reference_time`, returning a ` list[CheckFinding]`.
- Never mutate raw dataset values inside a check module.
- Ensure any new configuration field in `src/upstream_check/config/models.py` includes validation and unit tests in `tests/test_upstream_check.py`.

## Good First Issues

- Add support for custom CSV delimiters (`delimiter: ";"`, `delimiter: "\t"`) in `SourceConfig`.
- Add regex pattern matching rule (`pattern: "^IN-[A-Z]{2}-\\d+$"`) to `ColumnRuleConfig`.
- Add HTTP retry with exponential backoff for transient `502`/`503`/`504` responses in `sources/http_csv.py` and `sources/http_json.py`.
- Add `--update-baseline` flag to `upstream-check check` for explicit, developer-approved schema updates.
