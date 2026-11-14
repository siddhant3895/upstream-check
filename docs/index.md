# Upstream Check Documentation (`v0.2.1`)

**External data reliability for developers.**

Monitor external JSON APIs, CSV feeds, and public datasets directly from your development workflow—without database infrastructure, hosted accounts, or vendor lock-in.

## Primary Workflow

1. **Connect source**: `upstream-check init <url> --name <source-name>`
2. **Review contract**: Inspect `upstream-check.yaml` and commit `baselines/<source-name>.json`.
3. **Run checks**: `upstream-check check`
4. **Automate in CI**: Run via GitHub Actions on a cron schedule or pull request.

## Exit Codes

| Exit Code | Meaning |
| :--- | :--- |
| `0` | All configured checks passed across all evaluated sources. |
| `1` | One or more critical findings failed validation (or source was unreachable). |
| `2` | Invalid CLI arguments, unknown `--source` filter, or invalid `upstream-check.yaml` configuration. |
