# Security Policy

## Credential & Data Privacy Guarantees

Upstream Check is designed around strict local execution and zero credential leakage:

1. **No Telemetry or Cloud Uploads**: Upstream Check never transmits fetched data, schemas, or reports to any third-party server.
2. **Automatic URL Redaction**: Userinfo (`user:pass@host`) and sensitive query parameters (`api_key`, `token`, `secret`, `password`, `sig`) are stripped and replaced with `REDACTED` before writing `baselines/*.json` or terminal/CI reports.
3. **Environment Variable Header Interpolation**: Authentication headers should always use `${ENV_VAR}` syntax in `upstream-check.yaml` so secrets remain in your CI secret store.

## Reporting a Vulnerability

If you discover a security issue (such as credential leakage in error tracebacks or baseline artifacts), please open a private security advisory on GitHub rather than a public issue.
