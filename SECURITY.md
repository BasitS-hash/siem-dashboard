# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SentinelView, please report it
responsibly:

1. **Do not** open a public GitHub issue for security-sensitive reports.
2. Use **[GitHub Security Advisories](https://github.com/BasitS-hash/siem-dashboard/security/advisories/new)**
   ("Report a vulnerability") to disclose privately.
3. Include reproduction steps, affected versions, and impact assessment.

You can expect an acknowledgment within a few days. Please allow reasonable
time for a fix before any public disclosure.

## Scope

This is a demonstration / portfolio project. It intentionally ships **without
authentication** and uses an **in-memory data store**. It is not intended for
production deployment as-is. Reports about the absence of authentication or
persistence are out of scope (these are documented design choices — see the
roadmap in the README).

In scope:
- Injection vulnerabilities (XSS, CSV/formula injection, command injection)
- Input-validation bypasses on REST endpoints or socket events
- Denial-of-service vectors (unbounded input, resource exhaustion)
- Dependency vulnerabilities with a practical exploit path
- Information disclosure (stack traces, secrets, internal details)

## Hardening Measures

The following controls are implemented in the codebase:

### Transport & Headers
- **helmet** sets secure HTTP response headers.
- **`x-powered-by` disabled** to avoid framework fingerprinting.
- **CORS allowlist** — only explicitly configured origins are permitted; the
  wildcard origin `*` is rejected at startup.

### Rate Limiting & Resource Bounds
- **Per-IP rate limiting** on `/api` (configurable via `RATE_LIMIT_MAX`).
- **JSON body size cap** (`10kb`) on REST requests.
- **Socket.io payload cap** (`maxHttpBufferSize` 1 MB) to limit memory abuse.
- **Query `limit` clamping** (1–500) on log retrieval.

### Input Validation
- Alert IDs validated against a UUID-safe character set and length cap.
- Alert status validated against a fixed enum.
- All validators are pure functions with dedicated unit tests.

### Output Safety
- **CSV formula-injection defense:** exported cells beginning with
  `=`, `+`, `-`, `@`, tab, or carriage return are prefixed with a single quote
  so spreadsheet software treats them as text, never as executable formulas.
- **RFC 4180 quoting** for commas, quotes, and newlines.
- Centralized Express error handler returns generic messages and never leaks
  stack traces to clients.

### Configuration
- **Startup environment validation** (`config.ts`): invalid `PORT`,
  `ALLOWED_ORIGINS`, or `RATE_LIMIT_MAX` cause the process to exit with a
  clear error rather than running in a misconfigured state.
- **No secrets in source.** Configuration is supplied via environment
  variables; `.env` is git-ignored and only `.env.example` is committed.

### Supply Chain & CI
- **Dependencies pinned** to exact versions for reproducible installs.
- **CodeQL** static analysis (`security-and-quality` queries) on every PR and
  weekly.
- **gitleaks** scans full git history for committed secrets.
- **`npm audit`** runs in CI and fails on high-severity production advisories.
- **Dependabot** opens weekly update PRs for npm packages and GitHub Actions.

## Known Issues / Accepted Risk

- **esbuild dev-server advisory (GHSA-67mh-4wv8-2f99, moderate):** present via
  the Vite 5 toolchain. It affects only the local development server (not
  production builds or the deployed artifact) and is remediated only by a Vite
  major-version upgrade, which is deferred to avoid breaking the build. Tracked
  for a future upgrade.

## Secret Management

No secrets are committed to this repository. The threat-intelligence feeds used
(Feodo Tracker, URLhaus, CISA KEV) are **public and require no API keys**. If
you add an authenticated feed or service, store its credentials in environment
variables (never in source) and add them to `.env.example` as documented,
empty placeholders.
