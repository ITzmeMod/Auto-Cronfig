# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v3.x (latest) | ✅ Active |
| v2.x | ⚠️ Security fixes only |
| v1.x | ❌ End of life |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability:

1. Go to the [Security Advisories](https://github.com/ITzmeMod/Auto-Cronfig/security/advisories/new) page
2. Click **"New draft security advisory"**
3. Describe the vulnerability, steps to reproduce, and potential impact

We aim to acknowledge reports within **48 hours** and release a fix within **7 days** for critical issues.

## Security Design

### What Auto-Cronfig Does NOT Store

- Raw secret values are **never stored**. All leaked key entries in the SQLite vault use SHA-256 hashes of the raw value.
- GitHub tokens passed via `--token` or `GITHUB_TOKEN` are held in memory only and never written to disk by this tool.
- No data is sent to any third-party service (telemetry, analytics, etc.).

### SQL Injection Prevention

The `memory.py` engine uses parameterized queries (`?` placeholders) for all user-controlled input. The one location where a column name is interpolated into a SQL string (`update_pattern_stats`) uses an explicit allowlist validated with an `assert` before interpolation. The allowlist is:

```python
_ALLOWED_STAT_COLS = {"verified_live", "verified_dead", "verified_unknown"}
```

This value is derived entirely from internal logic, never from user input.

### Subprocess Safety

The Node.js scraper is invoked via `subprocess.run()` with:
- A **fixed command** (`["node", path_to_script, "--mode", mode]`)
- Mode validated against an explicit allowlist: `{"paste", "github-web", "gist"}`
- Query string sanitized: non-word characters stripped, max 200 chars
- `shell=False` (default) — no shell interpolation

### Rate Limiting

All GitHub API calls respect rate limits:
- Standard API: exponential backoff on 403/429 (max 3 retries)
- Code Search API: 6-second sleep between requests (10 req/min limit)

### Token Scope

A GitHub token with only `repo` scope (read-only) is sufficient for all scan operations. No write access is required or requested.

## Known Accepted Risks

| Finding | Severity | Accepted | Reason |
|---------|----------|----------|--------|
| `subprocess` import | Low | ✅ | Used with allowlist-validated args; `shell=False` |
| `except Exception` in workers | Low | ✅ | Background threads must not crash the main scan; all exceptions are now logged at DEBUG/WARNING level |

## Ethical Use

Auto-Cronfig is built for authorized security research and responsible disclosure only. Using this tool to scan repositories you do not own or have permission to scan may violate GitHub's Terms of Service and applicable laws. See [README.md](README.md#️-disclaimer) for the full disclaimer.
