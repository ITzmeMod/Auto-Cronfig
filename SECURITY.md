# Security Policy — Auto-Cronfig

## Supported Versions

| Version | Status |
|---------|--------|
| v3.x (latest) | ✅ Active — security fixes applied immediately |
| v2.x | ⚠️ Security fixes only |
| v1.x | ❌ End of life — upgrade required |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Option 1 — GitHub Private Advisory (preferred)
1. Go to: https://github.com/ITzmeMod/Auto-Cronfig/security/advisories/new
2. Click **"New draft security advisory"**
3. Describe the vulnerability, reproduction steps, and impact

### Option 2 — GitHub Contact
Contact the author directly: https://github.com/ITzmeMod

**Response SLA:**
- Acknowledgement: within **48 hours**
- Fix for Critical/High: within **7 days**
- Fix for Medium/Low: within **30 days**
- CVE request (if warranted): coordinated with fix

---

## Security Architecture

### 🔐 No Secrets Stored in Code
- Zero hardcoded credentials anywhere in the codebase
- GitHub token read from: `--token` flag → `GITHUB_TOKEN` env var → config file
- All tokens held in memory only during the session
- Config file (`~/.auto-cronfig/config.json`) written with `chmod 600` (owner-only)
- Config directory created with `chmod 700`

### 🏦 Vault Design
- Raw secret values are **never stored** anywhere
- All vault entries use SHA-256 hashes of the raw value
- Only masked previews shown: `ghp_abc••••xyz`
- Vault stored in `~/.auto-cronfig/memory.db` (SQLite, local only)

### 🛡️ Input Validation (engine/security.py)
All user-supplied inputs are validated before use:

| Input | Validation |
|-------|-----------|
| GitHub username | Regex `^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$` |
| GitHub repo | `owner/repo` format, each part regex-validated |
| Search query | Strip null bytes, control chars, max 200 chars |
| Platform name | Allowlist: `{lovable, bolt, replit, base44, v0, cursor, windsurf, claude, ...}` |
| Output path | No `..` traversal, extension allowlist: `.json .csv .html .md .txt` |

### 🔒 SQL Injection Prevention
The one location where a column name is interpolated into SQL (`update_pattern_stats`)
uses an explicit allowlist validated with `if col not in _ALLOWED_STAT_COLS: raise ValueError(...)`.
All other SQL uses parameterised queries (`?` placeholders).

### ⚙️ Subprocess Safety
Node.js scraper invoked via:
- Fixed command list: `["node", path_to_script, "--mode", mode]`
- Mode validated against allowlist: `{"paste", "github-web", "gist"}`
- `shell=False` always
- Query sanitised before passing

### 🌐 Network Security
- All external requests use **HTTPS only**
- Full User-Agent string identifying the tool for transparency
- Timeout on all requests (8–15 seconds)
- Exponential backoff on 403/429 (max 3 retries)
- No telemetry or data sent to third parties

### 🔑 Token Handling
- Tokens are **never logged** — `redact_token()` strips them from error messages
- Tokens are **never written to disk** by the scan engine
- Only the config file stores the token, with restricted permissions
- `--token` flag takes precedence over config file
- `GITHUB_TOKEN` env var supported as alternative

### 🏷️ Attribution (engine/security.py)
Attribution notice displayed on every startup:
```
Auto-Cronfig v3.0.0 by ITzmeMod | github.com/ITzmeMod/Auto-Cronfig | MIT License
For authorized security research only.
```

---

## Security Audit Results

| Tool | Result | Date |
|------|--------|------|
| Bandit (Python SAST) | **0 findings** | 2026-04-19 |
| npm audit | **0 vulnerabilities** | 2026-04-19 |
| Manual code review | Passed | 2026-04-19 |

---

## Known Accepted Risks

| Finding | Severity | Accepted | Justification |
|---------|----------|----------|---------------|
| `subprocess` import | Low (B404) | ✅ | Used with allowlist-validated fixed args; `shell=False` |
| Empty-string config defaults | Low (B105) | ✅ | Unset sentinels, not passwords; `nosec` with justification |
| Column name in SQL string | Low (B608) | ✅ | Allowlist-validated before interpolation; `if/raise` guard |

---

## Ethical Use Policy

Auto-Cronfig is built for **authorized security research and responsible disclosure**:

✅ **Allowed:**
- Scanning your own repositories
- Scanning repositories you have written permission to test
- Research in controlled/sandboxed environments
- Educational demonstrations

❌ **Not allowed:**
- Scanning repositories without authorization
- Using discovered credentials for any purpose
- Automated mass-scanning without rate limiting
- Circumventing GitHub's ToS or API rate limits

**If you discover live credentials in a public repository:**
1. **Do not use the credentials** under any circumstances
2. Contact the repository owner immediately (GitHub private message or issue)
3. Consider GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories)
4. Allow reasonable time for remediation before any public disclosure

Misuse of this tool may violate GitHub's Terms of Service, the Computer Fraud and
Abuse Act (CFAA), and equivalent laws in other jurisdictions.
