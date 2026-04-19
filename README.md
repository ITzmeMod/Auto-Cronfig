# 🔍 Auto-Cronfig v2

> **GitHub Secret Scanner** — Concurrent scanning, live key verification, and a self-improving SQLite intelligence engine.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Architecture

```
Auto-Cronfig v2
│
├── scanner.py              ← CLI entry point (backward compat)
│
├── engine/
│   ├── __init__.py
│   ├── patterns.py         ← 30+ pattern registry w/ severity & verifier refs
│   ├── verifier.py         ← Real HTTP live key verification
│   ├── memory.py           ← SQLite knowledge base (learns over time)
│   ├── scanner.py          ← Concurrent GitHub file scanner
│   └── orchestrator.py     ← Orchestration + reporting
│
├── tests/
│   ├── test_verifier.py    ← Verifier unit tests (mocked HTTP)
│   └── test_memory.py      ← Memory unit tests (SQLite :memory:)
│
└── requirements.txt
```

**Data flow:**

```
CLI args
  │
  ▼
AutoCronfig.run(target)
  │
  ├─► RepoScanner ──────────► GitHub API (tree + file contents)
  │        │                   (concurrent, 8 workers)
  │        ▼
  │   RawFindings (regex matches)
  │        │
  ├─► Verifier ─────────────► Live HTTP verification per service
  │        │                   (concurrent, 10 workers)
  │        ▼
  │   EnrichedFindings (LIVE/DEAD/UNKNOWN)
  │        │
  ├─► Memory (SQLite) ──────► Persists findings, stats, patterns
  │        │
  └─► ScanReport ───────────► Console + JSON/HTML output
```

---

## Installation

```bash
git clone https://github.com/ITzmeMod/Auto-Cronfig.git
cd Auto-Cronfig
pip install -r requirements.txt
```

---

## Usage

### Scan a repository
```bash
python scanner.py --repo owner/repo
python scanner.py --repo https://github.com/owner/repo
```

### Scan all public repos for a user
```bash
python scanner.py --user username
```

### Global GitHub code search
```bash
python scanner.py --global "AKIA"
python scanner.py --global "sk_live_" --max-results 50
```

### Show intelligence dashboard
```bash
python scanner.py --stats
```

### Export report
```bash
python scanner.py --repo owner/repo --output report.json
python scanner.py --repo owner/repo --output report.html
```

### Full options
```
  --repo OWNER/REPO     Scan a specific repository
  --user USERNAME       Scan all public repos for a user
  --global QUERY        Global GitHub code search
  --stats               Show memory stats and insights
  --token TOKEN         GitHub personal access token (or set GITHUB_TOKEN env var)
  --no-verify           Skip live key verification
  --output FILE         Save report to .json or .html
  --workers N           Concurrent workers (default: 8)
  --max-results N       Max results for global search (default: 100)
  --db-path PATH        Custom SQLite database path
```

---

## Key Verification

Auto-Cronfig v2 makes **real HTTP calls** to verify whether discovered secrets are actually live:

| Service | Method | Endpoint |
|---------|--------|----------|
| GitHub Token | GET | `api.github.com/user` |
| Stripe | GET | `api.stripe.com/v1/balance` |
| Slack | POST | `slack.com/api/auth.test` |
| Discord | GET | `discord.com/api/v10/users/@me` |
| Telegram | GET | `api.telegram.org/bot{token}/getMe` |
| SendGrid | GET | `api.sendgrid.com/v3/user/account` |
| Mailgun | GET | `api.mailgun.net/v3/domains` |
| Google API | GET | `maps.googleapis.com/...?key={key}` |

Each result is one of: `LIVE` 🚨 | `DEAD` ✅ | `UNKNOWN` ⚠️ | `ERROR` 🔴

Use `--no-verify` to skip verification and just scan.

---

## Memory & Learning System

Auto-Cronfig stores all findings in a local SQLite database (`~/.auto-cronfig/memory.db`).

### What it tracks
- **findings** — every secret match, with verification status
- **pattern_stats** — how often each pattern fires, live/dead ratios
- **file_stats** — which file types yield the most secrets
- **scan_history** — cumulative scan totals over time
- **knowledge** — derived insights refreshed on every scan

### How it gets smarter

Over time, the engine learns which file extensions and secret patterns are most dangerous:

1. **Extension prioritization** — Files with historically high finding rates are scanned first
2. **Pattern performance** — You can see which patterns fire most and have the highest live rate
3. **Intelligence insights** — Natural-language summaries generated from accumulated data

Example insights after several scans:
```
• .env files have the highest finding rate at 62%
• GitHub Personal Access Token has 34% live verification rate
• Most common secret type: Generic API Key (147 found)
• Lifetime: 12 scans, 4,821 files scanned, 89 total findings, 7 live keys confirmed
```

---

## Detected Secret Types (30+)

| Category | Patterns |
|----------|---------|
| **Cloud** | AWS Access Key, AWS Secret Key, Google API Key, Google OAuth, Firebase URL, Heroku API Key |
| **Payment** | Stripe Live/Test Key, Stripe Publishable Key, PayPal Client Secret |
| **Communication** | Slack Bot/User Token, Slack Webhook, Discord Bot Token, Discord Webhook, Twilio Account SID/Auth Token, Telegram Bot Token |
| **VCS** | GitHub PAT (Classic), GitHub OAuth Token, GitHub App Token, GitHub Fine-Grained PAT |
| **Email** | SendGrid API Key, Mailgun API Key |
| **Cryptography** | RSA Private Key, EC Private Key, OpenSSH Private Key, PGP Private Key |
| **Authentication** | JWT Token |
| **Database** | PostgreSQL, MySQL, MongoDB connection strings |
| **Streaming** | Twitch OAuth Token |
| **E-commerce** | Shopify Access Token, Shopify Private App Password |
| **Generic** | Generic API Key, Generic Secret, Generic Password |

---

## Running Tests

```bash
python -m pytest tests/ -v
```

All tests use mocked HTTP calls and in-memory SQLite — no real API keys needed.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built with ❤️ by [ITzmeMod](https://github.com/ITzmeMod)*
