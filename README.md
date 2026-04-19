<div align="center">

<img src="https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/.github/assets/banner.svg" alt="Auto-Cronfig Banner" width="100%">

# Auto-Cronfig

**Enterprise-grade GitHub secret scanner with live key verification, deep scan, and a self-improving intelligence engine.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Node.js 16+](https://img.shields.io/badge/Node.js-16%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/Tests-111%20passing-brightgreen?logo=pytest&logoColor=white)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-Termux%20Ready-3DDC84?logo=android&logoColor=white)](TERMUX.md)
[![Open Source](https://img.shields.io/badge/Open-Source-orange?logo=github)](https://github.com/ITzmeMod/Auto-Cronfig)

[Features](#-features) · [Install](#-installation) · [Interactive Menu](#-interactive-menu) · [Usage](#-usage) · [Scan Modes](#-scan-modes) · [Key Verification](#-key-verification) · [Memory & Learning](#-memory--learning-system) · [Notifications](#-notifications) · [Android](#-android--termux) · [Contributing](#-contributing)

</div>

---

## 🔍 What is Auto-Cronfig?

Auto-Cronfig is an open-source, enterprise-grade tool for scanning GitHub repositories for leaked API keys, secrets, credentials, and security vulnerabilities. It goes beyond simple regex matching — it **verifies keys are live**, **learns from every scan**, and gets smarter over time through a built-in SQLite intelligence engine.

Built with a Python + Node.js hybrid architecture, it scans not just file contents but also **commit history** (catching secrets that were added and deleted), **pull requests**, **issues**, **gists**, and across **all of GitHub** via the code search API.

---

## ✨ Features

### 🔎 Scanning
- **208+ detection patterns** across 15 categories — no AI dependency, pure regex
- **4 scan modes**: Fast, Standard, Deep, Global
- **Concurrent scanning** — up to 16 parallel workers via `ThreadPoolExecutor`
- **Deep scan** — commit history (catches deleted secrets!), PRs, issues, gists, wiki, releases
- **Global auto-scan** — 50+ built-in search queries across all of public GitHub
- **Node.js hybrid engine** — axios + cheerio for Pastebin, GitHub web search, Gist scraping
- **Smart pre-filtering** — content signal check before full regex scan for maximum speed
- **Risky file prioritization** — memory-guided, scans `.env`/`.pem`/etc. first

### 🔑 Verification
- **Live HTTP key verification** for 15 services
- Results: `LIVE 🚨` / `DEAD ✅` / `UNKNOWN ⚠️` / `ERROR 🔴`
- Concurrent verification with up to 10 workers
- Timeout-safe — never hangs on a slow endpoint

### 🧠 Intelligence
- **Self-improving SQLite memory** — learns from every scan
- **Leaked keys vault** — SHA256-hashed, never stores raw secrets
- **False positive registry** — mark once, skip forever
- **Watchlist** — auto-rescan repos/users on demand
- **Natural language insights** generated from accumulated scan data

### 📊 Reporting
- **4 export formats**: JSON, CSV, HTML (dark theme), Markdown
- **Rich terminal tables** with color-coded severity
- **Scan history dashboard** with lifetime statistics
- HTML reports are self-contained, dark-themed, fully offline

### 🔔 Notifications
- **Telegram**, **Discord**, **Slack**, custom webhook
- Severity thresholds — only alert on CRITICAL/HIGH if you want
- Non-blocking — runs in background threads
- Scan-complete summaries

### 📱 Cross-Platform
- Linux, macOS, Windows (WSL), Android (Termux — no root required)
- Universal one-liner installer auto-detects your platform

---

## 📐 Architecture

```
Auto-Cronfig v3
│
├── scanner.py                  ← CLI entry point
│
├── engine/
│   ├── patterns.py             ← 208-pattern registry (loads from JSON + fallback)
│   ├── verifier.py             ← Live HTTP key verification (15 services)
│   ├── memory.py               ← SQLite brain: vault, watchlist, false positives
│   ├── scanner.py              ← Concurrent GitHub file scanner
│   ├── deep_scanner.py         ← Commits, PRs, issues, gists, wiki, releases
│   ├── global_scanner.py       ← GitHub code search, 50+ built-in queries
│   ├── notifier.py             ← Telegram/Discord/Slack/webhook alerts
│   ├── exporter.py             ← JSON/CSV/HTML/Markdown export
│   └── orchestrator.py         ← Pipeline: scan → verify → learn → report
│
├── data/
│   └── patterns_extended.json  ← 208 patterns, 15 categories
│
├── node_scraper/
│   ├── index.js                ← CLI entry (paste/github-web/gist modes)
│   ├── paste_scanner.js        ← Pastebin, Ubuntu Paste, GitHub Gists
│   └── github_web.js           ← GitHub code search web scraping
│
└── tests/                      ← 111 tests, all passing
```

**Data flow:**
```
CLI
 │
 ▼
AutoCronfig.run(target, mode)
 │
 ├──[FAST]──────► RepoScanner (concurrent, 8-16 workers)
 │                     │
 ├──[DEEP]──────► DeepScanner (commits + PRs + issues + gists)
 │                     │
 ├──[GLOBAL]────► GlobalScanner (GitHub code search API)
 │                     │
 └──[NODE]──────► node_scraper (axios + cheerio, paste sites)
                       │
                       ▼
                 RawFindings
                       │
                       ▼
                 Verifier (concurrent HTTP checks)
                       │
                       ▼
                 Memory (SQLite — save, learn, deduplicate)
                       │
                       ▼
                 ScanReport → Export (JSON/CSV/HTML/MD) + Notify
```

---

## 📦 Installation

### Linux / macOS / WSL — One liner
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/install.sh)
```

### 📱 Android (Termux) — No Root Required
```bash
# In Termux (install from F-Droid, NOT Google Play)
bash <(curl -fsSL https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/install.sh)
```
→ Full Android guide: **[TERMUX.md](TERMUX.md)**

### Manual
```bash
# Clone
git clone https://github.com/ITzmeMod/Auto-Cronfig.git
cd Auto-Cronfig

# Python dependencies
pip install -r requirements.txt

# Node.js dependencies (optional — enables paste/web scraping)
npm install
```

### Requirements
| Component | Minimum | Notes |
|-----------|---------|-------|
| Python | 3.8+ | Core engine |
| Node.js | 16+ | Optional: paste/web scraping |
| GitHub Token | — | Strongly recommended (5000 req/hr vs 60) |

---

## 🎛️ Interactive Menu

No need to memorize commands. Just run:

```bash
python menu.py
```

You'll see the ASCII banner and a fully interactive menu:

```
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   █████╗ ██╗   ██╗████████╗██████╗       ██████╗ ███████╗    ║
  ║  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗     ██╔════╝██╔════╝    ║
  ║  ███████║██║   ██║   ██║   ██║   ██║     ██║     █████╗      ║
  ║  ██╔══██║██║   ██║   ██║   ██║   ██║     ██║     ██╔══╝      ║
  ║  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝     ╚██████╗██║         ║
  ║  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝       ╚═════╝╚═╝         ║
  ║                                                               ║
  ║  ▸ C R O N F I G  ·  GitHub Secret Scanner  ·  v3.0.0        ║
  ╚═══════════════════════════════════════════════════════════════╝

  ● Token set  │  Workers: 8  │  DB: ~/.auto-cronfig/memory.db

  Main Menu — use ↑↓ arrows and Enter to select:
  ❯  🔍  Scan         Scan a repo or user for secrets
     🔬  Deep Scan    Full audit: commits, PRs, issues, gists
     🌐  Global Scan  Search across all of public GitHub
     🏦  Vault        View & export leaked keys vault
     📊  Stats        Intelligence dashboard & insights
     ⚙   Settings     Configure token, workers, notifications
     ❓  Help         CLI reference & docs
     ℹ   About        Version & info
     ✖   Exit
```

**Navigate with `↑` `↓` arrow keys, press `Enter` to select.** No flags to memorize.

> Settings are saved to `~/.auto-cronfig/config.json` — set your GitHub token once and it's remembered.

---

## 🚀 Usage

### Quick Start
```bash
# Launch interactive menu (recommended)
python menu.py

# Or use CLI directly:
# Scan a repository
python scanner.py --repo owner/repo

# Scan all public repos of a user
python scanner.py --user username

# Scan with authentication (recommended)
python scanner.py --user username --token ghp_yourtoken

# Or set env var once
export GITHUB_TOKEN=ghp_yourtoken
python scanner.py --user username
```

### All Options
```
usage: scanner.py [-h] [--repo OWNER/REPO | --user USERNAME | --global QUERY | --stats]
                  [--token TOKEN] [--no-verify] [--output FILE]
                  [--workers N] [--max-results N] [--db-path PATH]
                  [--mode {fast,standard,deep,global}]

Positional targets:
  --repo OWNER/REPO       Scan a specific repository (URL or owner/repo)
  --user USERNAME         Scan all public repos for a user
  --global QUERY          Global GitHub code search for a term
  --stats                 Show intelligence dashboard and lifetime stats

Scan options:
  --mode MODE             fast | standard (default) | deep | global
  --token TOKEN           GitHub personal access token
  --no-verify             Skip live key verification (faster)
  --workers N             Concurrent workers (default: 8, max: 32)
  --max-results N         Max results for global search (default: 100)

Output options:
  --output FILE           Export report (.json | .csv | .html | .md)
  --db-path PATH          Custom SQLite database path
```

---

## 🎯 Scan Modes

| Mode | Speed | What It Scans | Best For |
|------|-------|---------------|----------|
| `fast` | ⚡⚡⚡ | Repository files only, no verification | Quick sweep, large repos |
| `standard` | ⚡⚡ | Files + live key verification | Default, everyday use |
| `deep` | ⚡ | Files + commits + PRs + issues + gists + releases | Full forensic audit |
| `global` | ⏱ | GitHub code search across all public repos | Finding leaks across all of GitHub |

### Examples

```bash
# Fast scan — no verification, maximum speed
python scanner.py --repo owner/repo --mode fast --workers 16

# Deep scan — every historical commit, PR, and issue
python scanner.py --repo owner/repo --mode deep

# Global scan for AWS keys across GitHub
python scanner.py --global "AKIA" --max-results 50

# Export HTML report
python scanner.py --repo owner/repo --output report.html

# Export CSV for spreadsheet analysis
python scanner.py --user target --output findings.csv

# Show intelligence dashboard
python scanner.py --stats
```

---

## 🔑 Key Verification

Auto-Cronfig makes **real HTTP requests** to verify whether discovered secrets are still active.

| Service | Endpoint | LIVE condition |
|---------|----------|----------------|
| **GitHub** | `api.github.com/user` | HTTP 200 + login in response |
| **Stripe** | `api.stripe.com/v1/balance` | HTTP 200 |
| **Slack** | `slack.com/api/auth.test` | `ok: true` |
| **Discord** | `discord.com/api/v10/users/@me` | HTTP 200 |
| **Telegram** | `api.telegram.org/bot{token}/getMe` | `ok: true` |
| **OpenAI** | `api.openai.com/v1/models` | HTTP 200 |
| **Anthropic** | `api.anthropic.com/v1/models` | HTTP 200 |
| **HuggingFace** | `huggingface.co/api/whoami` | HTTP 200 |
| **Replicate** | `api.replicate.com/v1/account` | HTTP 200 |
| **SendGrid** | `api.sendgrid.com/v3/user/account` | HTTP 200 |
| **Mailgun** | `api.mailgun.net/v3/domains` | HTTP 200 |
| **Cloudflare** | `api.cloudflare.com/client/v4/user` | HTTP 200 |
| **DigitalOcean** | `api.digitalocean.com/v2/account` | HTTP 200 |
| **Twitter/X** | `api.twitter.com/2/users/me` | HTTP 200 |
| **Google API** | Maps geocode probe | No `REQUEST_DENIED` |

Skip verification with `--no-verify` for faster scans.

---

## 🧠 Memory & Learning System

Auto-Cronfig stores all scan data in a local SQLite database (`~/.auto-cronfig/memory.db`).

### What It Tracks

| Table | Purpose |
|-------|---------|
| `findings` | Every match with verification status |
| `pattern_stats` | Fire rate, live/dead ratio per pattern |
| `file_stats` | Which extensions yield the most secrets |
| `leaked_keys` | SHA256-hashed vault — never stores raw values |
| `scan_history` | Cumulative totals over all time |
| `watchlist` | Repos/users to auto-rescan |
| `false_positives` | Hashed values to skip forever |
| `knowledge` | Auto-generated insights refreshed each scan |

### How It Gets Smarter

1. **Extension prioritization** — After scanning, files from historically productive extensions (`.env`, `.py`, `.yml`) are sorted to the front of future scans
2. **Pattern ranking** — Patterns with high live-verification rates get priority attention in reports
3. **False positive memory** — Mark any finding once; the engine skips that value forever across all future scans
4. **Insights generation** — After each scan, natural-language insights are synthesized:

```
Example insights after several scans:
  • .env files have the highest finding rate at 62%
  • GitHub Personal Access Token has 34% live verification rate
  • Most common secret type: Generic API Key (147 found)
  • Lifetime: 24 scans, 18,421 files scanned, 312 findings, 19 live keys confirmed
  • OpenAI keys found most frequently in Python files (71%)
```

---

## 🔔 Notifications

Set environment variables to enable notifications:

```bash
# Telegram
export AC_TELEGRAM_TOKEN=your_bot_token
export AC_TELEGRAM_CHAT_ID=your_chat_id

# Discord
export AC_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...

# Slack
export AC_SLACK_WEBHOOK=https://hooks.slack.com/services/...

# Custom webhook
export AC_WEBHOOK_URL=https://your-server.com/webhook

# Severity threshold (default: HIGH — alerts on HIGH and CRITICAL)
export AC_NOTIFY_SEVERITY=CRITICAL   # only CRITICAL
export AC_NOTIFY_SEVERITY=HIGH       # HIGH + CRITICAL
export AC_NOTIFY_SEVERITY=MEDIUM     # MEDIUM + above
```

Then run with `--notify`:
```bash
python scanner.py --user target --notify
```

---

## 🗂️ Detected Secret Categories

<details>
<summary><b>View all 15 categories (208+ patterns)</b></summary>

| Category | Examples |
|----------|---------|
| ☁️ **Cloud — AWS** | Access Key ID (`AKIA…`), Secret Access Key, Session Token, S3 URLs, Lambda ARN |
| ☁️ **Cloud — Google** | API Key (`AIza…`), OAuth Client Secret (`GOCSPX-`), Service Account JSON, OAuth Token (`ya29.`) |
| ☁️ **Cloud — Azure** | Subscription Key, Storage Connection String, Client Secret, SQL connection |
| ☁️ **Cloud — Other** | DigitalOcean (`dop_v1_`), Cloudflare, Vercel, Netlify, Railway, Fly.io, Linode |
| 💳 **Payment** | Stripe (`sk_live_`, `sk_test_`), PayPal, Square, Shopify, Razorpay, Mollie, Paddle |
| 📞 **Communication** | Twilio, Vonage/Nexmo, MessageBird, Plivo, Sinch, Infobip |
| 📧 **Email** | SendGrid (`SG.`), Mailgun (`key-`), Postmark, Mailchimp, Brevo, Mandrill |
| 💬 **Messaging** | Slack (all token types), Discord, Microsoft Teams, Mattermost, Zulip |
| 🔧 **VCS / CI-CD** | GitHub (`ghp_`, `gho_`, `ghs_`, `github_pat_`), GitLab (`glpat-`), Bitbucket, CircleCI, Jenkins |
| 📢 **Social / Marketing** | Twitter/X, Facebook, Instagram, LinkedIn, TikTok, Reddit, Pinterest |
| 📈 **Monitoring** | Datadog, New Relic, Sentry DSN, Rollbar, PagerDuty, Grafana, Splunk |
| 🗄️ **Database** | PostgreSQL, MySQL, MongoDB (`mongodb+srv://`), Redis, Elasticsearch, Supabase, InfluxDB |
| 🔐 **Security / Crypto** | RSA/EC/OpenSSH private keys, PGP blocks, JWT tokens, Ethereum keys, Bitcoin WIF |
| 🤖 **AI / ML** | OpenAI (`sk-`), Anthropic (`sk-ant-`), HuggingFace (`hf_`), Replicate (`r8_`), Groq (`gsk_`), Cohere |
| 🌐 **CDN / DNS / Misc** | Cloudflare, Algolia, Mapbox, Sentry, Intercom, HubSpot, Salesforce, Zendesk |

</details>

---

## 📱 Android / Termux

Run Auto-Cronfig on **any Android device** — no root required.

```bash
# Step 1: Install Termux from F-Droid (NOT Google Play)
# Step 2: Open Termux and run:

pkg update -y && pkg install -y python git nodejs
bash <(curl -fsSL https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/install.sh)
```

Performance tips for Android:
```bash
# Mid-range phone (4 cores)
python scanner.py --user target --token ghp_xxx --workers 4

# High-end phone (8+ cores)
python scanner.py --user target --token ghp_xxx --workers 8

# Slow connection
python scanner.py --user target --no-verify
```

→ Full Android guide including cron scheduling and push notifications: **[TERMUX.md](TERMUX.md)**

---

## 🧪 Tests

```bash
# Run full test suite
python -m pytest tests/ -v

# With coverage
pip install pytest-cov
python -m pytest tests/ --cov=engine --cov-report=term-missing
```

```
111 passed in 3.68s ✅
```

Test coverage includes:
- Pattern registry (all 208+ patterns compile and match correctly)
- Live verifier (mocked HTTP — GitHub, Stripe, Slack, Telegram, etc.)
- SQLite memory engine (in-memory DB)
- Exporter (JSON, CSV, HTML, Markdown output)
- Notifier (Telegram, Discord, Slack — mocked)
- Deep scanner (commits, PRs, issues, gists — mocked GitHub API)

---

## ⚠️ Disclaimer

Auto-Cronfig is built for **ethical security research, responsible disclosure, and educational purposes**. Only scan repositories you own or have explicit authorization to test. The authors are not responsible for any misuse.

If you discover live credentials in a public repository:
1. **Do not use the credentials**
2. Contact the repository owner immediately
3. Consider reporting via GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)

---

## 🤝 Contributing

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** your branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'feat: add amazing feature'`
4. **Push**: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Adding New Patterns

Edit `data/patterns_extended.json` and follow the existing schema:
```json
{
  "id": "my-service-api-key",
  "name": "My Service API Key",
  "regex": "msk_[0-9a-zA-Z]{32}",
  "severity": "HIGH",
  "category": "misc",
  "verifier": null,
  "tags": ["my-service"],
  "description": "My Service API key",
  "references": ["https://docs.myservice.com/auth"]
}
```

Severity levels: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW`

---

## 📄 License

[MIT License](LICENSE) — free to use, modify, and distribute.

---

<div align="center">

Built with ❤️ by [ITzmeMod](https://github.com/ITzmeMod)

⭐ **Star this repo if it helped you find a leak!** ⭐

</div>
