<div align="center">

<img src="https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/.github/assets/banner.svg" alt="Auto-Cronfig" width="100%">

# Auto-Cronfig

**Enterprise-grade GitHub secret scanner — finds leaked API keys, credentials & secrets in public repos. Targets new AI-scaffolded projects (Lovable · Bolt · Replit · Base44 · v0 · Cursor) where live-key rate is highest.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Node.js 16+](https://img.shields.io/badge/Node.js-16%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/Tests-111%20passing-brightgreen?logo=pytest)](tests/)
[![Bandit](https://img.shields.io/badge/Security-0%20findings-brightgreen)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-Termux%20Ready-3DDC84?logo=android&logoColor=white)](TERMUX.md)

[Install](#-installation) · [Menu](#-interactive-menu) · [CLI](#-cli-reference) · [Scan Modes](#-scan-modes) · [VibeScan](#-vibescan--highest-hit-rate) · [Global Scan](#-global-scan) · [Vault](#-results-vault) · [Notifications](#-notifications) · [Android](#-android--termux) · [Contributing](#-contributing)

</div>

---

## ✨ Features at a Glance

| Feature | Detail |
|---------|--------|
| 🎯 **VibeScan** | Targets new AI-scaffolded repos (Lovable, Bolt, Replit, Base44, v0, Cursor…) — **highest live-key hit rate** |
| 🌐 **Global Scan** | 200+ queries across all of public GitHub — AWS, GCP, AI keys, Stripe, private keys, .env leaks |
| 🔬 **Deep Scan** | Commit history (catches deleted secrets!), PRs, issues, gists, wiki, releases |
| 🔑 **Live Verification** | HTTP checks against 15 services — LIVE / DEAD / UNKNOWN result per key |
| 🧠 **Self-learning memory** | SQLite brain — learns which patterns/extensions are riskiest, gets smarter every scan |
| 🏦 **Results Vault** | Every finding stored to DB incrementally — Ctrl+C still saves results |
| 📊 **Multi-format export** | JSON · CSV · HTML (dark theme) · Markdown |
| 🔔 **Notifications** | Telegram · Discord · Slack · custom webhook |
| 🎛️ **Interactive menu** | Arrow-key TUI — no flags to memorize, works on Termux |
| 📱 **Android ready** | Termux, no root required |
| 🔒 **Secure** | 0 Bandit findings · 0 npm vulnerabilities |

---

## 📐 Architecture

```
Auto-Cronfig v3
│
├── menu.py                     ← Interactive TUI (arrow-key navigation)
├── scanner.py                  ← CLI entry point (7 subcommands)
│
├── engine/
│   ├── patterns.py             ← 208 patterns loaded from JSON + fallback
│   ├── verifier.py             ← Live HTTP verification (15 services)
│   ├── memory.py               ← SQLite brain: vault, watchlist, insights
│   ├── scanner.py              ← Concurrent GitHub file scanner
│   ├── deep_scanner.py         ← Commits · PRs · issues · gists · releases
│   ├── global_scanner.py       ← 200+ queries, GitHub-wide, fast parallel
│   ├── vibe_scanner.py         ← 103 queries, NEW AI-scaffolded repos only
│   ├── notifier.py             ← Telegram / Discord / Slack / webhook
│   ├── exporter.py             ← JSON / CSV / HTML / Markdown export
│   └── orchestrator.py         ← Pipeline: scan → verify → save → report
│
├── data/
│   └── patterns_extended.json  ← 208 patterns, 15 categories
│
├── node_scraper/               ← axios + cheerio (paste sites, web search)
│   ├── index.js
│   ├── paste_scanner.js
│   └── github_web.js
│
└── tests/                      ← 111 tests, all passing
```

---

## 📦 Installation

### One-liner (Linux · macOS · WSL · Termux Android)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/install.sh)
```

This installs Python, Node.js, all deps, runs tests, and creates the `auto-cronfig` shortcut.

### Manual

```bash
git clone https://github.com/ITzmeMod/Auto-Cronfig.git
cd Auto-Cronfig
pip install -r requirements.txt
npm install                      # optional — enables paste/web scraping
python menu.py                   # launch interactive menu
```

### Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| Python | 3.8+ | Core engine |
| Node.js | 16+ | Optional — paste/web scraping |
| GitHub Token | — | **Strongly recommended** (5000 req/hr vs 60) |

---

## 🎛️ Interactive Menu

The easiest way to use Auto-Cronfig — no flags to memorize:

```bash
python menu.py
# or after install:
auto-cronfig
```

```
  ╔══════════════════════════════════════════════════════╗
  ║  Auto-Cronfig  v3.0.0  ·  GitHub Secret Scanner      ║
  ╚══════════════════════════════════════════════════════╝

  ● token set  │  8w  │  db: ~/.auto-cronfig/memory.db

  Main Menu  ↑↓ navigate · Enter select · Ctrl+C exit
  ▸  🔍  Scan         Scan repo / user
     🔬  Deep Scan    Commits · PRs · Issues · Gists
     🌐  Global       Search all of GitHub
     🎯  Vibe Scan    New AI repos (Lovable·Bolt·Replit)
     🏦  Vault        Leaked keys vault
     📊  Stats        Intelligence dashboard
     ⚙   Settings     Token · workers · alerts
     ❓  Help         Quick reference
     ℹ   About        Version & info
     ✖   Exit
```

**Settings are saved** to `~/.auto-cronfig/config.json` — set your token once, it's remembered.

---

## 📋 CLI Reference

### Subcommands (recommended)

```bash
python scanner.py <subcommand> [options]
```

| Subcommand | Purpose |
|------------|---------|
| `scan` | Scan a repo or all repos of a user |
| `deep` | Full forensic scan (commits, PRs, issues, gists) |
| `global` | Search all of public GitHub (200+ queries) |
| `vibe` | Target new AI-scaffolded repos specifically |
| `watch` | Add targets to watchlist / run watchlist |
| `vault` | View and export the leaked keys vault |
| `stats` | Show intelligence dashboard & lifetime stats |

### scan

```bash
# Scan a single repository
python scanner.py scan --repo owner/repo --token ghp_xxx

# Scan all public repos of a user
python scanner.py scan --user username --token ghp_xxx

# Fast scan (no key verification)
python scanner.py scan --repo owner/repo --mode fast --no-verify

# Deep scan
python scanner.py scan --repo owner/repo --mode deep --token ghp_xxx

# Export report
python scanner.py scan --repo owner/repo --output report.html
python scanner.py scan --user username   --output findings.csv
```

### deep

```bash
# Full forensic audit — commits + PRs + issues + gists
python scanner.py deep --repo owner/repo --token ghp_xxx

# Control depth
python scanner.py deep --repo owner/repo --max-commits 1000 --max-prs 200
```

### global

```bash
# Run all 200+ built-in queries (recommended)
python scanner.py global --token ghp_xxx

# Target a specific secret type
python scanner.py global --query "OPENAI_API_KEY filename:.env" --token ghp_xxx

# Fast mode (parallel batches)
python scanner.py global --token ghp_xxx --mode fast

# Continuous — re-runs every hour
python scanner.py global --auto --interval 3600 --token ghp_xxx --output live.json

# Save report
python scanner.py global --token ghp_xxx --output global-scan.html
```

### vibe ⭐ (highest hit rate)

```bash
# Scan all vibe platforms (103 queries)
python scanner.py vibe --token ghp_xxx

# Target one platform
python scanner.py vibe --platform lovable   --token ghp_xxx
python scanner.py vibe --platform bolt      --token ghp_xxx
python scanner.py vibe --platform replit    --token ghp_xxx
python scanner.py vibe --platform base44    --token ghp_xxx
python scanner.py vibe --platform v0        --token ghp_xxx
python scanner.py vibe --platform cursor    --token ghp_xxx
python scanner.py vibe --platform windsurf  --token ghp_xxx
python scanner.py vibe --platform claude    --token ghp_xxx

# Only repos pushed in last 24 hours
python scanner.py vibe --days 1 --token ghp_xxx

# Repo-discovery mode (search repos → scan files)
python scanner.py vibe --repos --days 3 --token ghp_xxx

# Continuous scan every 30 minutes
python scanner.py vibe --continuous --interval 1800 --token ghp_xxx --output vibe.json

# Export results
python scanner.py vibe --token ghp_xxx --output vibe-report.html
```

### watch

```bash
# Add a repo to watchlist
python scanner.py watch --add owner/repo --token ghp_xxx

# Add a user to watchlist
python scanner.py watch --add username --token ghp_xxx

# Show watchlist
python scanner.py watch --list

# Scan everything on watchlist
python scanner.py watch --run --token ghp_xxx
```

### vault

```bash
# View vault (all stored findings)
python scanner.py vault

# Show only verified LIVE keys
python scanner.py vault --live-only

# Export vault
python scanner.py vault --export vault.json
python scanner.py vault --export vault.csv

# Filter by pattern type
python scanner.py vault --pattern "GitHub Personal Access Token"
```

### stats

```bash
# Show intelligence dashboard
python scanner.py stats

# Full breakdown
python scanner.py stats --full

# Export as HTML
python scanner.py stats --export stats.html
```

### Common flags (all subcommands)

```
--token TOKEN          GitHub personal access token
                       (or set env: export GITHUB_TOKEN=ghp_xxx)
--output FILE          Save report (.json | .csv | .html | .md)
--workers N            Concurrent workers (default 8, mobile: 4)
--no-verify            Skip live key verification (faster)
--mode fast|standard|deep|global|vibe
--db-path PATH         Custom SQLite database path
```

---

## 🎯 Scan Modes

| Mode | Speed | Coverage | Best For |
|------|-------|----------|----------|
| `fast` | ⚡⚡⚡ | Files only, no verification | Quick sweep |
| `standard` | ⚡⚡ | Files + live key checks | Everyday use |
| `deep` | ⚡ | Files + commits + PRs + issues + gists | Full forensic audit |
| `global` | ⏱ | 200+ queries, all of GitHub | Wide net across everything |
| `vibe` | ⚡⚡ | New AI repos < 90 days | **Highest live-key hit rate** |

---

## 🎯 VibeScan — Highest Hit Rate

New AI-scaffolded repos from tools like Lovable, Bolt.new, Replit, Base44, v0, and Cursor have dramatically higher rates of live leaked secrets. Developers paste real API keys into AI prompts, the AI scaffolds `.env` files, and the code gets pushed to GitHub without security review.

VibeScan targets repos pushed in the last 7–90 days with 103 specialised queries.

**Supported platforms:**

| Platform | What it targets |
|----------|----------------|
| 💜 Lovable | `lovable-tagger` repos with Supabase + OpenAI/Stripe keys |
| ⚡ Bolt.new | `stackblitz` / `webcontainer` scaffolded repos |
| 🔵 Replit | `replit.nix` repos with DB/API keys |
| 🟡 Base44 | `base44.com` app repos |
| 🔺 v0 | Vercel v0 generated Next.js repos |
| 🟢 Cursor | `.cursorrules` repos |
| 🌊 Windsurf | `.windsurfrules` repos |
| 🤖 Claude | Anthropic scaffold repos |
| + | Copilot, Devin, GPT-Engineer, Vercel AI SDK, Supabase/Firebase/Expo scaffolds |

High-value patterns specifically targeted: `sk-proj-` (new OpenAI), `SUPABASE_SERVICE_ROLE_KEY`, `CLERK_SECRET_KEY`, `PINECONE_API_KEY`, `RESEND_API_KEY`, `UPSTASH_REDIS_REST_TOKEN`, `NEXTAUTH_SECRET`, Prisma `DATABASE_URL`.

---

## 🌐 Global Scan

198 search queries organised into 9 categories — runs in parallel batches with a live progress bar.

| Category | Examples |
|----------|---------|
| AWS | AKIA…, aws_secret_access_key, AWS_ACCESS_KEY_ID |
| GCP | AIzaSy…, GOCSPX-, service_account JSON |
| AI | OPENAI_API_KEY, sk-ant-api, hf_, gsk_, r8_ |
| Stripe | sk_live_, sk_test_, whsec_ |
| GitHub | ghp_, gho_, github_pat_, GITHUB_TOKEN |
| Chat | xoxb- (Slack), DISCORD_TOKEN, TELEGRAM_BOT_TOKEN |
| Databases | mongodb+srv://, postgres://, DATABASE_URL, REDIS_URL |
| Private Keys | RSA, OpenSSH, EC, PGP |
| .env leaks | API_KEY=, SECRET_KEY=, PASSWORD=, CLIENT_SECRET= |

---

## 🔑 Live Key Verification

Auto-Cronfig makes real HTTP requests to check if found secrets are still active.

| Service | Endpoint | LIVE signal |
|---------|----------|-------------|
| GitHub | `api.github.com/user` | HTTP 200 + login |
| Stripe | `api.stripe.com/v1/balance` | HTTP 200 |
| Slack | `slack.com/api/auth.test` | `ok: true` |
| Discord | `discord.com/api/v10/users/@me` | HTTP 200 |
| Telegram | `api.telegram.org/bot{t}/getMe` | `ok: true` |
| OpenAI | `api.openai.com/v1/models` | HTTP 200 |
| Anthropic | `api.anthropic.com/v1/models` | HTTP 200 |
| HuggingFace | `huggingface.co/api/whoami` | HTTP 200 |
| Replicate | `api.replicate.com/v1/account` | HTTP 200 |
| SendGrid | `api.sendgrid.com/v3/user/account` | HTTP 200 |
| Mailgun | `api.mailgun.net/v3/domains` | HTTP 200 |
| Cloudflare | `api.cloudflare.com/client/v4/user` | HTTP 200 |
| DigitalOcean | `api.digitalocean.com/v2/account` | HTTP 200 |
| Twitter/X | `api.twitter.com/2/users/me` | HTTP 200 |
| Google API | Maps geocode probe | No REQUEST_DENIED |

Results: `LIVE 🚨` · `DEAD ✅` · `UNKNOWN ⚠️` · `ERROR 🔴`

Use `--no-verify` to skip verification for faster scans.

---

## 🏦 Results Vault

Every finding is saved to `~/.auto-cronfig/memory.db` **incrementally** — even if you stop the scan early with Ctrl+C, results are preserved.

```bash
# View all stored findings
python scanner.py vault

# Only verified LIVE keys
python scanner.py vault --live-only

# Export to JSON
python scanner.py vault --export vault.json

# Export to CSV
python scanner.py vault --export vault.csv
```

Raw key values are **never stored** — only SHA-256 hashes and masked previews (`ghp_abc****xyz`).

---

## 🧠 Intelligence Dashboard

The engine learns from every scan and generates insights:

```bash
python scanner.py stats --full
```

```
Lifetime stats:
  Scans run      : 24
  Files scanned  : 18,421
  Total findings : 312
  Live keys      : 19

Top patterns by live rate:
  GitHub PAT (Classic)         87% live
  OpenAI API Key               71% live
  Stripe Live Key              64% live

Riskiest extensions (scanned first):
  .env → 62% finding rate
  .py  → 28% finding rate
  .yml → 19% finding rate

Recent insights:
  • OpenAI keys found most in Lovable repos (71%)
  • Supabase service role keys have 43% live rate
  • .env.local files yield 3× more findings than .env
```

---

## 🔔 Notifications

Set environment variables and pass `--notify`:

```bash
export AC_TELEGRAM_TOKEN=your_bot_token
export AC_TELEGRAM_CHAT_ID=your_chat_id
export AC_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
export AC_SLACK_WEBHOOK=https://hooks.slack.com/services/...
export AC_NOTIFY_SEVERITY=HIGH    # alert on HIGH + CRITICAL (default)

python scanner.py vibe --token ghp_xxx --notify
```

Or configure in the interactive menu: `⚙ Settings → 📱 Telegram / 💬 Discord / 💼 Slack`

---

## 📊 Export Formats

```bash
# HTML — dark-themed, sortable table, self-contained
python scanner.py vibe --output report.html

# JSON — full data, machine-readable
python scanner.py global --output findings.json

# CSV — open in Excel/Sheets
python scanner.py scan --user username --output results.csv

# Markdown — paste into GitHub issues
python scanner.py scan --repo owner/repo --output report.md
```

---

## 📱 Android / Termux

One command in Termux (install from [F-Droid](https://f-droid.org/), not Play Store):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/install.sh)
```

Then:
```bash
auto-cronfig         # interactive menu
# or
python scanner.py vibe --token ghp_xxx --workers 4
```

**Performance tips for Android:**

| Phone | Recommended |
|-------|-------------|
| Mid-range (4 cores) | `--workers 4` |
| High-end (8+ cores) | `--workers 8` |
| Slow data | `--no-verify --workers 2` |
| Always | `--token ghp_xxx` |

→ Full guide with cron scheduling and push notifications: **[TERMUX.md](TERMUX.md)**

---

## 🧪 Tests

```bash
# Run all tests
python -m pytest tests/ -v

# With coverage
pip install pytest-cov
python -m pytest tests/ --cov=engine --cov-report=term-missing
```

```
111 passed in 3.18s ✅
```

Test coverage:
- `test_patterns.py` — 208 patterns compile & match correctly
- `test_verifier.py` — GitHub, Stripe, Slack, Telegram (mocked HTTP)
- `test_memory.py` — SQLite vault, watchlist, insights (in-memory DB)
- `test_exporter.py` — JSON, CSV, HTML, Markdown output
- `test_notifier.py` — Telegram, Discord, Slack (mocked)
- `test_deep_scanner.py` — commits, PRs, issues, gists (mocked GitHub API)

---

## 🔒 Security

Auto-Cronfig has **0 Bandit security findings** and **0 npm vulnerabilities**.

See [SECURITY.md](SECURITY.md) for:
- SQL injection prevention (allowlist-validated column names)
- Subprocess safety (fixed args, no shell=True, mode allowlist)
- Vault design (SHA-256 hashed — raw values never stored)
- Responsible disclosure policy

---

## 🗂️ Detected Secret Types (208 patterns, 15 categories)

<details>
<summary><b>Click to expand all categories</b></summary>

| Category | Patterns |
|----------|---------|
| ☁️ Cloud — AWS | Access Key, Secret Key, Session Token, S3 URLs, Lambda ARN |
| ☁️ Cloud — GCP | API Key (AIza…), OAuth Secret, Service Account JSON, Firebase |
| ☁️ Cloud — Azure | Subscription Key, Storage Connection, Client Secret, SQL conn |
| ☁️ Cloud — Other | DigitalOcean, Cloudflare, Vercel, Netlify, Railway, Fly.io, Linode |
| 💳 Payment | Stripe (sk_live_, sk_test_, whsec_), PayPal, Square, Shopify, Razorpay |
| 📞 Communication | Twilio, Vonage, MessageBird, Plivo |
| 📧 Email | SendGrid, Mailgun, Postmark, Mailchimp, Brevo, Mandrill |
| 💬 Messaging | Slack (xoxb-, xoxp-, xapp-), Discord, Teams, Mattermost, Zulip |
| 🔧 VCS / CI-CD | GitHub (ghp_, gho_, ghs_, github_pat_), GitLab (glpat-), CircleCI |
| 📢 Social | Twitter/X, Facebook, Instagram, LinkedIn, TikTok, Reddit |
| 📈 Monitoring | Datadog, New Relic, Sentry DSN, Rollbar, PagerDuty, Grafana |
| 🗄️ Database | PostgreSQL, MySQL, MongoDB (mongodb+srv://), Redis, Supabase, InfluxDB |
| 🔐 Crypto | RSA/EC/OpenSSH/PGP private keys, JWT tokens, Ethereum keys |
| 🤖 AI / ML | OpenAI (sk-, sk-proj-), Anthropic, HuggingFace (hf_), Replicate (r8_), Groq |
| 🌐 CDN / Misc | Cloudflare, Algolia, Mapbox, Intercom, HubSpot, Salesforce, Zendesk |

</details>

---

## 🤝 Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feat/my-feature`
3. Commit: `git commit -m 'feat: add my feature'`
4. Push: `git push origin feat/my-feature`
5. Open a Pull Request

### Adding new patterns

Edit `data/patterns_extended.json`:

```json
{
  "id": "my-service-key",
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

Severities: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW`

### Adding new vibe platform queries

Edit `engine/vibe_scanner.py` → `VIBE_SCAN_QUERIES` list.

---

## ⚠️ Disclaimer

For **authorized security research and responsible disclosure only**. Only scan repos you own or have explicit permission to test. If you discover live credentials:

1. **Do not use them**
2. Notify the repository owner immediately
3. Consider [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)

---

## 📄 License

[MIT License](LICENSE) — free to use, modify, and distribute.

---

<div align="center">

Built with ❤️ by [ITzmeMod](https://github.com/ITzmeMod)

⭐ **Star this repo if it helped you find a leak!** ⭐

</div>
