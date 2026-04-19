# 📱 Auto-Cronfig on Android (Termux)

Run Auto-Cronfig natively on **any Android device** — rooted or non-rooted — with a full interactive menu. No commands to memorize.

---

## 📋 Table of Contents

1. [Install Termux](#-step-1--install-termux)
2. [One-liner setup](#-step-2--one-liner-setup)
3. [Manual setup](#-step-3--manual-setup-alternative)
4. [Launch the menu](#-step-4--launch-the-interactive-menu)
5. [Set your GitHub token](#-step-5--set-your-github-token)
6. [Run scans](#-step-6--running-scans)
7. [Performance tips](#-performance-tips)
8. [Schedule automatic scans](#-schedule-automatic-scans-cron)
9. [Push notifications](#-push-notifications)
10. [Backup & data](#-where-data-is-stored)
11. [Troubleshooting](#-troubleshooting)

---

## 📲 Step 1 — Install Termux

> ⚠️ **Use the F-Droid version — NOT the Google Play version** (Play Store version is outdated and will fail)

1. Download **[F-Droid](https://f-droid.org/)** on your Android device
2. Open F-Droid → search **Termux** → install it
3. (Optional but recommended) Also install **Termux:API** from F-Droid for push notifications
4. Open the **Termux** app

---

## ⚡ Step 2 — One-liner Setup

Copy and paste this single command into Termux:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/install.sh)
```

This will:
- Install Python, Node.js, and git
- Clone the repo to `~/Auto-Cronfig`
- Install all Python and Node.js dependencies
- Run the test suite to verify everything works
- Create a shortcut so you can run `auto-cronfig` from anywhere

---

## 🛠️ Step 3 — Manual Setup (Alternative)

If you prefer step-by-step:

```bash
# 1. Update Termux packages
pkg update -y && pkg upgrade -y

# 2. Install required system packages
pkg install -y python git nodejs curl

# 3. Upgrade pip
pip install --upgrade pip

# 4. Clone Auto-Cronfig
git clone https://github.com/ITzmeMod/Auto-Cronfig.git
cd Auto-Cronfig

# 5. Install Python dependencies (includes the interactive menu)
pip install -r requirements.txt

# 6. Install Node.js dependencies (enables paste/web scraping)
npm install

# 7. Verify everything works
python -m pytest tests/ -q
```

Expected output at the end: `111 passed` ✅

---

## 🚀 Step 4 — Launch the Interactive Menu

```bash
cd ~/Auto-Cronfig
python menu.py
```

You'll see the full ASCII banner and an interactive menu — **no commands to memorize**:

```
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   █████╗ ██╗   ██╗████████╗██████╗       ██████╗ ███████╗   ║
  ║  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗     ██╔════╝██╔════╝   ║
  ║  ███████║██║   ██║   ██║   ██║   ██║     ██║     █████╗     ║
  ║  ██╔══██║██║   ██║   ██║   ██║   ██║     ██║     ██╔══╝     ║
  ║  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝     ╚██████╗██║        ║
  ║  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝       ╚═════╝╚═╝        ║
  ║                                                               ║
  ║  ▸ C R O N F I G  ·  GitHub Secret Scanner  ·  v3.0.0        ║
  ╚═══════════════════════════════════════════════════════════════╝

  ● Token set  │  Workers: 8  │  DB: ~/.auto-cronfig/memory.db

  Main Menu — use ↑↓ arrows and Enter to select:
  ▸  🔍  Scan         Scan a repo or user for secrets
     🔬  Deep Scan    Full audit: commits, PRs, issues, gists
     🌐  Global Scan  Search across all of public GitHub
     🏦  Vault        View & export leaked keys vault
     📊  Stats        Intelligence dashboard & insights
     ⚙   Settings     Configure token, workers, notifications
     ❓  Help         CLI reference & docs
     ℹ   About        Version & info
     ✖   Exit
```

**Navigate with `↑` `↓` arrow keys. Press `Enter` to select.**

---

## 🔑 Step 5 — Set Your GitHub Token

A GitHub token gives you **5000 API requests/hour** instead of 60 (unauthenticated). Strongly recommended.

**Get a token:**
1. Go to https://github.com/settings/tokens
2. Click **"Generate new token (classic)"**
3. Give it a name like `auto-cronfig`
4. Check the **`repo`** scope (read-only is enough)
5. Click **Generate token** — copy it

**Set it in the menu:**
1. Run `python menu.py`
2. Select **⚙ Settings**
3. Select **🔑 GitHub Token**
4. Paste your token (`ghp_...`)
5. Select **💾 Save & return**

Token is saved to `~/.auto-cronfig/config.json` — you only need to do this once.

**Or set via environment variable (session only):**
```bash
export GITHUB_TOKEN=ghp_yourtoken
python menu.py
```

---

## 🔍 Step 6 — Running Scans

### Via interactive menu (recommended)

```bash
python menu.py
```

Then choose your scan type from the menu. Each option walks you through:
- Target (repo URL or username)
- Scan mode (Fast / Standard / Deep)
- Output format (HTML / JSON / CSV / terminal)

---

### Via command line (advanced users)

```bash
cd ~/Auto-Cronfig

# ── Interactive menu (easiest) ──────────────────────────
python menu.py

# ── Scan a repo or user ─────────────────────────────────
python scanner.py scan --repo owner/repo --token ghp_xxx
python scanner.py scan --user username   --token ghp_xxx

# ── Deep scan (commits + PRs + issues + gists) ──────────
python scanner.py deep --repo owner/repo --token ghp_xxx

# ── Global scan — all of public GitHub ──────────────────
# All 200+ built-in queries (recommended)
python scanner.py global --token ghp_xxx

# Target a specific secret type
python scanner.py global --query "OPENAI_API_KEY filename:.env" --token ghp_xxx

# ── VibeScan — NEW AI-scaffolded repos (highest hit rate) ──
# Scan all vibe platforms (Lovable, Bolt, Replit, Base44…)
python scanner.py vibe --token ghp_xxx

# Target one platform
python scanner.py vibe --platform lovable --token ghp_xxx
python scanner.py vibe --platform replit  --token ghp_xxx
python scanner.py vibe --platform bolt    --token ghp_xxx

# Only repos pushed in last 24h
python scanner.py vibe --days 1 --token ghp_xxx

# Continuous vibe scan (re-runs every 30 min)
python scanner.py vibe --continuous --interval 1800 --token ghp_xxx --output live.json

# ── Save reports ─────────────────────────────────────────
python scanner.py scan --repo owner/repo --output report.html
python scanner.py vibe --token ghp_xxx   --output vibe.json
python scanner.py scan --user username   --output report.csv

# ── Other ────────────────────────────────────────────────
# View intelligence dashboard & lifetime stats
python scanner.py stats

# Fast scan (skip key verification)
python scanner.py scan --user username --mode fast --no-verify
```

---

## ⚡ Performance Tips

| Setting | Mid-range phone | High-end phone | Slow connection |
|---------|----------------|----------------|----------------|
| `--workers` | `4` | `8` | `2` |
| `--no-verify` | Optional | Optional | ✅ Recommended |
| `--token` | ✅ Always set | ✅ Always set | ✅ Always set |
| `--mode` | `standard` | `deep` | `fast` |

**Best command for mid-range Android:**
```bash
python scanner.py --user target --token ghp_xxx --workers 4
```

**Best command for high-end Android (8+ cores):**
```bash
python scanner.py --user target --token ghp_xxx --workers 8 --mode deep
```

**On very slow mobile data:**
```bash
python scanner.py --user target --token ghp_xxx --no-verify --workers 2
```

---

## 📅 Schedule Automatic Scans (Cron)

Scan automatically every day without touching your phone.

```bash
# Install cron support
pkg install -y termux-services cronie
sv-enable crond
crond
```

```bash
# Open crontab editor
crontab -e
```

Add one of these lines (press `i` to insert, `Esc` then `:wq` to save in nano/vi):

```bash
# Daily scan at 9 AM — save HTML report
0 9 * * * cd ~/Auto-Cronfig && python scanner.py vibe --token YOUR_TOKEN --output ~/vibe-$(date +\%Y\%m\%d).json

# Every 6 hours — fast scan
0 */6 * * * cd ~/Auto-Cronfig && python scanner.py vibe --token YOUR_TOKEN --mode fast --output ~/vibe-latest.json

# Weekly deep scan on Sunday at midnight
0 0 * * 0 cd ~/Auto-Cronfig && python scanner.py global --token YOUR_TOKEN --output ~/global-$(date +\%Y\%m\%d).html
```

---

## 🔔 Push Notifications

Get a notification on your phone when a live key is found.

**Setup:**
```bash
# Install Termux:API app from F-Droid first, then:
pkg install -y termux-api
```

**Add to crontab:**
```bash
# Scan and notify if LIVE keys found
0 9 * * * cd ~/Auto-Cronfig && \
  RESULT=$(python scanner.py --user YOUR_USERNAME --token YOUR_TOKEN --no-verify 2>&1 | grep "LIVE") && \
  [ -n "$RESULT" ] && \
  termux-notification \
    --title "🔑 Auto-Cronfig: Live Key Found!" \
    --content "$RESULT" \
    --priority high
```

**Using Telegram notifications (built-in):**
1. Run `python menu.py`
2. Go to **⚙ Settings → 📱 Telegram notifications**
3. Enter your bot token and chat ID
4. Run any scan — you'll get a Telegram message when CRITICAL/HIGH findings are found

---

## 🔄 Update Auto-Cronfig

```bash
cd ~/Auto-Cronfig
git pull
pip install -r requirements.txt
npm install
```

Or re-run the one-liner installer — it updates automatically if already installed:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ITzmeMod/Auto-Cronfig/main/install.sh)
```

---

## 🗄️ Where Data Is Stored

| Item | Location |
|------|----------|
| SQLite memory database | `~/.auto-cronfig/memory.db` |
| Saved config (token etc.) | `~/.auto-cronfig/config.json` |
| Repo files | `~/Auto-Cronfig/` |
| Scan reports | wherever you run the command from |

**On Termux, `~` resolves to:**
```
/data/data/com.termux/files/home/
```

**Backup your memory database:**
```bash
cp ~/.auto-cronfig/memory.db ~/storage/downloads/auto-cronfig-backup.db
```
> Run `termux-setup-storage` first if `~/storage` doesn't exist.

---

## ❓ Troubleshooting

| Problem | Fix |
|---------|-----|
| `pkg: command not found` | You're not in Termux — open the Termux app |
| `pip: command not found` | Run `pkg install python` first |
| `python: command not found` | Run `pkg install python` |
| `ModuleNotFoundError: questionary` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: colorama` | Run `pip install colorama` |
| `git: command not found` | Run `pkg install git` |
| `node: command not found` | Run `pkg install nodejs` |
| Menu arrows don't work | Make sure you're in Termux, not a basic shell |
| `Permission denied` | No root needed — Termux runs as user |
| Slow scan on mobile | Use `--workers 4 --no-verify` |
| Rate limited (GitHub 403) | Add `--token ghp_xxx` |
| `curl: command not found` | Run `pkg install curl` |
| Storage access denied | Run `termux-setup-storage` |

---

## 🤖 Compatibility

| Device Type | Supported | Notes |
|-------------|-----------|-------|
| Stock Android (non-rooted) | ✅ | Full support |
| Rooted Android (Magisk/KernelSU) | ✅ | Full support |
| Android 7.0 – 15 | ✅ | All versions |
| Samsung (One UI) | ✅ | |
| Xiaomi (MIUI/HyperOS) | ✅ | |
| OnePlus (OxygenOS) | ✅ | |
| Google Pixel | ✅ | |
| Android tablets | ✅ | |
| Chromebook (Android apps) | ✅ | |
| iOS (a-Shell) | ⚠️ | Limited — no cron, no notifications |

---

## 💡 Quick Reference Card

Save this for easy access:

```
════════════════════════════════════════
  Auto-Cronfig — Android Quick Reference
════════════════════════════════════════

  LAUNCH MENU
  cd ~/Auto-Cronfig && python menu.py

  QUICK SCANS (CLI)
  python scanner.py scan --repo owner/repo
  python scanner.py scan --user username
  python scanner.py global --token ghp_xxx
  python scanner.py vibe --token ghp_xxx
  python scanner.py vibe --platform lovable
  python scanner.py vibe --days 1
  python scanner.py stats

  COMMANDS
  scan   --repo/--user   Scan repo or user
  deep   --repo          Full history scan
  global                 200+ queries GitHub-wide
  vibe   --platform X    New AI repos (best hit rate)
  stats                  Dashboard & insights

  COMMON FLAGS
  --token ghp_xxx        GitHub token (required)
  --workers 4            Thread count (mobile: 4)
  --mode fast            No verification, fastest
  --mode deep            Full history scan
  --days 1               Last 24h repos (vibe)
  --output report.html   Save HTML report
  --no-verify            Skip live key checks
  --continuous           Loop forever (vibe/global)

  UPDATE
  cd ~/Auto-Cronfig && git pull

  GET TOKEN
  github.com/settings/tokens → repo scope

════════════════════════════════════════
```
