# 🔍 Auto-Cronfig — GitHub Secret & Vulnerability Scanner

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Open Source](https://img.shields.io/badge/open-source-brightgreen.svg)](https://github.com/ITzmeMod/Auto-Cronfig)

> **Auto-Cronfig** is a free, open-source GitHub scanning tool that automatically detects leaked API keys, secrets, credentials, and common security vulnerabilities in public GitHub repositories.

---

## 🚀 Features

- 🔑 **API Key Detection** — AWS, GCP, Stripe, Twilio, Slack, Discord, GitHub tokens & more
- 🔐 **Secret Leaks** — Passwords, private keys, JWT tokens, OAuth tokens
- 🛡️ **Vulnerability Patterns** — SQL injection hints, hardcoded creds, `.env` file exposure
- 📊 **Beautiful Reports** — Color-coded CLI output + optional JSON/HTML report export
- ⚡ **Fast & Lightweight** — No heavy dependencies, runs anywhere Python runs
- 🔄 **Cron-Ready** — Schedule scans to run automatically
- 🌐 **Multi-Repo Scan** — Scan a single repo, a user's all repos, or a list from file
- 💾 **Findings Export** — Save results to JSON for further processing

---

## 📦 Installation

```bash
git clone https://github.com/ITzmeMod/Auto-Cronfig.git
cd Auto-Cronfig
pip install -r requirements.txt
```

---

## 🛠️ Usage

### Scan a single repository
```bash
python scanner.py --repo https://github.com/owner/repo
```

### Scan all repos of a GitHub user
```bash
python scanner.py --user someusername
```

### Scan with a GitHub token (higher rate limits)
```bash
python scanner.py --user someusername --token ghp_yourtoken
```

### Export report to JSON
```bash
python scanner.py --repo https://github.com/owner/repo --output report.json
```

### Run on a schedule (cron)
```bash
# Edit crontab: crontab -e
# Run every day at 9 AM
0 9 * * * cd /path/to/Auto-Cronfig && python scanner.py --user target --output daily-report.json
```

---

## 📋 What It Detects

| Category | Examples |
|----------|---------|
| **AWS** | Access keys, secret keys, session tokens |
| **Google** | API keys, service account JSON |
| **Stripe** | Live & test secret keys |
| **Twilio** | Auth tokens, account SIDs |
| **Slack** | Bot tokens, webhook URLs |
| **Discord** | Bot tokens, webhook URLs |
| **GitHub** | Personal access tokens |
| **Generic** | Passwords in code, private keys, `.env` files |
| **Database** | Connection strings with credentials |
| **JWT** | Raw JWT tokens |

---

## ⚠️ Disclaimer

This tool is for **educational and ethical security research only**. Only scan repositories you own or have explicit permission to scan. The author is not responsible for misuse.

---

## 📄 License

MIT License — free to use, modify, and distribute. See [LICENSE](LICENSE).

---

## 🤝 Contributing

PRs welcome! Open an issue first for major changes.

1. Fork the repo
2. Create your branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -m 'Add my feature'`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request
