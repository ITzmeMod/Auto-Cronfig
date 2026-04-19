# 📱 Auto-Cronfig on Android (Termux)

Run Auto-Cronfig natively on **any Android device** — rooted or non-rooted — using [Termux](https://termux.dev).

---

## 📲 Step 1 — Install Termux

> ⚠️ **Use F-Droid version, NOT Google Play** (Play version is outdated)

1. Install [F-Droid](https://f-droid.org/)
2. Search for **Termux** and install it
3. Open Termux

---

## ⚙️ Step 2 — Setup Python & Dependencies

Copy-paste this into Termux (one block):

```bash
# Update packages
pkg update -y && pkg upgrade -y

# Install Python and git
pkg install -y python git

# Upgrade pip
pip install --upgrade pip

# Install Auto-Cronfig dependencies
pip install requests colorama tqdm
```

---

## 📥 Step 3 — Clone Auto-Cronfig

```bash
# Clone the repo
git clone https://github.com/ITzmeMod/Auto-Cronfig.git
cd Auto-Cronfig
```

---

## 🚀 Step 4 — Run It

```bash
# Scan a specific repo
python scanner.py --repo owner/repo

# Scan all public repos of a user
python scanner.py --user someusername

# Scan with your GitHub token (higher rate limits — recommended)
python scanner.py --user someusername --token ghp_yourtoken

# Global scan for leaked AWS keys across GitHub
python scanner.py --global AKIA --token ghp_yourtoken

# Save report to a file
python scanner.py --user someusername --output report.json

# View what the engine has learned over time
python scanner.py --stats

# Skip key verification (faster scan)
python scanner.py --user someusername --no-verify
```

---

## ⚡ Performance Tips for Android

| Flag | Recommended | Why |
|------|------------|-----|
| `--workers 4` | Mid-range phones | Avoids memory pressure |
| `--workers 8` | High-end phones (8+ cores) | Max throughput |
| `--no-verify` | Slow connections | Skip HTTP key checks |
| `--token ghp_xxx` | Always | 5000 req/hr vs 60 without |

Example for a mid-range phone:
```bash
python scanner.py --user target --token ghp_xxx --workers 4
```

---

## 🔄 Auto-Update (Stay Current)

```bash
cd Auto-Cronfig
git pull
```

---

## 📅 Schedule Scans with Termux (Cron)

Install the Termux cron package:

```bash
pkg install -y termux-services cronie
sv-enable crond
crond
```

Add a daily scan at 9 AM:

```bash
crontab -e
# Add this line:
0 9 * * * cd ~/Auto-Cronfig && python scanner.py --user TARGET --token YOUR_TOKEN --output ~/scan-$(date +\%Y\%m\%d).json
```

---

## 🔔 Push Notifications (Optional)

Get notified when live keys are found — using Termux:API:

```bash
# Install Termux:API app from F-Droid
# Then install the package:
pkg install -y termux-api

# Modify your cron to notify:
0 9 * * * cd ~/Auto-Cronfig && RESULT=$(python scanner.py --user TARGET --token YOUR_TOKEN --no-verify 2>&1 | grep "LIVE"); [ -n "$RESULT" ] && termux-notification --title "🔑 LIVE KEY FOUND" --content "$RESULT"
```

---

## 🗄️ Where Data Is Stored

Auto-Cronfig's memory (SQLite database) is stored at:

```
~/.auto-cronfig/memory.db
```

On Termux this is:
```
/data/data/com.termux/files/home/.auto-cronfig/memory.db
```

You can copy this file to backup your scan history and learned insights.

---

## ❓ Troubleshooting

| Problem | Fix |
|---------|-----|
| `pkg: command not found` | You're not in Termux — open the Termux app |
| `pip: command not found` | Run `pkg install python` first |
| `ModuleNotFoundError` | Run `pip install requests colorama tqdm` |
| `Permission denied` | You don't need root — Termux runs in user space |
| Slow scan on mobile | Use `--workers 4 --no-verify` |
| Rate limited by GitHub | Add `--token ghp_xxx` (get one at github.com/settings/tokens) |

---

## 🤖 No Root Required

Auto-Cronfig runs entirely in **Termux user space**. No root, no special permissions needed. Works on:

- ✅ Stock Android (non-rooted)
- ✅ Rooted Android (Magisk/KernelSU)
- ✅ Android 7.0+
- ✅ All brands (Samsung, Xiaomi, OnePlus, Pixel, etc.)
- ✅ Android tablets
- ✅ Chromebooks with Android support
