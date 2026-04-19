#!/usr/bin/env python3
"""
Auto-Cronfig — Interactive TUI Menu
Run: python menu.py
"""

import os
import sys
import time
import json
import shutil
import subprocess
from pathlib import Path

# ── Dependency check ─────────────────────────────────────────────────────────
_missing = []
try:
    import questionary
    from questionary import Style
except ImportError:
    _missing.append("questionary")
try:
    from colorama import Fore, Back, Style as CStyle, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    _missing.append("colorama")

if _missing:
    print(f"\n  Missing packages: {', '.join(_missing)}")
    print("  Run: pip install -r requirements.txt\n")
    sys.exit(1)

# ── Colours & style ───────────────────────────────────────────────────────────
C = Fore
R = CStyle.RESET_ALL
B = CStyle.BRIGHT

MENU_STYLE = Style([
    ("qmark",        "fg:#58a6ff bold"),
    ("question",     "fg:#e6edf3 bold"),
    ("answer",       "fg:#58a6ff bold"),
    ("pointer",      "fg:#a371f7 bold"),
    ("highlighted",  "fg:#e6edf3 bg:#1f2937 bold"),
    ("selected",     "fg:#3fb950"),
    ("separator",    "fg:#3d444d"),
    ("instruction",  "fg:#8b949e"),
    ("text",         "fg:#8b949e"),
    ("disabled",     "fg:#3d444d italic"),
])

CONFIG_FILE = Path.home() / ".auto-cronfig" / "config.json"

# ── Helpers ───────────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {"token": "", "workers": 8, "notify_severity": "HIGH",
            "telegram_token": "", "telegram_chat_id": "",
            "discord_webhook": "", "slack_webhook": ""}


def save_config(cfg: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def mask(s: str) -> str:
    if not s:
        return C.LIGHTBLACK_EX + "(not set)" + R
    return C.GREEN + s[:6] + "****" + s[-4:] + R


def run_scanner(*args):
    """Hand off to scanner.py with given args, then pause."""
    cmd = [sys.executable, str(Path(__file__).parent / "scanner.py"), *args]
    print()
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}  ⚠  Scan interrupted.{R}")
    input(f"\n  {C.LIGHTBLACK_EX}Press Enter to return to menu…{R}")


def ask(prompt, default="", password=False, validate=None):
    try:
        if password:
            return questionary.password(prompt, style=MENU_STYLE).ask() or default
        return questionary.text(prompt, default=default,
                                validate=validate, style=MENU_STYLE).ask() or default
    except KeyboardInterrupt:
        return default


def confirm(prompt, default=True) -> bool:
    try:
        return questionary.confirm(prompt, default=default, style=MENU_STYLE).ask()
    except KeyboardInterrupt:
        return False


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = f"""
{C.BLUE}{B}  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   {C.CYAN}█████{C.BLUE}╗ {C.CYAN}██╗   ██╗{C.BLUE}████████╗{C.CYAN}██████{C.BLUE}╗       {C.MAGENTA}██████{C.BLUE}╗ {C.MAGENTA}███████{C.BLUE}╗    ║
  ║  {C.CYAN}██╔══██{C.BLUE}╗{C.CYAN}██║   ██║{C.BLUE}╚══{C.CYAN}██{C.BLUE}╔══╝{C.CYAN}██╔═══██{C.BLUE}╗     {C.MAGENTA}██╔════╝{C.MAGENTA}██╔════╝    ║
  ║  {C.CYAN}███████║{C.CYAN}██║   ██║{C.BLUE}   {C.CYAN}██{C.BLUE}║   {C.CYAN}██║   ██║{C.BLUE}     {C.MAGENTA}██║     {C.MAGENTA}█████╗      ║
  ║  {C.CYAN}██╔══██║{C.CYAN}██║   ██║{C.BLUE}   {C.CYAN}██{C.BLUE}║   {C.CYAN}██║   ██║{C.BLUE}     {C.MAGENTA}██║     {C.MAGENTA}██╔══╝      ║
  ║  {C.CYAN}██║  ██║{C.CYAN}╚██████╔╝{C.BLUE}   {C.CYAN}██{C.BLUE}║   {C.CYAN}╚██████╔╝{C.BLUE}     {C.MAGENTA}╚██████╗{C.MAGENTA}██║         ║
  ║  {C.LIGHTBLACK_EX}╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝       ╚═════╝╚═╝{C.BLUE}         ║
  ║                                                               ║
  ║  {C.CYAN}▸ {C.WHITE}C R O N F I G{C.BLUE}  ·  {C.MAGENTA}GitHub Secret Scanner{C.BLUE}  ·  {C.YELLOW}v3.0.0{C.BLUE}          ║
  ║  {C.LIGHTBLACK_EX}Enterprise-grade · Self-learning · Android-ready{C.BLUE}               ║
  ╚═══════════════════════════════════════════════════════════════╝{R}
"""

def print_banner():
    clear()
    print(BANNER)


def print_status_bar(cfg: dict):
    token_status = f"{C.GREEN}●{R} Token set" if cfg.get("token") else f"{C.RED}●{R} No token"
    workers = cfg.get("workers", 8)
    print(f"  {C.LIGHTBLACK_EX}{'─'*63}{R}")
    print(f"  {token_status}  {C.LIGHTBLACK_EX}│{R}  {C.CYAN}Workers:{R} {workers}  {C.LIGHTBLACK_EX}│{R}  "
          f"{C.CYAN}DB:{R} {C.LIGHTBLACK_EX}~/.auto-cronfig/memory.db{R}")
    print(f"  {C.LIGHTBLACK_EX}{'─'*63}{R}\n")


# ── Sub-menus ─────────────────────────────────────────────────────────────────

def menu_scan(cfg: dict):
    """Single-repo or user scan."""
    print_banner()
    print(f"  {C.CYAN}{B}● SCAN TARGET{R}\n")

    choice = questionary.select(
        "What do you want to scan?",
        choices=[
            questionary.Choice("  🗂   Single repository  (owner/repo or URL)", "repo"),
            questionary.Choice("  👤  All repos for a GitHub user",             "user"),
            questionary.Choice("  ◀   Back to main menu",                       "back"),
        ],
        style=MENU_STYLE,
    ).ask()

    if not choice or choice == "back":
        return

    target = ""
    if choice == "repo":
        target = ask("  Enter repo  (e.g. owner/repo or full URL): ")
        if not target:
            return
    elif choice == "user":
        target = ask("  Enter GitHub username: ")
        if not target:
            return

    mode = questionary.select(
        "Scan mode:",
        choices=[
            questionary.Choice("  ⚡⚡⚡  Fast      — files only, no key verification",   "fast"),
            questionary.Choice("  ⚡⚡    Standard  — files + live key verification",      "standard"),
            questionary.Choice("  🔬    Deep      — files + commits + PRs + issues + gists", "deep"),
        ],
        style=MENU_STYLE,
    ).ask()
    if not mode:
        return

    verify = mode != "fast"
    workers = str(cfg.get("workers", 8))

    output_choice = questionary.select(
        "Save report to file?",
        choices=[
            questionary.Choice("  📄  HTML report  (beautiful dark-theme)",   "html"),
            questionary.Choice("  📊  JSON report  (machine-readable)",        "json"),
            questionary.Choice("  📋  CSV report   (spreadsheet-friendly)",    "csv"),
            questionary.Choice("  📝  Markdown     (for GitHub issues/PRs)",   "md"),
            questionary.Choice("  ✗   No — terminal output only",              "none"),
        ],
        style=MENU_STYLE,
    ).ask()
    if output_choice is None:
        return

    args = []
    if choice == "repo":
        args += ["--repo", target]
    else:
        args += ["--user", target]

    args += ["--mode", mode, "--workers", workers]

    if cfg.get("token"):
        args += ["--token", cfg["token"]]
    if not verify:
        args += ["--no-verify"]
    if output_choice != "none":
        fname = f"report-{target.replace('/', '-')}.{output_choice}"
        args += ["--output", fname]
        print(f"\n  {C.CYAN}▸ Report will be saved to:{R} {fname}")

    print_banner()
    print(f"  {C.CYAN}{B}● STARTING SCAN{R}\n")
    run_scanner(*args)


def menu_deep_scan(cfg: dict):
    """Dedicated deep scan entry."""
    print_banner()
    print(f"  {C.MAGENTA}{B}● DEEP SCAN{R}\n")
    print(f"  {C.LIGHTBLACK_EX}Deep scan checks:{R}")
    print(f"  {C.LIGHTBLACK_EX}  · File contents (all branches){R}")
    print(f"  {C.LIGHTBLACK_EX}  · Full commit history (catches deleted secrets!){R}")
    print(f"  {C.LIGHTBLACK_EX}  · Pull request diffs & comments{R}")
    print(f"  {C.LIGHTBLACK_EX}  · Issues & issue comments{R}")
    print(f"  {C.LIGHTBLACK_EX}  · Gists by the repo owner{R}")
    print()

    target = ask("  Enter repo (owner/repo or URL): ")
    if not target:
        return

    max_commits = ask("  Max commits to scan (default 500): ", default="500")
    workers = str(cfg.get("workers", 8))

    output_choice = questionary.select(
        "Save report?",
        choices=[
            questionary.Choice("  📄  HTML", "html"),
            questionary.Choice("  📊  JSON", "json"),
            questionary.Choice("  ✗   Terminal only", "none"),
        ],
        style=MENU_STYLE,
    ).ask()
    if output_choice is None:
        return

    args = ["--repo", target, "--mode", "deep", "--workers", workers]
    if cfg.get("token"):
        args += ["--token", cfg["token"]]
    if output_choice != "none":
        fname = f"deep-{target.replace('/', '-')}.{output_choice}"
        args += ["--output", fname]

    print_banner()
    print(f"  {C.MAGENTA}{B}● DEEP SCANNING: {target}{R}\n")
    run_scanner(*args)


def menu_global_scan(cfg: dict):
    """Global GitHub code search."""
    print_banner()
    print(f"  {C.YELLOW}{B}● GLOBAL SCAN{R}\n")
    print(f"  {C.LIGHTBLACK_EX}Searches across ALL of public GitHub for leaked secrets.{R}")
    print(f"  {C.RED}⚠  Requires a GitHub token (rate limits apply).{R}\n")

    if not cfg.get("token"):
        print(f"  {C.RED}✗ No GitHub token configured. Please set one in Settings first.{R}")
        input(f"\n  {C.LIGHTBLACK_EX}Press Enter…{R}")
        return

    mode = questionary.select(
        "Global scan mode:",
        choices=[
            questionary.Choice("  🌐  Auto — run all 50+ built-in search queries", "auto"),
            questionary.Choice("  🔎  Custom — enter your own search term",         "custom"),
        ],
        style=MENU_STYLE,
    ).ask()
    if not mode:
        return

    query = None
    if mode == "custom":
        query = ask("  Search term (e.g. AKIA, sk_live_, ghp_): ")
        if not query:
            return

    max_results = ask("  Max results per query (default 30): ", default="30")

    output_choice = questionary.select(
        "Save report?",
        choices=[
            questionary.Choice("  📄  HTML",          "html"),
            questionary.Choice("  📊  JSON",          "json"),
            questionary.Choice("  ✗   Terminal only", "none"),
        ],
        style=MENU_STYLE,
    ).ask()
    if output_choice is None:
        return

    args = ["--token", cfg["token"], "--max-results", max_results]
    if mode == "auto":
        args += ["--global", "AKIA"]  # triggers built-in query list
    else:
        args += ["--global", query]

    if output_choice != "none":
        fname = f"global-scan.{output_choice}"
        args += ["--output", fname]

    print_banner()
    print(f"  {C.YELLOW}{B}● GLOBAL SCAN IN PROGRESS…{R}\n")
    run_scanner(*args)


def menu_vault(cfg: dict):
    """Leaked keys vault viewer."""
    print_banner()
    print(f"  {C.RED}{B}● LEAKED KEYS VAULT{R}\n")
    print(f"  {C.LIGHTBLACK_EX}All confirmed live/found keys from previous scans.{R}")
    print(f"  {C.LIGHTBLACK_EX}Raw values are never stored — SHA-256 hashed only.{R}\n")

    choice = questionary.select(
        "What do you want to do?",
        choices=[
            questionary.Choice("  👁   View vault in terminal",               "view"),
            questionary.Choice("  📊  Export vault to JSON",                 "export_json"),
            questionary.Choice("  📋  Export vault to CSV",                  "export_csv"),
            questionary.Choice("  ◀   Back",                                 "back"),
        ],
        style=MENU_STYLE,
    ).ask()

    if not choice or choice == "back":
        return

    if choice == "view":
        run_scanner("--stats")
    elif choice == "export_json":
        run_scanner("--stats", "--output", "vault-export.json")
    elif choice == "export_csv":
        run_scanner("--stats", "--output", "vault-export.csv")


def menu_stats(cfg: dict):
    """Intelligence dashboard."""
    print_banner()
    print(f"  {C.CYAN}{B}● INTELLIGENCE DASHBOARD{R}\n")
    print(f"  {C.LIGHTBLACK_EX}Shows what the engine has learned from all scans.{R}\n")
    run_scanner("--stats")


def menu_settings(cfg: dict) -> dict:
    """Settings editor."""
    while True:
        print_banner()
        print(f"  {C.YELLOW}{B}● SETTINGS{R}\n")
        print(f"  {C.LIGHTBLACK_EX}Current configuration:{R}\n")
        print(f"    {C.CYAN}GitHub Token     :{R}  {mask(cfg.get('token',''))}")
        print(f"    {C.CYAN}Workers          :{R}  {cfg.get('workers', 8)}")
        print(f"    {C.CYAN}Notify severity  :{R}  {cfg.get('notify_severity','HIGH')}")
        print(f"    {C.CYAN}Telegram token   :{R}  {mask(cfg.get('telegram_token',''))}")
        print(f"    {C.CYAN}Telegram chat ID :{R}  {mask(cfg.get('telegram_chat_id',''))}")
        print(f"    {C.CYAN}Discord webhook  :{R}  {mask(cfg.get('discord_webhook',''))}")
        print(f"    {C.CYAN}Slack webhook    :{R}  {mask(cfg.get('slack_webhook',''))}")
        print()

        choice = questionary.select(
            "What do you want to change?",
            choices=[
                questionary.Choice("  🔑  GitHub Token          (required for most features)", "token"),
                questionary.Choice("  ⚙   Workers               (parallel scan threads)",      "workers"),
                questionary.Choice("  🔔  Notification severity (CRITICAL/HIGH/MEDIUM/LOW)",   "severity"),
                questionary.Choice("  📱  Telegram notifications",                             "telegram"),
                questionary.Choice("  💬  Discord notifications",                              "discord"),
                questionary.Choice("  💼  Slack notifications",                                "slack"),
                questionary.Choice("  💾  Save & return",                                      "save"),
            ],
            style=MENU_STYLE,
        ).ask()

        if not choice or choice == "save":
            save_config(cfg)
            print(f"\n  {C.GREEN}✓ Settings saved to {CONFIG_FILE}{R}")
            time.sleep(1)
            break

        elif choice == "token":
            val = ask("  Paste your GitHub token (ghp_…): ", password=True)
            if val:
                cfg["token"] = val

        elif choice == "workers":
            val = ask("  Number of workers (1-32): ", default=str(cfg.get("workers", 8)))
            try:
                w = int(val)
                if 1 <= w <= 32:
                    cfg["workers"] = w
                else:
                    print(f"  {C.RED}Must be between 1 and 32{R}")
                    time.sleep(1)
            except ValueError:
                pass

        elif choice == "severity":
            val = questionary.select(
                "Alert on severity:",
                choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                style=MENU_STYLE,
            ).ask()
            if val:
                cfg["notify_severity"] = val

        elif choice == "telegram":
            cfg["telegram_token"] = ask("  Telegram bot token: ", password=True,
                                         default=cfg.get("telegram_token", ""))
            cfg["telegram_chat_id"] = ask("  Telegram chat ID: ",
                                           default=cfg.get("telegram_chat_id", ""))

        elif choice == "discord":
            cfg["discord_webhook"] = ask("  Discord webhook URL: ", password=True,
                                          default=cfg.get("discord_webhook", ""))

        elif choice == "slack":
            cfg["slack_webhook"] = ask("  Slack webhook URL: ", password=True,
                                        default=cfg.get("slack_webhook", ""))

    return cfg


def menu_help():
    print_banner()
    print(f"  {C.CYAN}{B}● HELP & QUICK REFERENCE{R}\n")
    rows = [
        ("Scan a repo",        "python scanner.py --repo owner/repo --mode standard"),
        ("Scan a user",        "python scanner.py --user username"),
        ("Deep scan",          "python scanner.py --repo owner/repo --mode deep"),
        ("Global scan",        "python scanner.py --global AKIA"),
        ("Export HTML",        "python scanner.py --repo owner/repo --output report.html"),
        ("Export CSV",         "python scanner.py --user target --output report.csv"),
        ("View stats",         "python scanner.py --stats"),
        ("Skip verification",  "python scanner.py --repo owner/repo --no-verify"),
        ("Set token via env",  "export GITHUB_TOKEN=ghp_yourtoken"),
        ("Android install",    "bash <(curl -fsSL .../install.sh)  # see TERMUX.md"),
    ]
    for label, cmd in rows:
        print(f"  {C.YELLOW}▸ {C.WHITE}{label:<22}{R}  {C.LIGHTBLACK_EX}{cmd}{R}")

    print(f"\n  {C.CYAN}Documentation:{R}  https://github.com/ITzmeMod/Auto-Cronfig")
    print(f"  {C.CYAN}Android guide:{R}  TERMUX.md\n")
    input(f"  {C.LIGHTBLACK_EX}Press Enter to return…{R}")


def menu_about():
    print_banner()
    print(f"  {C.CYAN}{B}● ABOUT AUTO-CRONFIG{R}\n")
    print(f"  {C.WHITE}Version   {C.LIGHTBLACK_EX}·{R}  v3.0.0")
    print(f"  {C.WHITE}Author    {C.LIGHTBLACK_EX}·{R}  ITzmeMod")
    print(f"  {C.WHITE}License   {C.LIGHTBLACK_EX}·{R}  MIT — free to use, modify, distribute")
    print(f"  {C.WHITE}Repo      {C.LIGHTBLACK_EX}·{R}  https://github.com/ITzmeMod/Auto-Cronfig")
    print(f"  {C.WHITE}Patterns  {C.LIGHTBLACK_EX}·{R}  208+ across 15 categories")
    print(f"  {C.WHITE}Tests     {C.LIGHTBLACK_EX}·{R}  111 passing")
    print()
    print(f"  {C.LIGHTBLACK_EX}Built with Python + Node.js (axios + cheerio){R}")
    print(f"  {C.LIGHTBLACK_EX}SQLite-powered self-improving intelligence engine{R}")
    print(f"  {C.LIGHTBLACK_EX}Runs on Linux · macOS · Windows WSL · Android (Termux){R}")
    print()
    input(f"  {C.LIGHTBLACK_EX}Press Enter to return…{R}")


# ── Main menu loop ────────────────────────────────────────────────────────────

def main():
    cfg = load_config()

    # Apply env token if set and not already in config
    env_token = os.environ.get("GITHUB_TOKEN", "")
    if env_token and not cfg.get("token"):
        cfg["token"] = env_token

    while True:
        print_banner()
        print_status_bar(cfg)

        choice = questionary.select(
            "Main Menu  — use ↑↓ arrows and Enter to select:",
            choices=[
                questionary.Choice("  🔍  Scan         Scan a repo or user for secrets",       "scan"),
                questionary.Choice("  🔬  Deep Scan    Full audit: commits, PRs, issues, gists","deep"),
                questionary.Choice("  🌐  Global Scan  Search across all of public GitHub",     "global"),
                questionary.Choice("  🏦  Vault        View & export leaked keys vault",        "vault"),
                questionary.Choice("  📊  Stats        Intelligence dashboard & insights",      "stats"),
                questionary.Choice("  ⚙   Settings     Configure token, workers, notifications","settings"),
                questionary.Choice("  ❓  Help         CLI reference & docs",                   "help"),
                questionary.Choice("  ℹ   About        Version & info",                         "about"),
                questionary.Choice("  ✖   Exit",                                                "exit"),
            ],
            style=MENU_STYLE,
        ).ask()

        if not choice or choice == "exit":
            print_banner()
            print(f"  {C.CYAN}Thanks for using Auto-Cronfig. Stay secure. 🔒{R}\n")
            break
        elif choice == "scan":
            menu_scan(cfg)
        elif choice == "deep":
            menu_deep_scan(cfg)
        elif choice == "global":
            menu_global_scan(cfg)
        elif choice == "vault":
            menu_vault(cfg)
        elif choice == "stats":
            menu_stats(cfg)
        elif choice == "settings":
            cfg = menu_settings(cfg)
        elif choice == "help":
            menu_help()
        elif choice == "about":
            menu_about()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}Goodbye.{R}\n")
        sys.exit(0)
