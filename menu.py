#!/usr/bin/env python3
"""
Auto-Cronfig — Interactive TUI Menu
Run: python menu.py
"""
import os
import sys
import time
import json
import logging
import subprocess  # nosec B404 — used with fixed args, shell=False
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Dependency check ──────────────────────────────────────────
_missing = []
try:
    import questionary
    from questionary import Style
except ImportError:
    _missing.append("questionary")
try:
    from colorama import Fore, Style as CStyle, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    _missing.append("colorama")

if _missing:
    print(f"\n  Missing: {', '.join(_missing)}")
    print("  Run: pip install -r requirements.txt\n")
    sys.exit(1)

# ── Aliases ───────────────────────────────────────────────────
C   = Fore
R   = CStyle.RESET_ALL
B   = CStyle.BRIGHT
DIM = CStyle.DIM

# ── Terminal width helper ─────────────────────────────────────
def tw() -> int:
    try:
        import shutil
        return max(40, shutil.get_terminal_size((60, 24)).columns)
    except Exception:
        return 60

# ── Questionary style ─────────────────────────────────────────
STYLE = Style([
    ("qmark",       "fg:#58a6ff bold"),
    ("question",    "fg:#e6edf3 bold"),
    ("answer",      "fg:#58a6ff bold"),
    ("pointer",     "fg:#a371f7 bold"),
    ("highlighted", "fg:#ffffff bg:#1f2937 bold"),
    ("selected",    "fg:#3fb950 bold"),
    ("separator",   "fg:#3d444d"),
    ("instruction", "fg:#8b949e"),
    ("text",        "fg:#8b949e"),
    ("disabled",    "fg:#3d444d italic"),
])

# ── Config ────────────────────────────────────────────────────
CONFIG_FILE = Path.home() / ".auto-cronfig" / "config.json"

_DEFAULTS: dict = {  # nosec B105 — empty strings are unset sentinels
    "token":           "",   # nosec B105
    "workers":         8,
    "notify_severity": "HIGH",
    "telegram_token":  "",   # nosec B105
    "telegram_chat_id":"",
    "discord_webhook": "",   # nosec B105
    "slack_webhook":   "",   # nosec B105
}

def load_cfg() -> dict:
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            return {**_DEFAULTS, **data}
        except Exception as exc:
            logger.warning("config load error: %s", exc)
    return dict(_DEFAULTS)

def save_cfg(cfg: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def mask(s: str) -> str:
    if not s:
        return C.LIGHTBLACK_EX + "not set" + R
    return C.GREEN + s[:4] + "••••" + s[-3:] + R

# ── Screen helpers ────────────────────────────────────────────
def clr():
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "cls"], shell=False)  # nosec B603 B607
    else:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

def rule(char="─", color=C.LIGHTBLACK_EX):
    w = min(tw(), 56)
    print(f"  {color}{char * w}{R}")

def hdr(title: str, color=C.CYAN):
    clr()
    _banner()
    rule()
    print(f"  {color}{B}{title}{R}")
    rule()
    print()

# ── Banner (auto-fits to terminal width) ─────────────────────
_WIDE_BANNER = [
    f"{C.BLUE}{B}  ╔{'═'*52}╗",
    f"  ║  {C.CYAN}   _         _        {C.YELLOW} ___  {C.MAGENTA}  __  {C.BLUE}             ║",
    f"  ║  {C.CYAN}  / \\  _   _| |_ ___  {C.YELLOW}/ __|{C.MAGENTA} /  \\ {C.BLUE}  n f i g    ║",
    f"  ║  {C.CYAN} / _ \\| | | | __/ _ \\ {C.YELLOW}| (__ {C.MAGENTA}| () |{C.BLUE}             ║",
    f"  ║  {C.CYAN}/_/ \\_\\_,_|_|\\__\\___/ {C.YELLOW}\\___|{C.MAGENTA} \\__/ {C.BLUE}             ║",
    f"  ║  {C.WHITE}{'─'*48}{C.BLUE}  ║",
    f"  ║  {C.WHITE}  GitHub Secret Scanner  {C.YELLOW}v3.0.0{C.LIGHTBLACK_EX}  MIT{C.BLUE}       ║",
    f"  ╚{'═'*52}╝{R}",
]

_NARROW_BANNER = [
    f"{C.CYAN}{B}  ╔{'═'*34}╗",
    f"  ║  {C.WHITE}  Auto-Cronfig  {C.YELLOW}v3.0.0{C.CYAN}        ║",
    f"  ║  {C.LIGHTBLACK_EX}  GitHub Secret Scanner{C.CYAN}        ║",
    f"  ╚{'═'*34}╝{R}",
]

def _banner():
    if tw() >= 58:
        for line in _WIDE_BANNER:
            print(line)
    else:
        for line in _NARROW_BANNER:
            print(line)
    print()

def _statusbar(cfg: dict):
    tok = f"{C.GREEN}● token{R}" if cfg.get("token") else f"{C.RED}● no token{R}"
    wkr = f"{C.CYAN}{cfg.get('workers',8)}w{R}"
    print(f"  {tok}  {C.LIGHTBLACK_EX}│{R}  {wkr}  {C.LIGHTBLACK_EX}│{R}  "
          f"{C.LIGHTBLACK_EX}db:~/.auto-cronfig/{R}")
    print()

# ── Run scanner subprocess ────────────────────────────────────
def run_scanner(*args):
    """Invoke scanner.py with given args. All args are pre-validated
    list elements — no user input reaches the shell (shell=False)."""
    sp = Path(__file__).parent / "scanner.py"
    if not sp.is_file():
        print(f"\n  {C.RED}✗ scanner.py not found{R}")
        return
    cmd = [sys.executable, str(sp), *args]  # nosec B603
    print()
    try:
        subprocess.run(cmd, shell=False)  # nosec B603
    except KeyboardInterrupt:
        print(f"\n  {C.YELLOW}⚠ interrupted{R}")
    input(f"\n  {C.LIGHTBLACK_EX}↵ Enter to return…{R}")

# ── Input helpers ─────────────────────────────────────────────
def ask(prompt, default="", password=False):
    try:
        if password:
            return questionary.password(f"  {prompt}", style=STYLE).ask() or default
        return questionary.text(f"  {prompt}", default=default,
                                style=STYLE).ask() or default
    except KeyboardInterrupt:
        return default

def choose(prompt, choices):
    try:
        return questionary.select(
            f"  {prompt}", choices=choices, style=STYLE,
        ).ask()
    except KeyboardInterrupt:
        return None

def ok(prompt="Continue?", default=True) -> bool:
    try:
        return questionary.confirm(f"  {prompt}",
                                   default=default, style=STYLE).ask()
    except KeyboardInterrupt:
        return False

# ── SCAN menu ─────────────────────────────────────────────────
def menu_scan(cfg: dict):
    hdr("🔍  SCAN", C.CYAN)

    target_type = choose("Target type:", [
        questionary.Choice("  📁  Single repository", "repo"),
        questionary.Choice("  👤  All repos of a user", "user"),
        questionary.Choice("  ◀   Back", "back"),
    ])
    if not target_type or target_type == "back":
        return

    if target_type == "repo":
        target = ask("Repo  (owner/repo or URL):")
    else:
        target = ask("GitHub username:")
    if not target:
        return

    mode = choose("Scan mode:", [
        questionary.Choice("  ⚡  Fast      — files only, no verify",       "fast"),
        questionary.Choice("  🔍  Standard  — files + key verify",          "standard"),
        questionary.Choice("  🔬  Deep      — files + commits + PRs + issues", "deep"),
    ])
    if not mode:
        return

    fmt = choose("Save report?", [
        questionary.Choice("  🌐  HTML  (dark theme)",   "html"),
        questionary.Choice("  📊  JSON  (machine read)", "json"),
        questionary.Choice("  📋  CSV   (spreadsheet)",  "csv"),
        questionary.Choice("  ✗   Terminal only",        "none"),
    ])
    if fmt is None:
        return

    args = (["--repo", target] if target_type == "repo"
            else ["--user", target])
    args += ["--mode", mode, "--workers", str(cfg.get("workers", 8))]
    if cfg.get("token"):
        args += ["--token", cfg["token"]]
    if mode == "fast":
        args += ["--no-verify"]
    if fmt != "none":
        safe_target = target.replace("/", "-").replace("\\", "-")[:40]
        fname = f"report-{safe_target}.{fmt}"
        args += ["--output", fname]
        print(f"\n  {C.CYAN}▸ Report → {fname}{R}")

    hdr(f"🔍  SCANNING: {target}", C.CYAN)
    run_scanner(*args)

# ── DEEP SCAN menu ────────────────────────────────────────────
def menu_deep(cfg: dict):
    hdr("🔬  DEEP SCAN", C.MAGENTA)
    print(f"  {C.LIGHTBLACK_EX}Scans: files · commits · PRs · issues · gists{R}\n")

    target = ask("Repo  (owner/repo or URL):")
    if not target:
        return

    fmt = choose("Save report?", [
        questionary.Choice("  🌐  HTML", "html"),
        questionary.Choice("  📊  JSON", "json"),
        questionary.Choice("  ✗   Terminal only", "none"),
    ])
    if fmt is None:
        return

    args = ["--repo", target, "--mode", "deep",
            "--workers", str(cfg.get("workers", 8))]
    if cfg.get("token"):
        args += ["--token", cfg["token"]]
    if fmt != "none":
        safe_target = target.replace("/", "-").replace("\\", "-")[:40]
        args += ["--output", f"deep-{safe_target}.{fmt}"]

    hdr(f"🔬  DEEP SCAN: {target}", C.MAGENTA)
    run_scanner(*args)

# ── GLOBAL SCAN menu ──────────────────────────────────────────
_GLOBAL_CATEGORIES = [
    questionary.Choice("  🌍  ALL  — every category (200+ queries)",      "ALL"),
    questionary.Choice("  ☁️   AWS keys  (AKIA, secret access key)",       "AWS"),
    questionary.Choice("  🔵  Google / GCP  (AIzaSy, service accounts)",  "GCP"),
    questionary.Choice("  🤖  AI keys  (OpenAI, Anthropic, HuggingFace)", "AI"),
    questionary.Choice("  💳  Stripe / Payment  (sk_live_, sk_test_)",    "STRIPE"),
    questionary.Choice("  🐙  GitHub tokens  (ghp_, gho_, github_pat_)",  "GITHUB"),
    questionary.Choice("  💬  Slack / Discord / Telegram",                "CHAT"),
    questionary.Choice("  🗄️   Databases  (postgres, mongo, redis)",       "DB"),
    questionary.Choice("  🔐  Private keys  (RSA, SSH, PGP)",             "KEYS"),
    questionary.Choice("  📄  .env file leaks  (any secret in .env)",     "ENV"),
    questionary.Choice("  🔎  Custom  — enter your own search term",      "CUSTOM"),
    questionary.Choice("  ◀   Back",                                      "back"),
]

_CATEGORY_QUERY_MAP = {
    "AWS":    ["AKIA language:python", "AKIA filename:.env",
               "aws_access_key_id filename:.env",
               "AWS_SECRET_ACCESS_KEY filename:.env",
               "AKIA language:javascript", "AKIA language:yaml"],
    "GCP":    ["AIzaSy language:javascript", "AIzaSy language:python",
               "AIzaSy filename:.env", "GOCSPX- language:python",
               "GOOGLE_API_KEY filename:.env", "FIREBASE_API_KEY filename:.env",
               "type service_account language:json"],
    "AI":     ["OPENAI_API_KEY filename:.env", "OPENAI_API_KEY language:python",
               "sk-ant-api language:python", "ANTHROPIC_API_KEY filename:.env",
               "hf_ language:python", "HUGGINGFACE_TOKEN filename:.env",
               "r8_ language:python", "gsk_ language:python",
               "GROQ_API_KEY filename:.env", "MISTRAL_API_KEY filename:.env"],
    "STRIPE": ["sk_live_ language:python", "sk_live_ language:javascript",
               "sk_live_ filename:.env", "sk_test_ filename:.env",
               "STRIPE_SECRET_KEY filename:.env",
               "STRIPE_SECRET_KEY language:python", "whsec_ filename:.env"],
    "GITHUB": ["ghp_ language:yaml", "ghp_ filename:.env",
               "github_pat_ language:yaml", "GITHUB_TOKEN filename:.env",
               "gho_ language:python", "glpat- language:yaml"],
    "CHAT":   ["xoxb- language:python", "xoxb- filename:.env",
               "SLACK_BOT_TOKEN filename:.env",
               "DISCORD_TOKEN filename:.env", "DISCORD_BOT_TOKEN filename:.env",
               "discord.com/api/webhooks language:javascript",
               "TELEGRAM_BOT_TOKEN filename:.env",
               "api.telegram.org/bot language:python"],
    "DB":     ["mongodb+srv:// language:javascript", "mongodb+srv:// filename:.env",
               "postgres:// language:python", "DATABASE_URL filename:.env",
               "MONGO_URI filename:.env", "REDIS_URL filename:.env",
               "SUPABASE_SERVICE_ROLE_KEY filename:.env"],
    "KEYS":   ["-----BEGIN RSA PRIVATE KEY-----",
               "-----BEGIN OPENSSH PRIVATE KEY-----",
               "-----BEGIN EC PRIVATE KEY-----",
               "-----BEGIN PRIVATE KEY-----",
               "-----BEGIN PGP PRIVATE KEY BLOCK-----"],
    "ENV":    ["API_KEY= filename:.env", "SECRET_KEY= filename:.env",
               "ACCESS_TOKEN= filename:.env", "PASSWORD= filename:.env",
               "DB_PASSWORD= filename:.env", "AUTH_TOKEN= filename:.env",
               "SECRET= filename:.env", "CLIENT_SECRET= filename:.env",
               "DB_PASSWORD filename:.env.production",
               "SECRET_KEY filename:.env.production"],
}

def menu_global(cfg: dict):
    hdr("🌐  GLOBAL SCAN", C.YELLOW)
    print(f"  {C.LIGHTBLACK_EX}Searches all of public GitHub for secrets.{R}")
    print(f"  {C.LIGHTBLACK_EX}200+ queries · every category covered.{R}\n")

    if not cfg.get("token"):
        print(f"  {C.RED}✗ No GitHub token set.{R}")
        print(f"  {C.LIGHTBLACK_EX}Go to Settings → GitHub Token first.{R}")
        input(f"\n  {C.LIGHTBLACK_EX}↵ Enter…{R}")
        return

    cat = choose("What to scan for:", _GLOBAL_CATEGORIES)
    if not cat or cat == "back":
        return

    custom_query = None
    if cat == "CUSTOM":
        custom_query = ask("Search term (e.g. sk_live_, AKIA, ghp_):")
        if not custom_query:
            return

    speed = choose("Speed:", [
        questionary.Choice("  ⚡  Fast   — parallel batches (recommended)", "fast"),
        questionary.Choice("  🐢  Safe   — fully sequential (lower API load)", "safe"),
    ])
    if not speed:
        return

    limit = ask("Max results per query:", default="20")

    fmt = choose("Save report?", [
        questionary.Choice("  🌐  HTML", "html"),
        questionary.Choice("  📊  JSON", "json"),
        questionary.Choice("  📋  CSV",  "csv"),
        questionary.Choice("  ✗   Terminal only", "none"),
    ])
    if fmt is None:
        return

    # Build query arg — use first query of category for --global flag;
    # for ALL or category, scanner runs full built-in list via orchestrator
    if cat == "CUSTOM":
        query_arg = custom_query
    elif cat == "ALL":
        query_arg = "__ALL__"   # sentinel — orchestrator runs full list
    else:
        # Use first query of the category as the entry point;
        # scanner --global with a category prefix triggers category queries
        query_arg = _CATEGORY_QUERY_MAP[cat][0]

    args = ["--global", query_arg,
            "--token", cfg["token"],
            "--max-results", limit]
    if speed == "fast":
        args += ["--mode", "fast"]
    if fmt != "none":
        args += ["--output", f"global-{cat.lower()}.{fmt}"]

    hdr(f"🌐  SCANNING: {cat}", C.YELLOW)
    print(f"  {C.LIGHTBLACK_EX}Queries running… Ctrl+C to stop early.{R}\n")
    run_scanner(*args)

# ── VAULT menu ────────────────────────────────────────────────
def menu_vault(cfg: dict):
    hdr("🏦  VAULT", C.RED)
    print(f"  {C.LIGHTBLACK_EX}Confirmed findings from all scans.{R}")
    print(f"  {C.LIGHTBLACK_EX}Raw values never stored (SHA-256 hashed).{R}\n")

    act = choose("Action:", [
        questionary.Choice("  👁   View in terminal",  "view"),
        questionary.Choice("  📊  Export → JSON",      "json"),
        questionary.Choice("  📋  Export → CSV",       "csv"),
        questionary.Choice("  ◀   Back",               "back"),
    ])
    if not act or act == "back":
        return
    if act == "view":
        run_scanner("--stats")
    else:
        run_scanner("--stats", "--output", f"vault.{act}")

# ── STATS menu ────────────────────────────────────────────────
def menu_stats(cfg: dict):
    hdr("📊  INTELLIGENCE DASHBOARD", C.CYAN)
    run_scanner("--stats")

# ── SETTINGS menu ────────────────────────────────────────────
def menu_settings(cfg: dict) -> dict:
    while True:
        hdr("⚙   SETTINGS", C.YELLOW)

        # Status table
        rows = [
            ("GitHub Token",    mask(cfg.get("token",""))),
            ("Workers",         f"{C.CYAN}{cfg.get('workers',8)}{R}"),
            ("Alert severity",  f"{C.CYAN}{cfg.get('notify_severity','HIGH')}{R}"),
            ("Telegram token",  mask(cfg.get("telegram_token",""))),
            ("Telegram chat",   mask(cfg.get("telegram_chat_id",""))),
            ("Discord webhook", mask(cfg.get("discord_webhook",""))),
            ("Slack webhook",   mask(cfg.get("slack_webhook",""))),
        ]
        for label, val in rows:
            print(f"  {C.LIGHTBLACK_EX}{label:<16}{R}  {val}")
        print()

        act = choose("Change:", [
            questionary.Choice("  🔑  GitHub Token",       "token"),
            questionary.Choice("  ⚙   Workers",            "workers"),
            questionary.Choice("  🔔  Alert severity",     "severity"),
            questionary.Choice("  📱  Telegram",           "telegram"),
            questionary.Choice("  💬  Discord",            "discord"),
            questionary.Choice("  💼  Slack",              "slack"),
            questionary.Choice("  💾  Save & return",      "save"),
        ])

        if not act or act == "save":
            save_cfg(cfg)
            print(f"\n  {C.GREEN}✓ Saved → {CONFIG_FILE}{R}")
            time.sleep(1)
            break

        elif act == "token":
            v = ask("GitHub token (ghp_…):", password=True)
            if v:
                cfg["token"] = v

        elif act == "workers":
            v = ask("Workers (1–32):", default=str(cfg.get("workers", 8)))
            try:
                n = int(v)
                if 1 <= n <= 32:
                    cfg["workers"] = n
                else:
                    print(f"  {C.RED}Must be 1–32{R}")
                    time.sleep(1)
            except ValueError:
                pass

        elif act == "severity":
            v = choose("Alert on severity:", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            if v:
                cfg["notify_severity"] = v

        elif act == "telegram":
            v = ask("Bot token:", password=True,
                    default=cfg.get("telegram_token", ""))
            if v:
                cfg["telegram_token"] = v
            v2 = ask("Chat ID:", default=cfg.get("telegram_chat_id", ""))
            if v2:
                cfg["telegram_chat_id"] = v2

        elif act == "discord":
            v = ask("Webhook URL:", password=True,
                    default=cfg.get("discord_webhook", ""))
            if v:
                cfg["discord_webhook"] = v

        elif act == "slack":
            v = ask("Webhook URL:", password=True,
                    default=cfg.get("slack_webhook", ""))
            if v:
                cfg["slack_webhook"] = v

    return cfg

# ── HELP ─────────────────────────────────────────────────────
def menu_help():
    hdr("❓  HELP", C.CYAN)
    cmds = [
        ("menu",     "python menu.py"),
        ("scan repo","scanner.py --repo owner/repo"),
        ("scan user","scanner.py --user username"),
        ("deep scan","scanner.py --repo x --mode deep"),
        ("global",   "scanner.py --global AKIA"),
        ("HTML out", "scanner.py --repo x --output r.html"),
        ("stats",    "scanner.py --stats"),
        ("fast mode","scanner.py --repo x --no-verify"),
        ("set token","export GITHUB_TOKEN=ghp_xxx"),
        ("update",   "cd Auto-Cronfig && git pull"),
    ]
    for label, cmd in cmds:
        print(f"  {C.YELLOW}▸ {C.WHITE}{label:<12}{R}  {C.LIGHTBLACK_EX}{cmd}{R}")
    print()
    print(f"  {C.CYAN}Docs:   {R}github.com/ITzmeMod/Auto-Cronfig")
    print(f"  {C.CYAN}Android:{R} see TERMUX.md")
    print()
    input(f"  {C.LIGHTBLACK_EX}↵ Enter to return…{R}")

# ── ABOUT ─────────────────────────────────────────────────────
def menu_about():
    hdr("ℹ   ABOUT", C.CYAN)
    info = [
        ("Version",   "v3.0.0"),
        ("Author",    "ITzmeMod"),
        ("License",   "MIT"),
        ("Patterns",  "208+ across 15 categories"),
        ("Tests",     "111 passing"),
        ("Engine",    "Python + Node.js (axios+cheerio)"),
        ("Memory",    "SQLite self-learning"),
        ("Platforms", "Linux · macOS · WSL · Android"),
    ]
    for k, v in info:
        print(f"  {C.LIGHTBLACK_EX}{k:<12}{R}  {C.WHITE}{v}{R}")
    print()
    print(f"  {C.CYAN}github.com/ITzmeMod/Auto-Cronfig{R}")
    print()
    input(f"  {C.LIGHTBLACK_EX}↵ Enter to return…{R}")

# ── MAIN MENU ─────────────────────────────────────────────────
def main():
    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    cfg = load_cfg()

    # Pick up token from env if not already saved
    env_tok = os.environ.get("GITHUB_TOKEN", "")
    if env_tok and not cfg.get("token"):
        cfg["token"] = env_tok

    while True:
        clr()
        _banner()
        _statusbar(cfg)

        choice = choose(
            "Main Menu  ↑↓ navigate · Enter select · Ctrl+C exit",
            [
                questionary.Choice("  🔍  Scan         Scan repo / user",       "scan"),
                questionary.Choice("  🔬  Deep Scan    Commits·PRs·Issues·Gists","deep"),
                questionary.Choice("  🌐  Global       Search all of GitHub",    "global"),
                questionary.Choice("  🏦  Vault        Leaked keys vault",       "vault"),
                questionary.Choice("  📊  Stats        Intelligence dashboard",  "stats"),
                questionary.Choice("  ⚙   Settings     Token · workers · alerts","settings"),
                questionary.Choice("  ❓  Help         Quick reference",         "help"),
                questionary.Choice("  ℹ   About        Version & info",          "about"),
                questionary.Choice("  ✖   Exit",                                 "exit"),
            ],
        )

        if not choice or choice == "exit":
            clr()
            _banner()
            print(f"  {C.CYAN}Stay secure. 🔒{R}\n")
            break
        elif choice == "scan":       menu_scan(cfg)
        elif choice == "deep":       menu_deep(cfg)
        elif choice == "global":     menu_global(cfg)
        elif choice == "vault":      menu_vault(cfg)
        elif choice == "stats":      menu_stats(cfg)
        elif choice == "settings":   cfg = menu_settings(cfg)
        elif choice == "help":       menu_help()
        elif choice == "about":      menu_about()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}Goodbye.{R}\n")
        sys.exit(0)
