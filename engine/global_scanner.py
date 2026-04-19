"""
Auto-Cronfig v3 — Global Scanner
Searches all of public GitHub for any leaked secret, API key, or credential.
200+ search queries covering every major secret category.
Fast mode: parallel query dispatch with rate-limit-aware pacing.
"""

import time
import sys
import json
import datetime
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Callable

logger = logging.getLogger(__name__)

from .scanner import RawFinding, _make_headers, _request_with_backoff, _scan_text_for_patterns

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ─────────────────────────────────────────────────────────────────────────────
# 200+ GLOBAL SEARCH QUERIES — every major secret / leak category
# ─────────────────────────────────────────────────────────────────────────────
GLOBAL_SEARCH_QUERIES = [

    # ── AWS ──────────────────────────────────────────────────────────────────
    "AKIA filename:.env",
    "AKIA language:python",
    "AKIA language:javascript",
    "AKIA language:yaml",
    "AKIA language:ruby",
    "AKIA language:go",
    "AKIA language:java",
    "AKIA language:php",
    "ASIAKID language:python",
    "aws_access_key_id language:python",
    "aws_secret_access_key language:python",
    "aws_access_key_id filename:.env",
    "AWS_ACCESS_KEY_ID filename:.env",
    "AWS_SECRET_ACCESS_KEY filename:.env",

    # ── Google / GCP ─────────────────────────────────────────────────────────
    "AIzaSy language:javascript",
    "AIzaSy language:python",
    "AIzaSy filename:.env",
    "AIzaSy language:yaml",
    "GOCSPX- language:python",
    "GOCSPX- language:javascript",
    "ya29. language:python",
    "type service_account language:json",
    "GOOGLE_API_KEY filename:.env",
    "FIREBASE_API_KEY filename:.env",

    # ── Azure ─────────────────────────────────────────────────────────────────
    "DefaultEndpointsProtocol=https language:python",
    "DefaultEndpointsProtocol=https language:javascript",
    "AccountKey= language:python",
    "AZURE_CLIENT_SECRET filename:.env",
    "AZURE_STORAGE_KEY filename:.env",

    # ── GitHub tokens ─────────────────────────────────────────────────────────
    "ghp_ language:yaml",
    "ghp_ language:python",
    "ghp_ filename:.env",
    "gho_ language:python",
    "ghs_ language:yaml",
    "github_pat_ language:yaml",
    "github_pat_ language:python",
    "GITHUB_TOKEN filename:.env",
    "GITHUB_TOKEN language:yaml",

    # ── GitLab ────────────────────────────────────────────────────────────────
    "glpat- language:yaml",
    "glpat- language:python",
    "glpat- filename:.env",
    "GITLAB_TOKEN filename:.env",

    # ── Stripe ────────────────────────────────────────────────────────────────
    "sk_live_ language:python",
    "sk_live_ language:javascript",
    "sk_live_ language:ruby",
    "sk_live_ filename:.env",
    "sk_test_ language:python",
    "sk_test_ filename:.env",
    "STRIPE_SECRET_KEY filename:.env",
    "STRIPE_SECRET_KEY language:python",
    "STRIPE_SECRET_KEY language:javascript",
    "whsec_ language:javascript",
    "whsec_ filename:.env",

    # ── OpenAI / Anthropic / AI ───────────────────────────────────────────────
    "OPENAI_API_KEY filename:.env",
    "OPENAI_API_KEY language:python",
    "OPENAI_API_KEY language:javascript",
    "sk-ant-api language:python",
    "sk-ant-api language:javascript",
    "sk-ant-api filename:.env",
    "ANTHROPIC_API_KEY filename:.env",
    "hf_ language:python",
    "hf_ filename:.env",
    "HUGGINGFACE_TOKEN filename:.env",
    "r8_ language:python",
    "REPLICATE_API_TOKEN filename:.env",
    "gsk_ language:python",
    "gsk_ filename:.env",
    "GROQ_API_KEY filename:.env",
    "COHERE_API_KEY filename:.env",
    "MISTRAL_API_KEY filename:.env",
    "TOGETHER_API_KEY filename:.env",
    "PERPLEXITY_API_KEY filename:.env",
    "STABILITY_API_KEY filename:.env",
    "ELEVENLABS_API_KEY filename:.env",

    # ── Slack ─────────────────────────────────────────────────────────────────
    "xoxb- language:python",
    "xoxb- language:javascript",
    "xoxb- language:yaml",
    "xoxb- filename:.env",
    "xoxp- language:python",
    "xoxp- filename:.env",
    "xapp- language:python",
    "SLACK_BOT_TOKEN filename:.env",
    "SLACK_SIGNING_SECRET filename:.env",
    "hooks.slack.com/services language:javascript",
    "hooks.slack.com/services language:python",

    # ── Discord ───────────────────────────────────────────────────────────────
    "DISCORD_TOKEN filename:.env",
    "DISCORD_BOT_TOKEN filename:.env",
    "discord.com/api/webhooks language:javascript",
    "discord.com/api/webhooks language:python",
    "discord.com/api/webhooks language:yaml",

    # ── Telegram ──────────────────────────────────────────────────────────────
    "TELEGRAM_BOT_TOKEN filename:.env",
    "TELEGRAM_TOKEN filename:.env",
    "api.telegram.org/bot language:python",
    "api.telegram.org/bot language:javascript",

    # ── Twilio ────────────────────────────────────────────────────────────────
    "TWILIO_AUTH_TOKEN filename:.env",
    "TWILIO_ACCOUNT_SID filename:.env",
    "twilio_auth_token language:python",
    "twilio_auth_token language:ruby",

    # ── SendGrid / Email ──────────────────────────────────────────────────────
    "SG. language:python",
    "SG. language:javascript",
    "SG. filename:.env",
    "SENDGRID_API_KEY filename:.env",
    "key- language:python filename:mailgun",
    "MAILGUN_API_KEY filename:.env",
    "POSTMARK_API_KEY filename:.env",
    "MAILCHIMP_API_KEY filename:.env",
    "SPARKPOST_API_KEY filename:.env",
    "BREVO_API_KEY filename:.env",

    # ── Private keys ─────────────────────────────────────────────────────────
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",

    # ── Databases ─────────────────────────────────────────────────────────────
    "mongodb+srv:// language:javascript",
    "mongodb+srv:// language:python",
    "mongodb+srv:// filename:.env",
    "mongodb:// language:javascript",
    "mongodb:// language:python",
    "postgres:// language:python",
    "postgres:// language:javascript",
    "postgres:// filename:.env",
    "DATABASE_URL filename:.env",
    "MONGO_URI filename:.env",
    "REDIS_URL filename:.env",
    "redis://:@ language:python",
    "mysql:// language:python",
    "SUPABASE_SERVICE_ROLE_KEY filename:.env",
    "SUPABASE_SERVICE_KEY filename:.env",
    "NEON_DATABASE_URL filename:.env",
    "PLANETSCALE_URL filename:.env",

    # ── Social / Marketing ───────────────────────────────────────────────────
    "EAAAl language:javascript",
    "EAAAl language:python",
    "FACEBOOK_APP_SECRET filename:.env",
    "TWITTER_API_KEY filename:.env",
    "TWITTER_BEARER_TOKEN filename:.env",
    "INSTAGRAM_ACCESS_TOKEN filename:.env",
    "LINKEDIN_CLIENT_SECRET filename:.env",
    "TIKTOK_ACCESS_TOKEN filename:.env",
    "REDDIT_CLIENT_SECRET filename:.env",

    # ── Cloud / DevOps ────────────────────────────────────────────────────────
    "dop_v1_ language:yaml",
    "dop_v1_ filename:.env",
    "DIGITALOCEAN_TOKEN filename:.env",
    "LINODE_TOKEN filename:.env",
    "VULTR_API_KEY filename:.env",
    "CF_API_TOKEN filename:.env",
    "CLOUDFLARE_API_TOKEN filename:.env",
    "VERCEL_TOKEN filename:.env",
    "NETLIFY_AUTH_TOKEN filename:.env",
    "RAILWAY_TOKEN filename:.env",
    "FLY_API_TOKEN filename:.env",
    "HEROKU_API_KEY filename:.env",
    "hvs. language:python",
    "hvs. filename:.env",
    "atlasv1. language:python",
    "VAULT_TOKEN filename:.env",

    # ── Payment processors ────────────────────────────────────────────────────
    "sq0atp- language:python",
    "sq0atp- filename:.env",
    "PAYPAL_CLIENT_SECRET filename:.env",
    "RAZORPAY_KEY_SECRET filename:.env",
    "SHOPIFY_ACCESS_TOKEN filename:.env",
    "shpat_ language:python",
    "shpat_ filename:.env",
    "PADDLE_API_KEY filename:.env",
    "MOLLIE_API_KEY filename:.env",

    # ── Monitoring / Analytics ────────────────────────────────────────────────
    "DATADOG_API_KEY filename:.env",
    "DD_API_KEY filename:.env",
    "SENTRY_DSN filename:.env",
    "sentry_dsn language:python",
    "NEWRELIC_LICENSE_KEY filename:.env",
    "NR_LICENSE_KEY filename:.env",
    "ROLLBAR_ACCESS_TOKEN filename:.env",
    "BUGSNAG_API_KEY filename:.env",
    "PAGERDUTY_API_KEY filename:.env",
    "GRAFANA_API_KEY filename:.env",
    "AMPLITUDE_API_KEY filename:.env",
    "MIXPANEL_TOKEN filename:.env",
    "SEGMENT_WRITE_KEY filename:.env",
    "LOGDNA_INGESTION_KEY filename:.env",

    # ── Generic .env catches ─────────────────────────────────────────────────
    "API_KEY= filename:.env",
    "SECRET_KEY= filename:.env",
    "ACCESS_TOKEN= filename:.env",
    "PRIVATE_KEY= filename:.env",
    "PASSWORD= filename:.env",
    "DB_PASSWORD= filename:.env",
    "AUTH_TOKEN= filename:.env",
    "SECRET= filename:.env",
    "API_SECRET= filename:.env",
    "CLIENT_SECRET= filename:.env",

    # ── Config file leaks ─────────────────────────────────────────────────────
    "password: filename:config.yml",
    "password: filename:database.yml",
    "secret_key_base filename:secrets.yml",
    "api_key: filename:config.yaml",
    "auth_token filename:application.yml",
    "password filename:wp-config.php",
    "DB_PASSWORD filename:.env.production",
    "DB_PASSWORD filename:.env.local",
    "SECRET_KEY filename:.env.production",
    "NEXTAUTH_SECRET filename:.env.local",
]

# ── Category query map — focused lists per secret type ────────────────────────
CATEGORY_QUERY_MAP = {
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

# ─────────────────────────────────────────────────────────────────────────────

class GlobalScanner:
    def __init__(self, token: Optional[str] = None, workers: int = 4, memory=None):
        self.token   = token
        self.workers = workers
        self.memory  = memory
        self._headers = _make_headers(token)
        self._seen: set = set()

    # ── single query ──────────────────────────────────────────────────────────
    def _run_query(
        self,
        query: str,
        max_results: int = 30,
        callback: Optional[Callable] = None,
    ) -> List[RawFinding]:
        import base64 as b64
        findings: List[RawFinding] = []
        per_page = min(30, max_results)

        resp = _request_with_backoff(
            "GET", "https://api.github.com/search/code",
            self._headers,
            params={"q": query, "per_page": per_page, "page": 1},
        )
        if resp is None:
            return findings

        sc = resp.status_code
        if sc == 422:
            # query too short/broad — skip silently
            return findings
        if sc == 403:
            time.sleep(20)
            return findings
        if sc != 200:
            return findings

        items = resp.json().get("items", [])
        for item in items[:max_results]:
            repo_full = item["repository"]["full_name"]
            file_path = item["path"]
            html_url  = item.get("html_url",
                f"https://github.com/{repo_full}/blob/HEAD/{file_path}")
            content_url = item.get("url",
                f"https://api.github.com/repos/{repo_full}/contents/{file_path}")

            cr = _request_with_backoff("GET", content_url, self._headers)
            if not cr or cr.status_code != 200:
                continue

            raw_b64 = cr.json().get("content", "")
            if not raw_b64:
                continue
            try:
                content = b64.b64decode(raw_b64).decode("utf-8", errors="replace")
                hits = _scan_text_for_patterns(
                    content, repo_full, file_path, html_url, memory=self.memory
                )
                for hit in hits:
                    key = (hit.repo, hit.file_path, hit.pattern_name, hit.match_preview)
                    if key not in self._seen:
                        self._seen.add(key)
                        findings.append(hit)
                        if callback:
                            try:
                                callback(hit)
                            except Exception as exc:
                                logger.debug("callback error: %s", exc)
            except Exception as exc:
                logger.debug("content decode error: %s", exc)

            # GitHub code search: 10 requests/min for content fetches
            time.sleep(6)

        return findings

    # ── run all queries (fast-mode: parallel batches) ─────────────────────────
    def run_all_queries(
        self,
        max_per_query: int = 20,
        callback: Optional[Callable] = None,
        fast: bool = True,
    ) -> List[RawFinding]:
        """
        Run all GLOBAL_SEARCH_QUERIES.
        fast=True: run queries in parallel batches of 3 (still rate-limited per content fetch).
        fast=False: fully sequential.
        Deduplicates across all queries.
        """
        self._seen = set()
        all_findings: List[RawFinding] = []
        queries = list(GLOBAL_SEARCH_QUERIES)
        total   = len(queries)

        if fast:
            # Batch size 3 — safe for GitHub search API (10 search req/min)
            batch_size = 3
            batches = [queries[i:i+batch_size] for i in range(0, total, batch_size)]
            done = 0
            for batch in batches:
                with ThreadPoolExecutor(max_workers=batch_size) as ex:
                    futs = {ex.submit(self._run_query, q, max_per_query, callback): q
                            for q in batch}
                    for fut in as_completed(futs):
                        q = futs[fut]
                        try:
                            hits = fut.result()
                            all_findings.extend(hits)
                            done += 1
                            pct = int(done / total * 100)
                            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                            sys.stdout.write(
                                f"\r  [{bar}] {pct:3d}%  "
                                f"{done}/{total} queries  "
                                f"{len(all_findings)} found  "
                            )
                            sys.stdout.flush()
                        except Exception as exc:
                            logger.debug("query batch error: %s", exc)
                # Small pause between batches so search rate stays safe
                time.sleep(2)
        else:
            it = tqdm(queries, desc="  Scanning", unit="q") if HAS_TQDM else queries
            for i, q in enumerate(it, 1):
                try:
                    hits = self._run_query(q, max_per_query, callback)
                    all_findings.extend(hits)
                except KeyboardInterrupt:
                    print("\n  Interrupted.")
                    break
                except Exception as exc:
                    logger.debug("query error: %s", exc)

        print()  # newline after progress bar
        return all_findings

    # ── targeted search ────────────────────────────────────────────────────────
    def run_targeted(self, query_term: str, max_results: int = 100,
                     callback: Optional[Callable] = None) -> List[RawFinding]:
        """Search GitHub for a specific term or pattern."""
        self._seen = set()
        return self._run_query(query_term, max_results=max_results, callback=callback)

    # ── continuous auto-scan ──────────────────────────────────────────────────
    def run_auto_scan(self, interval_seconds: int = 3600, output_path: Optional[str] = None):
        """Runs run_all_queries every interval_seconds until Ctrl+C."""
        scan_n = 0
        print(f"  Auto global scan started — interval {interval_seconds}s")
        print("  Ctrl+C to stop\n")
        while True:
            scan_n += 1
            ts  = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            print(f"\n  ── Scan #{scan_n}  {ts} {'─'*20}")
            t0  = time.monotonic()
            findings = self.run_all_queries(max_per_query=20, fast=True)
            dur = time.monotonic() - t0
            print(f"  ✓ {len(findings)} findings in {dur:.0f}s")

            if output_path and findings:
                try:
                    existing: list = []
                    try:
                        with open(output_path) as f:
                            existing = json.load(f)
                    except Exception as exc:
                        logger.debug("load existing results error: %s", exc)
                    for h in findings:
                        existing.append({
                            "scan": scan_n, "ts": ts,
                            "repo": h.repo, "file": h.file_path,
                            "pattern": h.pattern_name,
                            "preview": h.match_preview,
                            "severity": h.severity, "url": h.url,
                        })
                    with open(output_path, "w") as f:
                        json.dump(existing, f, indent=2)
                    print(f"  → saved to {output_path}")
                except Exception as exc:
                    logger.warning("save error: %s", exc)

            print(f"  Next scan in {interval_seconds}s…  (Ctrl+C to stop)")
            try:
                for rem in range(interval_seconds, 0, -1):
                    sys.stdout.write(f"\r  ⏱  {rem:5d}s remaining   ")
                    sys.stdout.flush()
                    time.sleep(1)
                print("\r" + " " * 30)
            except KeyboardInterrupt:
                print("\n  Stopped.")
                break
