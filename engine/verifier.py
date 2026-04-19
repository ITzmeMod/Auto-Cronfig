"""
Live key verification engine for Auto-Cronfig v3.
Makes real HTTP calls to verify whether found secrets are active.
Extended with OpenAI, Anthropic, HuggingFace, Replicate, Cloudflare, DigitalOcean, Twitter.
"""

import time
import datetime
from dataclasses import dataclass, field
from typing import Optional

import requests


@dataclass
class VerificationResult:
    status: str  # "LIVE" | "DEAD" | "UNKNOWN" | "ERROR"
    detail: str
    checked_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    latency_ms: int = 0


def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()


def _verify_github_token(key: str) -> VerificationResult:
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"token {key}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=8,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            login = data.get("login", "unknown")
            scopes = resp.headers.get("X-OAuth-Scopes", "")
            return VerificationResult(
                status="LIVE",
                detail=f"GitHub user: {login}, scopes: {scopes or 'none'}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code == 401:
            return VerificationResult(
                status="DEAD",
                detail="GitHub token is invalid or revoked (401)",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_stripe_key(key: str) -> VerificationResult:
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.stripe.com/v1/balance",
            auth=(key, ""),
            timeout=8,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            return VerificationResult(
                status="LIVE",
                detail="Stripe key is valid — /v1/balance returned 200",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code in (401, 403):
            return VerificationResult(
                status="DEAD",
                detail=f"Stripe key rejected ({resp.status_code})",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_slack_token(key: str) -> VerificationResult:
    start = time.monotonic()
    try:
        resp = requests.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {key}"},
            timeout=8,
        )
        latency = int((time.monotonic() - start) * 1000)
        data = resp.json()
        if data.get("ok") is True:
            team = data.get("team", "unknown")
            user = data.get("user", "unknown")
            return VerificationResult(
                status="LIVE",
                detail=f"Slack token is live — team: {team}, user: {user}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            error = data.get("error", "unknown error")
            return VerificationResult(
                status="DEAD",
                detail=f"Slack token invalid: {error}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_discord_token(key: str) -> VerificationResult:
    token = key.strip()
    if token.lower().startswith("bot "):
        token = token[4:]
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://discord.com/api/v10/users/@me",
            headers={"Authorization": f"Bot {token}"},
            timeout=8,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            username = data.get("username", "unknown")
            return VerificationResult(
                status="LIVE",
                detail=f"Discord bot token is live — username: {username}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code == 401:
            return VerificationResult(
                status="DEAD",
                detail="Discord token is invalid or revoked (401)",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_telegram_token(key: str) -> VerificationResult:
    start = time.monotonic()
    try:
        resp = requests.get(
            f"https://api.telegram.org/bot{key}/getMe",
            timeout=8,
        )
        latency = int((time.monotonic() - start) * 1000)
        data = resp.json()
        if data.get("ok") is True:
            bot = data.get("result", {})
            username = bot.get("username", "unknown")
            return VerificationResult(
                status="LIVE",
                detail=f"Telegram bot token is live — @{username}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            desc = data.get("description", "unknown error")
            return VerificationResult(
                status="DEAD",
                detail=f"Telegram token invalid: {desc}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_sendgrid_key(key: str) -> VerificationResult:
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.sendgrid.com/v3/user/account",
            headers={"Authorization": f"Bearer {key}"},
            timeout=8,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            account_type = data.get("type", "unknown")
            return VerificationResult(
                status="LIVE",
                detail=f"SendGrid key is live — account type: {account_type}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code in (401, 403):
            return VerificationResult(
                status="DEAD",
                detail=f"SendGrid key rejected ({resp.status_code})",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_mailgun_key(key: str) -> VerificationResult:
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.mailgun.net/v3/domains",
            auth=("api", key),
            timeout=8,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            return VerificationResult(
                status="LIVE",
                detail="Mailgun key is valid — /v3/domains returned 200",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code in (401, 403):
            return VerificationResult(
                status="DEAD",
                detail=f"Mailgun key rejected ({resp.status_code})",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_google_api_key(key: str) -> VerificationResult:
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://maps.googleapis.com/maps/api/geocode/json",
            params={"address": "test", "key": key},
            timeout=8,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            api_status = data.get("status", "")
            if api_status == "REQUEST_DENIED":
                return VerificationResult(
                    status="DEAD",
                    detail="Google API key rejected — REQUEST_DENIED",
                    checked_at=_now_iso(),
                    latency_ms=latency,
                )
            return VerificationResult(
                status="LIVE",
                detail=f"Google API key is valid — geocode status: {api_status}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_openai_key(key: str) -> VerificationResult:
    """Verify OpenAI API key by calling /v1/models."""
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            model_count = len(data.get("data", []))
            return VerificationResult(
                status="LIVE",
                detail=f"OpenAI API key is valid — {model_count} models available",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code == 401:
            return VerificationResult(
                status="DEAD",
                detail="OpenAI API key is invalid or revoked (401)",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_anthropic_key(key: str) -> VerificationResult:
    """Verify Anthropic API key by calling /v1/models."""
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
            },
            timeout=10,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            return VerificationResult(
                status="LIVE",
                detail="Anthropic API key is valid — /v1/models returned 200",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code in (401, 403):
            return VerificationResult(
                status="DEAD",
                detail=f"Anthropic API key rejected ({resp.status_code})",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_huggingface_token(key: str) -> VerificationResult:
    """Verify HuggingFace token via /api/whoami."""
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://huggingface.co/api/whoami",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            username = data.get("name", data.get("user", "unknown"))
            return VerificationResult(
                status="LIVE",
                detail=f"HuggingFace token is valid — user: {username}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code == 401:
            return VerificationResult(
                status="DEAD",
                detail="HuggingFace token is invalid or revoked (401)",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_replicate_token(key: str) -> VerificationResult:
    """Verify Replicate API token via /v1/account."""
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.replicate.com/v1/account",
            headers={"Authorization": f"Token {key}"},
            timeout=10,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            username = data.get("username", "unknown")
            return VerificationResult(
                status="LIVE",
                detail=f"Replicate token is valid — user: {username}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code == 401:
            return VerificationResult(
                status="DEAD",
                detail="Replicate token is invalid or revoked (401)",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_cloudflare_token(key: str) -> VerificationResult:
    """Verify Cloudflare API token via /client/v4/user."""
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.cloudflare.com/client/v4/user",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            email = data.get("result", {}).get("email", "unknown")
            return VerificationResult(
                status="LIVE",
                detail=f"Cloudflare token is valid — email: {email}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code in (400, 401, 403):
            return VerificationResult(
                status="DEAD",
                detail=f"Cloudflare token rejected ({resp.status_code})",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_digitalocean_token(key: str) -> VerificationResult:
    """Verify DigitalOcean token via /v2/account."""
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.digitalocean.com/v2/account",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            email = data.get("account", {}).get("email", "unknown")
            return VerificationResult(
                status="LIVE",
                detail=f"DigitalOcean token is valid — email: {email}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code == 401:
            return VerificationResult(
                status="DEAD",
                detail="DigitalOcean token is invalid or revoked (401)",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_twitter_bearer_token(key: str) -> VerificationResult:
    """Verify Twitter/X Bearer token via /2/users/me."""
    start = time.monotonic()
    try:
        resp = requests.get(
            "https://api.twitter.com/2/users/me",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        )
        latency = int((time.monotonic() - start) * 1000)
        if resp.status_code == 200:
            data = resp.json()
            username = data.get("data", {}).get("username", "unknown")
            return VerificationResult(
                status="LIVE",
                detail=f"Twitter Bearer token is valid — user: @{username}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        elif resp.status_code == 401:
            return VerificationResult(
                status="DEAD",
                detail="Twitter Bearer token is invalid (401)",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
        else:
            return VerificationResult(
                status="UNKNOWN",
                detail=f"Unexpected status code: {resp.status_code}",
                checked_at=_now_iso(),
                latency_ms=latency,
            )
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Request failed: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=int((time.monotonic() - start) * 1000),
        )


def _verify_shopify_token(key: str) -> VerificationResult:
    """Verify Shopify token by checking pattern (domain check not possible without domain)."""
    if key.startswith("shpat_") and len(key) == 38:
        return VerificationResult(
            status="UNKNOWN",
            detail="Shopify token format matches — cannot verify without target shop domain",
            checked_at=_now_iso(),
            latency_ms=0,
        )
    return VerificationResult(
        status="UNKNOWN",
        detail="Shopify token pattern not conclusive",
        checked_at=_now_iso(),
        latency_ms=0,
    )


# ── Verifier dispatch map ─────────────────────────────────────────────────────
_VERIFIER_MAP = {
    "github_token": _verify_github_token,
    "stripe_key": _verify_stripe_key,
    "slack_token": _verify_slack_token,
    "discord_token": _verify_discord_token,
    "telegram_token": _verify_telegram_token,
    "sendgrid_key": _verify_sendgrid_key,
    "mailgun_key": _verify_mailgun_key,
    "google_api_key": _verify_google_api_key,
    "openai_key": _verify_openai_key,
    "anthropic_key": _verify_anthropic_key,
    "huggingface_token": _verify_huggingface_token,
    "replicate_token": _verify_replicate_token,
    "cloudflare_token": _verify_cloudflare_token,
    "digitalocean_token": _verify_digitalocean_token,
    "twitter_bearer_token": _verify_twitter_bearer_token,
    "shopify_token": _verify_shopify_token,
    "aws_access_key": lambda key: VerificationResult(
        status="UNKNOWN",
        detail="AWS key format detected — use aws-cli for full verification",
        checked_at=_now_iso(),
        latency_ms=0,
    ),
}


def verify(pattern_name: str, raw_match: str) -> VerificationResult:
    """
    Dispatch to the correct verifier based on pattern_name.
    Returns UNKNOWN if no verifier is registered for the pattern.
    Never raises.
    """
    from .patterns import PATTERNS

    pattern_meta = PATTERNS.get(pattern_name, {})
    verifier_ref = pattern_meta.get("verifier")

    if not verifier_ref or verifier_ref not in _VERIFIER_MAP:
        return VerificationResult(
            status="UNKNOWN",
            detail=f"No verifier available for pattern: {pattern_name}",
            checked_at=_now_iso(),
            latency_ms=0,
        )

    try:
        return _VERIFIER_MAP[verifier_ref](raw_match.strip())
    except Exception as e:
        return VerificationResult(
            status="ERROR",
            detail=f"Verifier raised unexpected exception: {type(e).__name__}: {e}",
            checked_at=_now_iso(),
            latency_ms=0,
        )
