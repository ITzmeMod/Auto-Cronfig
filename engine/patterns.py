"""
Pattern registry for Auto-Cronfig v2.
Each entry includes regex, severity, category, verifier ref, and description.
"""

PATTERNS = {
    # ── AWS ──────────────────────────────────────────────────────────────
    "AWS Access Key": {
        "regex": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "category": "cloud",
        "verifier": "aws_access_key",
        "description": "AWS IAM Access Key ID",
    },
    "AWS Secret Key": {
        "regex": r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key[\s]*[=:\"']+\s*([A-Za-z0-9/+=]{40})",
        "severity": "CRITICAL",
        "category": "cloud",
        "verifier": None,
        "description": "AWS IAM Secret Access Key",
    },
    # ── Google ───────────────────────────────────────────────────────────
    "Google API Key": {
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
        "category": "cloud",
        "verifier": "google_api_key",
        "description": "Google API Key",
    },
    "Google OAuth Client Secret": {
        "regex": r"GOCSPX-[0-9A-Za-z\-_]{28}",
        "severity": "HIGH",
        "category": "cloud",
        "verifier": None,
        "description": "Google OAuth Client Secret",
    },
    "Google OAuth Token": {
        "regex": r"ya29\.[0-9A-Za-z\-_]+",
        "severity": "CRITICAL",
        "category": "cloud",
        "verifier": None,
        "description": "Google OAuth Access Token",
    },
    # ── Stripe ───────────────────────────────────────────────────────────
    "Stripe Live Key": {
        "regex": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
        "category": "payment",
        "verifier": "stripe_key",
        "description": "Stripe Live Secret Key",
    },
    "Stripe Test Key": {
        "regex": r"sk_test_[0-9a-zA-Z]{24,}",
        "severity": "MEDIUM",
        "category": "payment",
        "verifier": "stripe_key",
        "description": "Stripe Test Secret Key",
    },
    "Stripe Publishable Key": {
        "regex": r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
        "severity": "LOW",
        "category": "payment",
        "verifier": None,
        "description": "Stripe Publishable Key",
    },
    # ── Twilio ───────────────────────────────────────────────────────────
    "Twilio Account SID": {
        "regex": r"AC[0-9a-fA-F]{32}",
        "severity": "HIGH",
        "category": "communication",
        "verifier": None,
        "description": "Twilio Account SID",
    },
    "Twilio Auth Token": {
        "regex": r"(?i)twilio[_\-\s]*auth[_\-\s]*token[\s]*[=:\"']+\s*([0-9a-f]{32})",
        "severity": "CRITICAL",
        "category": "communication",
        "verifier": None,
        "description": "Twilio Auth Token",
    },
    # ── Slack ────────────────────────────────────────────────────────────
    "Slack Bot Token": {
        "regex": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "severity": "HIGH",
        "category": "communication",
        "verifier": "slack_token",
        "description": "Slack Bot Token",
    },
    "Slack User Token": {
        "regex": r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}",
        "severity": "HIGH",
        "category": "communication",
        "verifier": "slack_token",
        "description": "Slack User Token",
    },
    "Slack Webhook URL": {
        "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        "severity": "HIGH",
        "category": "communication",
        "verifier": None,
        "description": "Slack Incoming Webhook URL",
    },
    # ── Discord ───────────────────────────────────────────────────────────
    "Discord Bot Token": {
        "regex": r"(?:Bot\s+)?([MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})",
        "severity": "HIGH",
        "category": "communication",
        "verifier": "discord_token",
        "description": "Discord Bot Token",
    },
    "Discord Webhook URL": {
        "regex": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+",
        "severity": "HIGH",
        "category": "communication",
        "verifier": None,
        "description": "Discord Webhook URL",
    },
    # ── GitHub ────────────────────────────────────────────────────────────
    "GitHub Personal Access Token": {
        "regex": r"ghp_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "category": "vcs",
        "verifier": "github_token",
        "description": "GitHub Personal Access Token (Classic)",
    },
    "GitHub OAuth Token": {
        "regex": r"gho_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "category": "vcs",
        "verifier": "github_token",
        "description": "GitHub OAuth Token",
    },
    "GitHub App Token": {
        "regex": r"ghs_[A-Za-z0-9]{36}",
        "severity": "CRITICAL",
        "category": "vcs",
        "verifier": "github_token",
        "description": "GitHub App Installation Token",
    },
    "GitHub Fine-Grained PAT": {
        "regex": r"github_pat_[A-Za-z0-9_]{82}",
        "severity": "CRITICAL",
        "category": "vcs",
        "verifier": "github_token",
        "description": "GitHub Fine-Grained Personal Access Token",
    },
    # ── Private Keys ──────────────────────────────────────────────────────
    "RSA Private Key": {
        "regex": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "CRITICAL",
        "category": "cryptography",
        "verifier": None,
        "description": "RSA Private Key",
    },
    "EC Private Key": {
        "regex": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "CRITICAL",
        "category": "cryptography",
        "verifier": None,
        "description": "EC (Elliptic Curve) Private Key",
    },
    "OpenSSH Private Key": {
        "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "CRITICAL",
        "category": "cryptography",
        "verifier": None,
        "description": "OpenSSH Private Key",
    },
    "PGP Private Key": {
        "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "CRITICAL",
        "category": "cryptography",
        "verifier": None,
        "description": "PGP Private Key Block",
    },
    # ── JWT ───────────────────────────────────────────────────────────────
    "JWT Token": {
        "regex": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "severity": "MEDIUM",
        "category": "authentication",
        "verifier": None,
        "description": "JSON Web Token (JWT)",
    },
    # ── Database ──────────────────────────────────────────────────────────
    "PostgreSQL Connection String": {
        "regex": r"postgres(?:ql)?://[^:]+:[^@]+@[^\s\"']+",
        "severity": "CRITICAL",
        "category": "database",
        "verifier": None,
        "description": "PostgreSQL Connection String with credentials",
    },
    "MySQL Connection String": {
        "regex": r"mysql://[^:]+:[^@]+@[^\s\"']+",
        "severity": "CRITICAL",
        "category": "database",
        "verifier": None,
        "description": "MySQL Connection String with credentials",
    },
    "MongoDB Connection String": {
        "regex": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"']+",
        "severity": "CRITICAL",
        "category": "database",
        "verifier": None,
        "description": "MongoDB Connection String with credentials",
    },
    # ── Email Services ────────────────────────────────────────────────────
    "SendGrid API Key": {
        "regex": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "severity": "HIGH",
        "category": "email",
        "verifier": "sendgrid_key",
        "description": "SendGrid API Key",
    },
    "Mailgun API Key": {
        "regex": r"key-[0-9a-zA-Z]{32}",
        "severity": "HIGH",
        "category": "email",
        "verifier": "mailgun_key",
        "description": "Mailgun API Key",
    },
    # ── Firebase ──────────────────────────────────────────────────────────
    "Firebase URL": {
        "regex": r"https://[a-z0-9\-]+\.firebaseio\.com",
        "severity": "MEDIUM",
        "category": "cloud",
        "verifier": None,
        "description": "Firebase Realtime Database URL",
    },
    # ── Heroku ────────────────────────────────────────────────────────────
    "Heroku API Key": {
        "regex": r"(?i)heroku[_\-\s]*(?:api[_\-\s]*)?key[\s]*[=:\"']+\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        "severity": "HIGH",
        "category": "cloud",
        "verifier": None,
        "description": "Heroku API Key",
    },
    # ── Shopify ───────────────────────────────────────────────────────────
    "Shopify Access Token": {
        "regex": r"shpat_[a-fA-F0-9]{32}",
        "severity": "HIGH",
        "category": "ecommerce",
        "verifier": None,
        "description": "Shopify Access Token",
    },
    "Shopify Private App Password": {
        "regex": r"shppa_[a-fA-F0-9]{32}",
        "severity": "HIGH",
        "category": "ecommerce",
        "verifier": None,
        "description": "Shopify Private App Password",
    },
    # ── Telegram ──────────────────────────────────────────────────────────
    "Telegram Bot Token": {
        "regex": r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
        "severity": "HIGH",
        "category": "communication",
        "verifier": "telegram_token",
        "description": "Telegram Bot API Token",
    },
    # ── Twitch ────────────────────────────────────────────────────────────
    "Twitch OAuth Token": {
        "regex": r"oauth:[a-z0-9]{30}",
        "severity": "HIGH",
        "category": "streaming",
        "verifier": None,
        "description": "Twitch OAuth Token",
    },
    # ── PayPal ────────────────────────────────────────────────────────────
    "PayPal Client Secret": {
        "regex": r"(?i)paypal[_\-\s]*(?:client[_\-\s]*)?secret[\s]*[=:\"']+\s*([A-Za-z0-9\-_]{40,80})",
        "severity": "HIGH",
        "category": "payment",
        "verifier": None,
        "description": "PayPal Client Secret",
    },
    # ── Generic secrets ───────────────────────────────────────────────────
    "Generic API Key": {
        "regex": r"(?i)api[_\-\s]*key[\s]*[=:\"']+\s*([A-Za-z0-9\-_]{20,80})",
        "severity": "MEDIUM",
        "category": "generic",
        "verifier": None,
        "description": "Generic API Key assignment",
    },
    "Generic Secret": {
        "regex": r"(?i)(?:secret|private[_\-]key)[\s]*[=:\"']+\s*([A-Za-z0-9\-_/+]{20,80})",
        "severity": "MEDIUM",
        "category": "generic",
        "verifier": None,
        "description": "Generic secret/private key assignment",
    },
    "Generic Password": {
        "regex": r"(?i)password[\s]*[=:\"']+\s*([^\s\"']{8,80})",
        "severity": "MEDIUM",
        "category": "generic",
        "verifier": None,
        "description": "Generic password assignment",
    },
}

# Files that should be prioritized / flagged even without pattern matches
RISKY_FILENAMES = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".pem",
    ".key",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "secrets.json",
    "config.json",
    "wp-config.php",
    "settings.py",
    "database.yml",
    "secrets.yml",
    ".p12",
    ".pfx",
    ".sqlite",
    ".db",
]
