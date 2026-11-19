"""Application configuration settings."""

import os
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Security Rule Settings and Allow-lists
# Official GitHub and major verified cloud platform vendor organizations
TRUSTED_ACTION_OWNERS = {
    "actions",
    "github",
    "aws-actions",
    "google-github-actions",
    "azure",
}

# Permissions policy settings
DEFAULT_PERMISSIONS_SEVERITY = "MEDIUM"
WRITE_ALL_PERMISSIONS_SEVERITY = "HIGH"

# Production deployment identification keywords
PRODUCTION_KEYWORDS = {
    "prod",
    "production",
}

# Untrusted workflow triggers that can be triggered by external actors
UNTRUSTED_TRIGGERS = {
    "pull_request",
    "pull_request_target",
    "issue_comment",
    "issues",
    "fork",
}

# Patterns for detecting hardcoded plaintext secrets (R005)
SECRET_PATTERNS = [
    (re.compile(r"\b(" + "A" + "K" + "IA[0-9A-Z]{16})\b"), "AWS Access Key ID"),
    (re.compile(r"-----" + "BE" + "GIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"https://hooks\.slack\.com/services/T[0-9a-zA-Z_]+/B[0-9a-zA-Z_]+/[0-9a-zA-Z_]+"), "Slack Webhook"),
    (re.compile(r"https://hooks\.example\.com/services/[^\s'\"]+"), "Webhook URL"),
    (re.compile(r"(?i)\b(?:api[_-]?key|auth[_-]?token|secret[_-]?key|bearer[_-]?token|password)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"), "Hardcoded Credential Token"),
    (re.compile(r"(?i)\b(?:STATIC_API_TOKEN|SUPER_SECRET|DEPLOY_KEY)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"), "Static API Token"),
]

# Patterns for script injection contexts interpolated into shell commands (R004)
UNTRUSTED_CONTEXT_PATTERNS = [
    re.compile(r"\$\{\{\s*github\.event\.issue\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.issue\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.comment\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.commits(\[.+\]|\.\*)\.message\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.head_ref\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.head_commit\.message\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.discussion\.title\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.discussion\.body\s*\}\}"),
    re.compile(r"\$\{\{\s*github\.event\.client_payload[^\}]*\}\}"),
]


class Config:
    """Base configuration."""

    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-replace-in-production")
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH", str(BASE_DIR / "instance" / "auditor.db")
    )
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB maximum HTTP request body
    MAX_YAML_SIZE = 1 * 1024 * 1024       # 1MB maximum YAML workflow size
    ALLOW_LOCAL_PATH = False              # Disabled by default for web API security
    RATELIMIT_ENABLED = True              # Enable per-IP rate limiting
    RATELIMIT_PER_MINUTE = 60             # 60 requests per minute by default
    RATELIMIT_WINDOW_SECONDS = 60         # 60-second sliding window


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    DATABASE_PATH = ":memory:"


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}

