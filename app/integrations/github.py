"""ZEROVANT — Genuine GitHub Integration Architecture.

Provides:
- Stage 1: Secure token verification, accessible repo listing, and branch discovery.
- Stage 2: GitHub Actions CI/CD automation workflow generation.
- Stage 3: GitHub App & Webhook HMAC-SHA256 signature verification and event processing.
"""

import hashlib
import hmac
import logging
import os
import re
from typing import Any

import requests

from app.ingest.github_client import (
    GitHubAuthError,
    GitHubClient,
    GitHubClientError,
    GitHubNetworkError,
    GitHubRateLimitError,
    GitHubResourceNotFoundError,
    GitHubSSRFError,
)
from app.pipeline import run_scan
from app.storage.repository import ScanRepository

logger = logging.getLogger(__name__)

# Server-side in-memory credential storage for active auditor session
# Token is NEVER exposed to frontend or stored in client-side localStorage
_ACTIVE_CREDENTIALS: dict[str, Any] = {
    "token": os.environ.get("GITHUB_TOKEN", ""),
    "user": None,
    "webhook_secret": os.environ.get("GITHUB_WEBHOOK_SECRET", "zerovant-webhook-secret-dev"),
}


def get_active_token() -> str:
    """Retrieve the currently configured GitHub token (from session or environment)."""
    return _ACTIVE_CREDENTIALS.get("token") or os.environ.get("GITHUB_TOKEN", "")


def set_active_token(token: str, user_profile: dict[str, Any] | None = None) -> None:
    """Store the verified GitHub token in server-side session memory."""
    _ACTIVE_CREDENTIALS["token"] = token
    _ACTIVE_CREDENTIALS["user"] = user_profile


def get_active_user() -> dict[str, Any] | None:
    """Retrieve the profile metadata for the authenticated GitHub user/app."""
    return _ACTIVE_CREDENTIALS.get("user")


def get_webhook_secret() -> str:
    """Retrieve configured webhook HMAC secret."""
    return _ACTIVE_CREDENTIALS.get("webhook_secret") or os.environ.get("GITHUB_WEBHOOK_SECRET", "")


def verify_github_token(token: str, base_url: str = "https://api.github.com", timeout: float = 10.0) -> dict[str, Any]:
    """Verify GitHub Personal Access Token or App installation token against api.github.com/user.

    Returns:
        User profile dict: login, id, type, scopes, rate_limit_remaining.
    Raises:
        GitHubAuthError: If token is invalid or expired (HTTP 401).
        GitHubRateLimitError: If rate limit exceeded (HTTP 403/429).
        GitHubNetworkError: If connection fails or times out.
    """
    if not token or not isinstance(token, str):
        raise GitHubAuthError("GitHub token must be a non-empty string.")

    headers = {
        "Authorization": f"Bearer {token.strip()}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ZEROVANT-CI-CD-Pipeline-Auditor",
    }

    try:
        resp = requests.get(f"{base_url.rstrip('/')}/user", headers=headers, timeout=timeout)
    except requests.Timeout as exc:
        raise GitHubNetworkError(f"GitHub authentication request timed out: {exc}") from exc
    except requests.RequestException as exc:
        raise GitHubNetworkError(f"GitHub authentication network error: {exc}") from exc

    if resp.status_code == 401:
        raise GitHubAuthError("Invalid, revoked, or expired GitHub Personal Access Token.")

    if resp.status_code in (403, 429):
        reset_time = int(resp.headers.get("X-RateLimit-Reset", 0))
        remaining = int(resp.headers.get("X-RateLimit-Remaining", 0))
        raise GitHubRateLimitError("GitHub API rate limit exceeded.", reset_timestamp=reset_time, remaining=remaining)

    if resp.status_code != 200:
        raise GitHubClientError(f"GitHub API returned unexpected status {resp.status_code}.")

    data = resp.json()
    scopes_header = resp.headers.get("X-OAuth-Scopes", "")
    scopes = [s.strip() for s in scopes_header.split(",") if s.strip()]

    profile = {
        "login": data.get("login"),
        "id": data.get("id"),
        "name": data.get("name"),
        "type": data.get("type", "User"),
        "scopes": scopes,
        "rate_limit_remaining": int(resp.headers.get("X-RateLimit-Remaining", 5000)),
    }

    set_active_token(token.strip(), profile)
    return profile


def list_user_repositories(
    token: str | None = None,
    limit: int = 30,
    base_url: str = "https://api.github.com",
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """List repositories accessible to the configured token (for the Scanner repository dropdown)."""
    auth_token = token or get_active_token()
    if not auth_token:
        raise GitHubAuthError("No GitHub authentication token configured.")

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ZEROVANT-CI-CD-Pipeline-Auditor",
    }

    params = {"per_page": min(limit, 100), "sort": "updated", "direction": "desc"}

    try:
        resp = requests.get(f"{base_url.rstrip('/')}/user/repos", headers=headers, params=params, timeout=timeout)
    except requests.RequestException as exc:
        raise GitHubNetworkError(f"Failed to fetch repositories: {exc}") from exc

    if resp.status_code != 200:
        raise GitHubClientError(f"GitHub API error fetching repositories (HTTP {resp.status_code}).")

    repos = resp.json()
    return [
        {
            "id": r.get("id"),
            "name": r.get("name"),
            "full_name": r.get("full_name"),
            "html_url": r.get("html_url"),
            "default_branch": r.get("default_branch", "main"),
            "private": r.get("private", False),
            "updated_at": r.get("updated_at"),
        }
        for r in repos
        if isinstance(r, dict)
    ]


def list_repository_branches(
    owner: str,
    repo: str,
    token: str | None = None,
    base_url: str = "https://api.github.com",
    timeout: float = 10.0,
) -> list[str]:
    """List branch names for a repository (for the Scanner branch selector)."""
    # Validate identifiers
    ident_pattern = re.compile(r"^[a-zA-Z0-9_.-]+$")
    if not ident_pattern.match(owner) or not ident_pattern.match(repo):
        raise GitHubSSRFError("Invalid owner or repository name identifier.")

    auth_token = token or get_active_token()
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ZEROVANT-CI-CD-Pipeline-Auditor",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    try:
        resp = requests.get(
            f"{base_url.rstrip('/')}/repos/{owner}/{repo}/branches",
            headers=headers,
            params={"per_page": 50},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise GitHubNetworkError(f"Failed to list branches: {exc}") from exc

    if resp.status_code == 404:
        raise GitHubResourceNotFoundError(f"Repository '{owner}/{repo}' not found.")

    if resp.status_code != 200:
        raise GitHubClientError(f"GitHub API error listing branches (HTTP {resp.status_code}).")

    branches = resp.json()
    return [b.get("name") for b in branches if isinstance(b, dict) and b.get("name")]


# =========================================================================
# Stage 3: Webhook Verification & Processing (GitHub App / Webhooks)
# =========================================================================

def verify_webhook_signature(payload_bytes: bytes, signature_header: str | None, secret: str) -> bool:
    """Verify GitHub webhook payload HMAC-SHA256 signature (X-Hub-Signature-256).

    Args:
        payload_bytes: Raw HTTP request body bytes.
        signature_header: Header value format 'sha256=<hex_digest>'.
        secret: Webhook shared secret string.

    Returns:
        True if signature is valid and authentic, False otherwise.
    """
    if not signature_header or not secret:
        return False

    if not signature_header.startswith("sha256="):
        return False

    expected_signature = signature_header[len("sha256=") :]
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    computed_signature = mac.hexdigest()

    return hmac.compare_digest(computed_signature, expected_signature)


def process_webhook_event(
    event_type: str,
    payload: dict[str, Any],
    repository_storage: ScanRepository,
) -> dict[str, Any]:
    """Process verified GitHub webhook event (push or pull_request) and run static audit scan.

    Returns:
        Result summary dict with scan_id, repository, ref, and findings count.
    """
    if event_type not in ("push", "pull_request"):
        return {"status": "ignored", "reason": f"Event '{event_type}' does not trigger CI/CD security audits."}

    repo_data = payload.get("repository", {})
    repo_url = repo_data.get("html_url") or repo_data.get("clone_url")
    owner = repo_data.get("owner", {}).get("login")
    repo_name = repo_data.get("name")

    if not repo_url or not owner or not repo_name:
        raise ValueError("Webhook payload missing repository metadata.")

    # Determine ref
    if event_type == "push":
        raw_ref = payload.get("ref", "refs/heads/main")
        ref = raw_ref.replace("refs/heads/", "")
    else:  # pull_request
        pr_data = payload.get("pull_request", {})
        ref = pr_data.get("head", {}).get("ref") or "main"

    logger.info("Executing automated webhook scan for %s/%s on ref '%s'", owner, repo_name, ref)

    # Ingest workflows and run scan
    token = get_active_token()
    client = GitHubClient(token=token)
    workflows = client.fetch_workflows(repo_url, ref=ref)

    if not workflows:
        return {
            "status": "completed",
            "message": "No workflow definitions found under .github/workflows/*.yml",
            "findings_count": 0,
        }

    scan_id = run_scan(
        source=repo_url,
        source_type="github",
        repo_url=repo_url,
        ref=ref,
        repository=repository_storage,
    )

    scan = repository_storage.get_scan(scan_id)
    return {
        "status": "completed",
        "scan_id": scan_id,
        "repository": f"{owner}/{repo_name}",
        "ref": ref,
        "risk_score": scan.get("repo_score") if scan else 0,
        "findings_count": scan.get("finding_count") if scan else 0,
        "chains_count": len(scan.get("chains", [])) if scan else 0,
    }
