"""Tests for ZEROVANT GitHub Integration Architecture."""

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

from app.integrations.github import (
    verify_webhook_signature,
)


def test_github_status_endpoint(client):
    """Verify /api/integrations/github/status returns configuration status."""
    res = client.get("/api/integrations/github/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "configured" in data
    assert "authenticated" in data


def test_github_connect_token_validation(client):
    """Verify token connection endpoint rejects empty/missing tokens."""
    res = client.post("/api/integrations/github/connect", json={})
    assert res.status_code == 400
    assert res.get_json()["error"]["code"] == "MISSING_TOKEN"


@patch("requests.get")
def test_github_connect_token_success(mock_get, client):
    """Verify successful GitHub token verification returns sanitized user profile."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "login": "test-secops",
        "id": 12345,
        "name": "Security Ops",
        "type": "User",
    }
    mock_resp.headers = {
        "X-OAuth-Scopes": "repo, read:org",
        "X-RateLimit-Remaining": "4950",
    }
    mock_get.return_value = mock_resp

    res = client.post("/api/integrations/github/connect", json={"token": "ghp_validToken1234567890"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "connected"
    assert data["user"]["login"] == "test-secops"
    assert "repo" in data["user"]["scopes"]


@patch("requests.get")
def test_github_connect_token_unauthorized(mock_get, client):
    """Verify invalid GitHub token returns HTTP 401."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.return_value = mock_resp

    res = client.post("/api/integrations/github/connect", json={"token": "ghp_invalidToken"})
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "AUTH_FAILED"


def test_webhook_hmac_signature_verification():
    """Verify HMAC-SHA256 signature calculation and verification."""
    secret = "test-webhook-secret-key-123"
    payload = b'{"action": "ping"}'

    # Compute valid signature
    mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
    valid_sig = f"sha256={mac.hexdigest()}"

    assert verify_webhook_signature(payload, valid_sig, secret) is True
    assert verify_webhook_signature(payload, "sha256=invalidhex000000", secret) is False
    assert verify_webhook_signature(payload, None, secret) is False


def test_webhook_ping_event(client):
    """Verify GitHub webhook ping event returns pong."""
    res = client.post(
        "/api/integrations/github/webhook",
        headers={"X-GitHub-Event": "ping"},
        json={"zen": "Design for failure."},
    )
    assert res.status_code == 200
    assert res.get_json()["status"] == "pong"


def test_webhook_invalid_signature_rejected(client):
    """Verify webhooks with invalid HMAC signatures return 401."""
    res = client.post(
        "/api/integrations/github/webhook",
        headers={
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": "sha256=bad_signature_digest",
        },
        json={"ref": "refs/heads/main"},
    )
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "INVALID_SIGNATURE"


@patch("app.integrations.github.GitHubClient.fetch_workflows")
def test_webhook_push_event_executes_scan(mock_fetch, client):
    """Verify verified push event initiates pipeline scan and stores results."""
    # Mock workflow response
    vulnerable_yaml = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
"""
    mock_fetch.return_value = [(".github/workflows/ci.yml", vulnerable_yaml)]

    secret = "zerovant-webhook-secret-dev"
    payload_data = {
        "ref": "refs/heads/main",
        "repository": {
            "name": "demo-pipeline",
            "html_url": "https://github.com/zerovant-test/demo-pipeline",
            "owner": {"login": "zerovant-test"},
        },
    }
    payload_bytes = json.dumps(payload_data).encode("utf-8")

    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    valid_sig = f"sha256={mac.hexdigest()}"

    res = client.post(
        "/api/integrations/github/webhook",
        data=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": valid_sig,
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "completed"
    assert "scan_id" in data
    assert data["repository"] == "zerovant-test/demo-pipeline"
