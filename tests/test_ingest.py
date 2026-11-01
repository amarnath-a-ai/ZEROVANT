"""Tests for Ingestion Adapters: LocalLoader and GitHubClient (Phase 1)."""

import base64
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from app.ingest import (
    GitHubAuthError,
    GitHubClient,
    GitHubNetworkError,
    GitHubPayloadTooLargeError,
    GitHubRateLimitError,
    GitHubResourceNotFoundError,
    GitHubSSRFError,
    LocalLoader,
    parse_and_validate_github_url,
    validate_download_url,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


# ============================================================================
# LocalLoader Tests
# ============================================================================


def test_local_loader_load_single_file():
    """Verify loading a valid single workflow file."""
    loader = LocalLoader()
    file_path = FIXTURES_DIR / "safe" / "safe_r001_pinned.yml"
    content = loader.load_from_file(file_path)
    assert "Safe Pinned Actions" in content


def test_local_loader_nonexistent_file():
    """Verify FileNotFoundError on nonexistent file."""
    loader = LocalLoader()
    with pytest.raises(FileNotFoundError):
        loader.load_from_file("nonexistent/path/workflow.yml")


def test_local_loader_invalid_extension():
    """Verify ValueError on non-yaml file extension."""
    loader = LocalLoader()
    with pytest.raises(ValueError, match="Invalid workflow file extension"):
        loader.load_from_file(FIXTURES_DIR / "real_world" / "SOURCES.md")


def test_local_loader_size_limit(tmp_path):
    """Verify ValueError when file exceeds max size limit."""
    huge_file = tmp_path / "huge.yml"
    # Create 2MB file
    huge_file.write_text("x" * (2 * 1024 * 1024), encoding="utf-8")

    loader = LocalLoader(max_file_size=1 * 1024 * 1024)
    with pytest.raises(ValueError, match="exceeds maximum allowed limit"):
        loader.load_from_file(huge_file)


def test_local_loader_directory_discovery():
    """Verify discovery of all workflow files in a directory."""
    loader = LocalLoader()
    discovered = loader.load_from_directory(FIXTURES_DIR / "safe")
    assert len(discovered) >= 8
    file_names = [f[0] for f in discovered]
    assert any("safe_r001_pinned.yml" in name for name in file_names)


def test_local_loader_symlink_escape_protection(tmp_path):
    """Verify ValueError when a symlink resolves outside the base directory."""
    target_outside = tmp_path / "outside"
    target_outside.mkdir()
    secret_file = target_outside / "secret.yml"
    secret_file.write_text("name: Secret\non: push\njobs: {}\n", encoding="utf-8")

    base_dir = tmp_path / "repo"
    workflows_dir = base_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    # Attempt native symlink first
    symlink_path = workflows_dir / "escaped.yml"
    symlink_created = False
    try:
        symlink_path.symlink_to(secret_file)
        symlink_created = True
    except (OSError, NotImplementedError):
        pass

    loader = LocalLoader()

    if symlink_created:
        with pytest.raises(ValueError, match="Symlink traversal security violation"):
            loader.load_from_directory(base_dir)
    else:
        # Mock resolved target pointing outside base_dir to verify protection on Windows non-admin
        mock_file = MagicMock(spec=Path)
        mock_file.resolve.return_value = secret_file.resolve()
        mock_file.name = "escaped.yml"
        mock_file.suffix = ".yml"

        with patch.object(Path, "glob", return_value=[mock_file]):
            with pytest.raises(ValueError, match="Symlink traversal security violation"):
                loader.load_from_directory(base_dir)


# ============================================================================
# GitHub URL Validation (SSRF Prevention) Tests
# ============================================================================


def test_github_url_validation_success():
    """Verify valid GitHub URLs and slugs parse properly."""
    # Standard URL
    owner, repo, ref = parse_and_validate_github_url("https://github.com/pallets/flask")
    assert owner == "pallets"
    assert repo == "flask"
    assert ref is None

    # .git extension
    owner, repo, ref = parse_and_validate_github_url("https://github.com/pallets/flask.git")
    assert owner == "pallets"
    assert repo == "flask"
    assert ref is None

    # Tree ref branch
    owner, repo, ref = parse_and_validate_github_url("https://github.com/pallets/flask/tree/main")
    assert owner == "pallets"
    assert repo == "flask"
    assert ref == "main"

    # Slug
    owner, repo, ref = parse_and_validate_github_url("pallets/flask")
    assert owner == "pallets"
    assert repo == "flask"
    assert ref is None

    # Slug with @ref
    owner, repo, ref = parse_and_validate_github_url("pallets/flask@v3.0.0")
    assert owner == "pallets"
    assert repo == "flask"
    assert ref == "v3.0.0"


def test_github_url_ssrf_forbidden_schemes():
    """Verify plain HTTP and non-https schemes are rejected."""
    with pytest.raises(GitHubSSRFError, match="Insecure HTTP protocol is forbidden"):
        parse_and_validate_github_url("http://github.com/owner/repo")

    with pytest.raises(GitHubSSRFError, match="Unsupported URL scheme"):
        parse_and_validate_github_url("ftp://github.com/owner/repo")


def test_github_url_ssrf_forbidden_hosts():
    """Verify non-github hosts and loopback addresses are rejected."""
    with pytest.raises(GitHubSSRFError, match="Forbidden host"):
        parse_and_validate_github_url("https://evil.com/owner/repo")

    with pytest.raises(GitHubSSRFError, match="Forbidden host"):
        parse_and_validate_github_url("https://127.0.0.1/owner/repo")

    with pytest.raises(GitHubSSRFError, match="Forbidden host"):
        parse_and_validate_github_url("https://169.254.169.254/owner/repo")


def test_github_url_ssrf_credentials_rejected():
    """Verify URLs with embedded credentials are rejected."""
    with pytest.raises(GitHubSSRFError, match="Credentials in GitHub URLs are forbidden"):
        parse_and_validate_github_url("https://user:password@github.com/owner/repo")


def test_github_url_ssrf_odd_ports_rejected():
    """Verify URLs with non-standard ports are rejected."""
    with pytest.raises(GitHubSSRFError, match="Non-standard port"):
        parse_and_validate_github_url("https://github.com:8443/owner/repo")


def test_github_url_path_traversal_rejected():
    """Verify path traversal sequences are rejected."""
    with pytest.raises(GitHubSSRFError, match="Path traversal"):
        parse_and_validate_github_url("https://github.com/owner/../evil/repo")

    with pytest.raises(GitHubSSRFError, match="Path traversal"):
        parse_and_validate_github_url("owner/../../evil")


# ============================================================================
# GitHubClient Mocked Network Tests
# ============================================================================


def test_github_client_token_privacy():
    """Verify token is set in request headers but NEVER exposed in repr or string output."""
    client = GitHubClient(token="secret_pat_value_12345")
    assert "Authorization" in client.session.headers
    assert client.session.headers["Authorization"] == "Bearer secret_pat_value_12345"
    assert "secret_pat_value_12345" not in repr(client)
    assert "authenticated=True" in repr(client)


@patch("requests.Session.get")
def test_github_client_fetch_workflows_inline_base64(mock_get):
    """Verify fetching workflows when content is provided inline via base64 encoding."""
    raw_yaml = "name: CI\non: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps: []"
    encoded = base64.b64encode(raw_yaml.encode("utf-8")).decode("utf-8")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "name": "ci.yml",
            "type": "file",
            "encoding": "base64",
            "content": encoded,
            "download_url": None,
        }
    ]
    mock_get.return_value = mock_resp

    client = GitHubClient()
    workflows = client.fetch_workflows("pallets/flask")
    assert len(workflows) == 1
    assert workflows[0][0] == ".github/workflows/ci.yml"
    assert "name: CI" in workflows[0][1]


@patch("requests.Session.get")
def test_github_client_fetch_workflows_download_url(mock_get):
    """Verify fetching workflows when content is streamed via download_url."""
    # First request: listing
    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json.return_value = [
        {
            "name": "build.yml",
            "type": "file",
            "encoding": None,
            "content": None,
            "download_url": "https://raw.githubusercontent.com/owner/repo/main/.github/workflows/build.yml",
        }
    ]

    # Second request: downloading file stream
    file_resp = MagicMock()
    file_resp.status_code = 200
    file_resp.__enter__.return_value = file_resp
    file_resp.iter_content.return_value = [b"name: Build\non: push\njobs: {}\n"]

    mock_get.side_effect = [list_resp, file_resp]

    client = GitHubClient()
    workflows = client.fetch_workflows("owner/repo")
    assert len(workflows) == 1
    assert workflows[0][0] == ".github/workflows/build.yml"
    assert "name: Build" in workflows[0][1]


@patch("requests.Session.get")
def test_github_client_404_not_found(mock_get):
    """Verify GitHubResourceNotFoundError on 404 response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    client = GitHubClient()
    with pytest.raises(GitHubResourceNotFoundError, match="HTTP 404"):
        client.fetch_workflows("owner/nonexistent-repo")


@patch("requests.Session.get")
def test_github_client_rate_limiting(mock_get):
    """Verify GitHubRateLimitError on 403 rate limit response with reset header."""
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.headers = {
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1730000000",
    }
    mock_get.return_value = mock_resp

    client = GitHubClient()
    with pytest.raises(GitHubRateLimitError) as exc_info:
        client.fetch_workflows("owner/repo")

    assert exc_info.value.remaining == 0
    assert exc_info.value.reset_timestamp == 1730000000


@patch("requests.Session.get")
def test_github_client_auth_error(mock_get):
    """Verify GitHubAuthError on 401 response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.return_value = mock_resp

    client = GitHubClient()
    with pytest.raises(GitHubAuthError, match="HTTP 401"):
        client.fetch_workflows("owner/repo")


@patch("requests.Session.get")
def test_github_client_timeout_error(mock_get):
    """Verify GitHubNetworkError on connection timeout."""
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

    client = GitHubClient()
    with pytest.raises(GitHubNetworkError, match="timed out"):
        client.fetch_workflows("owner/repo")


@patch("requests.Session.get")
def test_github_client_oversized_file(mock_get):
    """Verify GitHubPayloadTooLargeError when downloaded content exceeds size limit."""
    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json.return_value = [
        {
            "name": "huge.yml",
            "download_url": "https://raw.githubusercontent.com/owner/repo/main/.github/workflows/huge.yml",
        }
    ]

    file_resp = MagicMock()
    file_resp.status_code = 200
    file_resp.__enter__.return_value = file_resp
    # Stream chunks totaling > 100 bytes
    file_resp.iter_content.return_value = [b"a" * 60, b"b" * 60]

    mock_get.side_effect = [list_resp, file_resp]

    # Max file size set to 100 bytes
    client = GitHubClient(max_file_size=100)
    with pytest.raises(GitHubPayloadTooLargeError, match="exceeded size limit"):
        client.fetch_workflows("owner/repo")


def test_download_url_ssrf_strict_checks():
    """Verify strict validation of download_url against unauthorized hosts and schemes."""
    # Must be HTTPS
    with pytest.raises(GitHubSSRFError, match="Insecure HTTP protocol"):
        validate_download_url("http://raw.githubusercontent.com/owner/repo/main/.github/workflows/ci.yml")

    # AWS metadata / private IP rejected
    with pytest.raises(GitHubSSRFError):
        validate_download_url("http://169.254.169.254/latest/meta-data/")

    # Arbitrary evil host rejected
    with pytest.raises(GitHubSSRFError, match="Forbidden host"):
        validate_download_url("https://evil.example/malicious.yml")

    # Lookalike domain rejected
    with pytest.raises(GitHubSSRFError, match="Forbidden host"):
        validate_download_url("https://raw.githubusercontent.com.evil.example/exploit.yml")

    # Credentials rejected
    with pytest.raises(GitHubSSRFError, match="Credentials"):
        validate_download_url("https://user:pass@raw.githubusercontent.com/owner/repo/main/ci.yml")

    # Non-standard port rejected
    with pytest.raises(GitHubSSRFError, match="Non-standard port"):
        validate_download_url("https://raw.githubusercontent.com:8443/owner/repo/main/ci.yml")

    # Valid raw URL accepted
    validate_download_url("https://raw.githubusercontent.com/owner/repo/main/.github/workflows/ci.yml")


@patch("requests.Session.get")
def test_download_url_redirect_forbidden(mock_get):
    """Verify that HTTP redirects during file download are strictly rejected."""
    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.json.return_value = [
        {
            "name": "redirect.yml",
            "download_url": "https://raw.githubusercontent.com/owner/repo/main/.github/workflows/redirect.yml",
        }
    ]

    redirect_resp = MagicMock()
    redirect_resp.status_code = 302
    redirect_resp.is_redirect = True
    redirect_resp.headers = {"Location": "http://169.254.169.254/"}
    redirect_resp.__enter__.return_value = redirect_resp

    mock_get.side_effect = [list_resp, redirect_resp]

    client = GitHubClient()
    with pytest.raises(GitHubSSRFError, match="Redirect detected"):
        client.fetch_workflows("owner/repo")


def test_github_client_token_never_logged_on_error(caplog):
    """Verify that sensitive authentication tokens are NEVER emitted in logs even on errors."""
    import logging

    secret_token = "gh_pat_super_secret_audit_token_987654321"

    with caplog.at_level(logging.DEBUG):
        client = GitHubClient(token=secret_token)

        # Trigger mock 401 error
        with patch.object(client.session, "get") as mock_get:
            mock_401 = MagicMock()
            mock_401.status_code = 401
            mock_get.return_value = mock_401

            with pytest.raises(GitHubAuthError):
                client.fetch_workflows("owner/repo")

        # Trigger network error
        with patch.object(client.session, "get", side_effect=requests.RequestException("connection drop")):
            with pytest.raises(GitHubNetworkError):
                client.fetch_workflows("owner/repo")

    # Assert secret token is nowhere in the logs
    assert secret_token not in caplog.text


def test_local_loader_path_traversal_protection(tmp_path):
    """Verify that path traversal attempts (../ segments or outside absolute paths) are rejected."""
    allowed_dir = tmp_path / "allowed_repo"
    allowed_dir.mkdir()
    wf_file = allowed_dir / "workflow.yml"
    wf_file.write_text("name: Test\non: push\njobs: {}\n", encoding="utf-8")

    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret.yml"
    outside_file.write_text("name: Outside\non: push\njobs: {}\n", encoding="utf-8")

    loader = LocalLoader(allowed_root=allowed_dir)

    # Legitimate load inside allowed root succeeds
    content = loader.load_from_file(wf_file)
    assert "name: Test" in content

    # Loading file outside allowed root fails with ValueError
    with pytest.raises(ValueError, match="Path traversal security violation"):
        loader.load_from_file(outside_file)

    # Relative path traversal using ../ fails
    relative_traversal = allowed_dir / ".." / "outside_dir" / "secret.yml"
    with pytest.raises(ValueError, match="Path traversal security violation"):
        loader.load_from_file(relative_traversal)

    # Directory loading outside allowed root fails
    with pytest.raises(ValueError, match="Path traversal security violation"):
        loader.load_from_directory(outside_dir)

