"""Read-only GitHub REST API client for fetching workflow definitions."""

import base64
import logging
import os
import re
from typing import Any
from urllib.parse import unquote, urlparse

import requests

logger = logging.getLogger(__name__)

# Strict identifier regex for GitHub owner and repository names
GITHUB_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")
DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB
DEFAULT_MAX_DIR_SIZE = 2 * 1024 * 1024   # 2 MB


class GitHubClientError(Exception):
    """Base exception for all GitHub API client errors."""
    pass


class GitHubSSRFError(GitHubClientError, ValueError):
    """Raised when a repository URL violates SSRF security boundaries."""
    pass


class GitHubResourceNotFoundError(GitHubClientError):
    """Raised when repository or .github/workflows directory is not found (HTTP 404)."""
    pass


class GitHubRateLimitError(GitHubClientError):
    """Raised when GitHub API rate limits are exceeded (HTTP 403/429)."""

    def __init__(self, message: str, reset_timestamp: int | None = None, remaining: int = 0):
        super().__init__(message)
        self.reset_timestamp = reset_timestamp
        self.remaining = remaining


class GitHubAuthError(GitHubClientError):
    """Raised when authentication credentials are invalid or missing permissions (HTTP 401)."""
    pass


class GitHubNetworkError(GitHubClientError):
    """Raised on network connection errors or timeouts."""
    pass


class GitHubPayloadTooLargeError(GitHubClientError):
    """Raised when an API response exceeds allowed size limits."""
    pass


def parse_and_validate_github_url(repo_input: str) -> tuple[str, str, str | None]:
    """Validate and parse a GitHub repository URL or slug into (owner, repo, ref).

    Enforces strict SSRF protection:
      - Protocol must be HTTPS
      - Host must strictly be github.com (case-insensitive)
      - No credentials allowed in URL
      - No custom/odd ports allowed (only standard 443)
      - Path traversal (.. or %2e%2e) is strictly prohibited
      - Validates owner and repository names against safe alphanumeric patterns
    """
    if not repo_input or not isinstance(repo_input, str):
        raise ValueError("Repository input must be a non-empty string")

    raw = repo_input.strip()

    # Reject plain unencrypted HTTP immediately
    if raw.lower().startswith("http://"):
        raise GitHubSSRFError(
            "Insecure HTTP protocol is forbidden. Only encrypted HTTPS (https://github.com) is permitted."
        )

    ref: str | None = None

    if "://" in raw:
        parsed = urlparse(raw)

        if parsed.scheme.lower() != "https":
            raise GitHubSSRFError(f"Unsupported URL scheme '{parsed.scheme}'. Only HTTPS is permitted.")

        if parsed.username or parsed.password:
            raise GitHubSSRFError("Credentials in GitHub URLs are forbidden.")

        hostname = (parsed.hostname or "").lower()
        if hostname != "github.com":
            raise GitHubSSRFError(
                f"Forbidden host '{hostname}'. Only 'github.com' is allowed (SSRF prevention)."
            )

        if parsed.port is not None and parsed.port != 443:
            raise GitHubSSRFError(f"Non-standard port '{parsed.port}' is forbidden.")

        # Decode path to detect URL-encoded path traversal attacks
        decoded_path = unquote(parsed.path)
        if ".." in decoded_path or "/." in decoded_path:
            raise GitHubSSRFError("Path traversal sequences are strictly forbidden.")

        path_clean = decoded_path.strip("/")
        parts = [p for p in path_clean.split("/") if p]

        if len(parts) < 2:
            raise ValueError(f"URL does not specify a valid repository path: {raw}")

        owner = parts[0]
        repo_name = parts[1]

        # Support URLs like https://github.com/owner/repo/tree/branch-name
        if len(parts) >= 4 and parts[2] in ("tree", "blob"):
            ref = "/".join(parts[3:])

    else:
        # Format: owner/repo or owner/repo@ref
        if ".." in raw or "/" not in raw:
            raise GitHubSSRFError("Path traversal or invalid repository format is forbidden.")

        if "@" in raw:
            slug, ref_candidate = raw.split("@", 1)
            ref = ref_candidate.strip() or None
        else:
            slug = raw

        parts = slug.strip("/").split("/")
        if len(parts) != 2:
            raise ValueError(f"Expected repository slug in 'owner/repo' format, got '{raw}'")

        owner, repo_name = parts[0], parts[1]

    # Clean .git suffix if present
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    if not GITHUB_IDENTIFIER_PATTERN.match(owner):
        raise ValueError(f"Invalid characters in repository owner name: '{owner}'")
    if not GITHUB_IDENTIFIER_PATTERN.match(repo_name):
        raise ValueError(f"Invalid characters in repository name: '{repo_name}'")

    return owner, repo_name, ref


def validate_download_url(download_url: str) -> None:
    """Validate that download_url is strictly from raw.githubusercontent.com via HTTPS.

    Prevents SSRF attacks where a malicious or compromised API response directs the client
    to download arbitrary internal/external resources, lookalike domains, or redirects
    to unauthorized endpoints.
    """
    if not download_url or not isinstance(download_url, str):
        raise GitHubSSRFError("download_url must be a non-empty string.")

    raw = download_url.strip()
    if raw.lower().startswith("http://"):
        raise GitHubSSRFError(
            "Insecure HTTP protocol is forbidden in download_url. Only HTTPS is permitted."
        )

    parsed = urlparse(raw)
    if parsed.scheme.lower() != "https":
        raise GitHubSSRFError(
            f"Unsupported scheme '{parsed.scheme}' in download_url. Only HTTPS is permitted."
        )

    if parsed.username or parsed.password:
        raise GitHubSSRFError("Credentials in download_url are strictly forbidden.")

    hostname = (parsed.hostname or "").lower()
    if hostname != "raw.githubusercontent.com":
        raise GitHubSSRFError(
            f"Forbidden host '{hostname}' in download_url. Only 'raw.githubusercontent.com' is allowed."
        )

    if parsed.port is not None and parsed.port != 443:
        raise GitHubSSRFError(f"Non-standard port '{parsed.port}' in download_url is forbidden.")


class GitHubClient:
    """Read-only GitHub REST API client for fetching workflow definitions."""

    def __init__(
        self,
        token: str | None = None,
        base_url: str = "https://api.github.com",
        timeout: float = 10.0,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        session: requests.Session | None = None,
    ):
        self._token = token or os.environ.get("GITHUB_TOKEN", "")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.session = session or requests.Session()

        # Set default headers
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "cicd-auditor-static-scanner",
        })
        if self._token:
            self.session.headers["Authorization"] = f"Bearer {self._token}"

    def __repr__(self) -> str:
        # Never expose authentication tokens in string representation
        has_token = bool(self._token)
        return f"<GitHubClient base_url='{self.base_url}' authenticated={has_token}>"

    def fetch_workflows(
        self, repo_input: str, ref: str | None = None
    ) -> list[tuple[str, str]]:
        """Fetch all workflow YAML files from .github/workflows directory of a repository.

        Args:
            repo_input: Full GitHub URL or 'owner/repo' slug.
            ref: Optional git branch or tag reference (overrides ref in URL).

        Returns:
            List of (file_path, raw_yaml_content) tuples.

        Raises:
            GitHubSSRFError: If the repository URL violates SSRF constraints.
            GitHubResourceNotFoundError: If repository or workflows directory does not exist.
            GitHubRateLimitError: If GitHub API rate limit is exceeded.
            GitHubAuthError: If authentication fails.
            GitHubNetworkError: If connection times out or fails.
            GitHubPayloadTooLargeError: If response exceeds maximum byte limits.
        """
        owner, repo, url_ref = parse_and_validate_github_url(repo_input)
        target_ref = ref or url_ref

        api_url = f"{self.base_url}/repos/{owner}/{repo}/contents/.github/workflows"
        params = {"ref": target_ref} if target_ref else {}

        logger.info("Listing workflows for %s/%s (ref: %s)", owner, repo, target_ref)

        resp = self._make_request(api_url, params=params)

        if resp.status_code == 404:
            raise GitHubResourceNotFoundError(
                f"Repository '{owner}/{repo}' or directory '.github/workflows' not found (HTTP 404)."
            )

        self._check_response_status(resp)

        try:
            items = resp.json()
        except ValueError as exc:
            raise GitHubClientError(f"Failed to parse GitHub API JSON response: {exc}") from exc

        if not isinstance(items, list):
            raise GitHubResourceNotFoundError(
                f"Path '.github/workflows' in '{owner}/{repo}' is not a directory."
            )

        workflows: list[tuple[str, str]] = []

        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            if not (name.endswith(".yml") or name.endswith(".yaml")):
                continue

            file_path = f".github/workflows/{name}"

            # If content is present directly in the API response (base64 encoded)
            if item.get("encoding") == "base64" and item.get("content"):
                try:
                    content_bytes = base64.b64decode(item["content"])
                    if len(content_bytes) > self.max_file_size:
                        raise GitHubPayloadTooLargeError(
                            f"Workflow file '{name}' ({len(content_bytes)} bytes) exceeds size limit ({self.max_file_size} bytes)"
                        )
                    workflows.append((file_path, content_bytes.decode("utf-8", errors="replace")))
                    continue
                except Exception as b64_err:
                    logger.debug("Failed base64 inline decode for %s: %s", name, b64_err)

            # Fall back to download_url
            download_url = item.get("download_url")
            if download_url:
                content = self._download_file_content(download_url, name)
                workflows.append((file_path, content))

        return workflows

    def _make_request(self, url: str, params: dict[str, Any] | None = None) -> requests.Response:
        """Execute HTTP GET request with timeout and error handling."""
        try:
            return self.session.get(url, params=params, timeout=self.timeout)
        except (requests.Timeout, requests.exceptions.Timeout) as exc:
            raise GitHubNetworkError(f"GitHub API request timed out after {self.timeout}s: {exc}") from exc
        except requests.RequestException as exc:
            raise GitHubNetworkError(f"GitHub API network connection error: {exc}") from exc

    def _download_file_content(self, download_url: str, filename: str) -> str:
        """Download raw file content with streaming size-limit enforcement and SSRF protection."""
        validate_download_url(download_url)
        try:
            with self.session.get(
                download_url, stream=True, timeout=self.timeout, allow_redirects=False
            ) as resp:
                if (resp.is_redirect is True) or (300 <= resp.status_code < 400):
                    raise GitHubSSRFError(
                        f"Redirect detected when downloading '{filename}' from {download_url} (HTTP {resp.status_code}). Redirects are forbidden."
                    )
                self._check_response_status(resp)

                content_chunks = []
                total_bytes = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    total_bytes += len(chunk)
                    if total_bytes > self.max_file_size:
                        raise GitHubPayloadTooLargeError(
                            f"Workflow file '{filename}' exceeded size limit of {self.max_file_size} bytes"
                        )
                    content_chunks.append(chunk)

                return b"".join(content_chunks).decode("utf-8", errors="replace")
        except (requests.Timeout, requests.exceptions.Timeout) as exc:
            raise GitHubNetworkError(f"Download timed out for '{filename}': {exc}") from exc
        except requests.RequestException as exc:
            raise GitHubNetworkError(f"Download failed for '{filename}': {exc}") from exc

    def _check_response_status(self, resp: requests.Response) -> None:
        """Check HTTP status codes and raise specific structured exceptions."""
        if resp.status_code == 401:
            raise GitHubAuthError("GitHub authentication failed (HTTP 401). Verify GITHUB_TOKEN.")

        if resp.status_code in (403, 429):
            remaining = int(resp.headers.get("X-RateLimit-Remaining", "0") or 0)
            reset_ts = resp.headers.get("X-RateLimit-Reset")
            reset_int = int(reset_ts) if reset_ts and reset_ts.isdigit() else None
            msg = f"GitHub API rate limit exceeded (HTTP {resp.status_code}). Reset timestamp: {reset_int}"
            raise GitHubRateLimitError(msg, reset_timestamp=reset_int, remaining=remaining)

        if resp.status_code >= 400:
            raise GitHubClientError(
                f"GitHub API returned error status {resp.status_code}: {resp.text[:200]}"
            )
