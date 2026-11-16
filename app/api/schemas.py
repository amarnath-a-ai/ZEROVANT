"""Validation schemas and functions for REST API requests and responses."""

from typing import Any

from app.ingest.github_client import GitHubSSRFError, parse_and_validate_github_url


class ValidationError(Exception):
    """Raised when an API request fails schema validation."""

    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def validate_scan_request(
    data: Any,
    allow_local_path: bool = False,
    max_yaml_size: int = 1_048_576,
) -> dict[str, Any]:
    """Validate scan initiation payload for POST /api/scan.

    Enforces:
    - JSON object input
    - Exactly one source: repo_url or yaml (local_path disabled by default)
    - URL safety (no SSRF / private IP / embedded credentials)
    - YAML size limit (default 1 MB)
    """
    if not isinstance(data, dict):
        raise ValidationError("BAD_REQUEST", "Request body must be a JSON object.", 400)

    # Validate individual fields if present
    if "yaml" in data and not str(data["yaml"]).strip():
        raise ValidationError("EMPTY_YAML", "'yaml' content cannot be empty.", 400)

    if "repo_url" in data and not str(data["repo_url"]).strip():
        raise ValidationError("INVALID_URL", "'repo_url' cannot be empty.", 400)

    has_repo = "repo_url" in data and bool(str(data["repo_url"]).strip())
    has_yaml = "yaml" in data and bool(str(data["yaml"]).strip())
    has_local = "local_path" in data and bool(str(data["local_path"]).strip())

    if has_local and not allow_local_path:
        raise ValidationError(
            "LOCAL_PATH_DISABLED",
            "Local path ingestion is disabled in web API mode to prevent unauthorized local file access.",
            400,
        )

    sources_count = sum([has_repo, has_yaml, has_local if allow_local_path else 0])
    if sources_count == 0:
        raise ValidationError(
            "MISSING_SOURCE",
            "Must provide exactly one source: 'repo_url' or 'yaml'.",
            400,
        )
    if sources_count > 1:
        raise ValidationError(
            "MULTIPLE_SOURCES",
            "Must provide exactly one source: 'repo_url' or 'yaml'.",
            400,
        )

    if has_repo:
        repo_url = data["repo_url"]
        if not isinstance(repo_url, str):
            raise ValidationError("INVALID_URL", "'repo_url' must be a string.", 400)
        try:
            owner, repo, ref_from_url = parse_and_validate_github_url(repo_url.strip())
        except (GitHubSSRFError, ValueError) as exc:
            raise ValidationError("INVALID_URL", f"Invalid GitHub URL: {exc}", 400) from exc

        ref = data.get("ref") or ref_from_url or "main"
        return {
            "source_type": "github_repo",
            "source": f"{owner}/{repo}",
            "repo_url": repo_url.strip(),
            "ref": ref,
        }

    if has_yaml:
        yaml_content = data["yaml"]
        if not isinstance(yaml_content, str):
            raise ValidationError("INVALID_YAML", "'yaml' must be a string.", 400)
        if len(yaml_content.encode("utf-8")) > max_yaml_size:
            raise ValidationError(
                "PAYLOAD_TOO_LARGE",
                f"YAML content exceeds maximum permitted size of {max_yaml_size} bytes.",
                413,
            )

        return {
            "source_type": "pasted_yaml",
            "source": yaml_content,
            "ref": data.get("ref", "inline"),
        }

    if has_local and allow_local_path:
        return {
            "source_type": "local_directory",
            "source": data["local_path"],
            "ref": data.get("ref", "local"),
        }

    raise ValidationError("BAD_REQUEST", "Unable to validate scan source.", 400)
