"""Validation schemas for API requests and responses."""

SCAN_REQUEST_SCHEMA = {
    "type": "object",
    "properties": {
        "target_type": {
            "type": "string",
            "enum": ["github_repo", "pasted_yaml", "local_directory"],
        },
        "content": {"type": "string"},
        "repo": {"type": "string"},
        "directory": {"type": "string"},
    },
    "required": ["target_type"],
}

