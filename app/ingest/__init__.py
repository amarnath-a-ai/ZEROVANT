"""Ingestion module for loading workflows from GitHub or local filesystem."""

from app.ingest.github_client import GitHubClient
from app.ingest.local_loader import LocalLoader

__all__ = ["GitHubClient", "LocalLoader"]

