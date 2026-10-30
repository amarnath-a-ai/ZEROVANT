"""Shared Pytest fixtures and configuration."""

import pytest

from app import create_app


@pytest.fixture
def app():
    """Create test Flask application instance."""
    app_instance = create_app(config_name="testing")
    return app_instance


@pytest.fixture
def client(app):
    """Test client for HTTP API requests."""
    return app.test_client()
