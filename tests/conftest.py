"""Shared Pytest fixtures and configuration."""

import pytest

from app import create_app
from app.api.limiter import limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure in-memory rate limiter is reset before and after every test."""
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def app():
    """Create test Flask application instance."""
    app_instance = create_app(config_name="testing")
    return app_instance


@pytest.fixture
def client(app):
    """Test client for HTTP API requests."""
    return app.test_client()
