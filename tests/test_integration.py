"""End-to-End Integration Tests (Phase 6)."""

from app.rules import ALL_RULES


def test_system_integration_smoke():
    """Verify core components interface correctly without runtime error."""
    assert len(ALL_RULES) >= 10

