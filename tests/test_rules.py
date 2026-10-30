"""Tests for Rule Engine and 10 Security Rules (Phase 2)."""

from app.rules import ALL_RULES, default_registry


def test_all_ten_rules_registered():
    """Verify all 10 security rules are defined and registered."""
    registered = default_registry.list_rules()
    assert len(registered) == 10
    assert len(ALL_RULES) == 10

    expected_ids = {
        "R001", "R002", "R003", "R004", "R005",
        "R006", "R007", "R008", "R009", "R010"
    }
    actual_ids = {r.id for r in registered}
    assert actual_ids == expected_ids

