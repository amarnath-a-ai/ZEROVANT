"""Tests for REST API Routes (Phase 5)."""


def test_health_check(client):
    """Verify health check endpoint returns 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "app": "cicd-auditor"}


def test_get_rules_endpoint(client):
    """Verify /api/rules lists all 10 registered rules."""
    response = client.get("/api/rules")
    assert response.status_code == 200
    data = response.get_json()
    assert "rules" in data
    assert data["total"] >= 10
    rule_ids = {r["id"] for r in data["rules"]}
    assert "R001" in rule_ids
    assert "R003" in rule_ids

