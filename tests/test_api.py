"""Tests for REST API Routes and App Factory (Phase 7a)."""

from app.rules import default_registry


def test_health_endpoints_and_security_headers(client):
    """Verify health endpoints return 200 and include standard security headers."""
    # 1. Root health check
    res_root = client.get("/health")
    assert res_root.status_code == 200
    assert res_root.get_json()["status"] == "ok"

    # Security headers
    assert res_root.headers.get("Content-Security-Policy") == "default-src 'self'"
    assert res_root.headers.get("X-Content-Type-Options") == "nosniff"
    assert res_root.headers.get("X-Frame-Options") == "DENY"
    assert res_root.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # 2. API health check
    res_api = client.get("/api/health")
    assert res_api.status_code == 200
    assert res_api.get_json() == {
        "status": "ok",
        "app": "cicd-auditor",
        "version": "1.0.0",
    }


def test_root_index_endpoint(client):
    """Verify root / returns 200 placeholder response."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "online"
    assert "CI/CD Pipeline Security Auditor" in data["app"]


def test_get_rules_catalog_and_filtering(client):
    """Verify /api/rules returns all 30 rules and supports ?category= and ?tier= filters."""
    # All rules
    response = client.get("/api/rules")
    assert response.status_code == 200
    data = response.get_json()
    assert "rules" in data
    assert data["total"] == len(default_registry.list_rules())
    assert data["total"] == 30

    rule_ids = {r["id"] for r in data["rules"]}
    assert "R001" in rule_ids
    assert "persist-credentials" in rule_ids

    # Tier filter: extension
    res_ext = client.get("/api/rules?tier=extension")
    assert res_ext.status_code == 200
    data_ext = res_ext.get_json()
    assert data_ext["total"] == 5
    assert all(r["tier"] == "extension" for r in data_ext["rules"])
    assert "persist-credentials" in {r["id"] for r in data_ext["rules"]}

    # Tier filter: core
    res_core = client.get("/api/rules?tier=core")
    assert res_core.status_code == 200
    data_core = res_core.get_json()
    assert data_core["total"] == 25
    assert all(r["tier"] == "core" for r in data_core["rules"])

    # Category filter
    res_cred = client.get("/api/rules?category=credentials")
    assert res_cred.status_code == 200
    data_cred = res_cred.get_json()
    assert data_cred["total"] > 0
    assert all(r["category"] == "credentials" for r in data_cred["rules"])


def test_get_chains_catalog(client):
    """Verify /api/chains lists all 10 correlated attack chain definitions with narratives."""
    response = client.get("/api/chains")
    assert response.status_code == 200
    data = response.get_json()
    assert data["total"] == 10
    chains = data["chains"]

    chain_types = {c["chain_type"] for c in chains}
    expected_chains = {
        "pwn-request",
        "injection-to-exfil",
        "supply-chain-takeover",
        "deploy-blast-radius",
        "runner-persistence",
        "artifact-poisoning",
        "comment-trigger-takeover",
        "credential-persistence",
        "cache-poisoning-escalation",
        "oidc-abuse",
    }
    assert expected_chains == chain_types

    # Ensure required structure is populated
    sample = chains[0]
    assert "name" in sample
    assert "required_rules" in sample
    assert "narrative_template" in sample


def test_get_stats_endpoint(client):
    """Verify /api/stats returns system statistics including category breakdowns."""
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.get_json()
    assert "total_repos" in data
    assert "total_scans" in data
    assert "total_findings" in data
    assert "severity_counts" in data
    assert "category_counts" in data
    assert "tier_counts" in data


def test_post_scan_pasted_vulnerable_yaml(client):
    """Verify POST /api/scan with vulnerable YAML creates scan and returns 201 with findings."""
    vulnerable_yaml = """
name: Insecure CI
on:
  pull_request_target:
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: echo ${{ github.event.issue.title }}
"""
    res = client.post("/api/scan", json={"yaml": vulnerable_yaml})
    assert res.status_code == 201
    data = res.get_json()
    assert "scan_id" in data
    assert data["status"] == "completed"

    scan_id = data["scan_id"]

    # Retrieve scan via GET /api/scans/<id>
    get_res = client.get(f"/api/scans/{scan_id}")
    assert get_res.status_code == 200
    scan = get_res.get_json()
    assert scan["id"] == scan_id
    assert scan["finding_count"] >= 2
    assert scan["repo_score"] > 50.0
    assert len(scan["findings"]) == scan["finding_count"]

    # Verify findings are sorted by score descending
    scores = [f["base_score"] for f in scan["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_post_scan_pasted_safe_yaml(client):
    """Verify POST /api/scan with clean YAML yields zero findings."""
    safe_yaml = """
name: Secure CI
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
      - run: echo "All secure"
"""
    res = client.post("/api/scan", json={"yaml": safe_yaml})
    assert res.status_code == 201
    scan_id = res.get_json()["scan_id"]

    get_res = client.get(f"/api/scans/{scan_id}")
    assert get_res.status_code == 200
    scan = get_res.get_json()
    assert scan["finding_count"] == 0
    assert scan["repo_score"] == 0.0
    assert scan["risk_level"] == "LOW"


def test_post_scan_extension_rule_and_chain(client):
    """Verify POST /api/scan with extension rule (persist-credentials) and chain detection."""
    ext_yaml = """
name: Credential Leakage
on:
  push:
    branches: [main]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: acme-corp/build-helper@v3
"""
    res = client.post("/api/scan", json={"yaml": ext_yaml})
    assert res.status_code == 201
    scan_id = res.get_json()["scan_id"]

    get_res = client.get(f"/api/scans/{scan_id}")
    assert get_res.status_code == 200
    scan = get_res.get_json()

    # Find persist-credentials
    rule_ids = {f["rule_id"] for f in scan["findings"]}
    assert "persist-credentials" in rule_ids

    # Find correlated chain
    chain_types = {c["chain_type"] for c in scan["chains"]}
    assert "credential-persistence" in chain_types


def test_post_scan_malformed_yaml_returns_422(client):
    """Verify POST /api/scan with syntax-invalid YAML returns 422 Unprocessable Entity."""
    bad_yaml = """
name: Malformed YAML
on: [unclosed list
jobs:
  broken
"""
    res = client.post("/api/scan", json={"yaml": bad_yaml})
    assert res.status_code == 422
    data = res.get_json()
    assert "error" in data
    assert data["error"]["code"] == "UNPROCESSABLE_ENTITY"
    assert "Malformed YAML" in data["error"]["message"]


def test_post_scan_payload_validation_errors(client):
    """Verify validation edge cases return consistent error shapes and 400/415 status codes."""
    # 1. Non-JSON Content-Type
    res_type = client.post("/api/scan", data="plain text", content_type="text/plain")
    assert res_type.status_code == 415
    assert res_type.get_json()["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"

    # 2. Both sources provided
    res_both = client.post("/api/scan", json={"yaml": "...", "repo_url": "https://github.com/foo/bar"})
    assert res_both.status_code == 400
    assert res_both.get_json()["error"]["code"] == "MULTIPLE_SOURCES"

    # 3. Neither source provided
    res_none = client.post("/api/scan", json={})
    assert res_none.status_code == 400
    assert res_none.get_json()["error"]["code"] == "MISSING_SOURCE"

    # 4. local_path when disabled
    res_local = client.post("/api/scan", json={"local_path": "/var/workflows"})
    assert res_local.status_code == 400
    assert res_local.get_json()["error"]["code"] == "LOCAL_PATH_DISABLED"

    # 5. Empty YAML
    res_empty = client.post("/api/scan", json={"yaml": "   "})
    assert res_empty.status_code == 400
    assert res_empty.get_json()["error"]["code"] == "EMPTY_YAML"


def test_get_scan_not_found(client):
    """Verify GET /api/scans/<id> for non-existent scan returns 404."""
    res = client.get("/api/scans/scan-does-not-exist")
    assert res.status_code == 404
    data = res.get_json()
    assert data["error"]["code"] == "NOT_FOUND"


def test_get_repos_listing_and_pagination(client):
    """Verify GET /api/repos returns registered repositories with counts and handles pagination."""
    res_empty = client.get("/api/repos")
    assert res_empty.status_code == 200
    assert res_empty.get_json() == {"repos": [], "total": 0}

    # Trigger a scan to create a repository record
    yaml_content = "name: TestCI\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo 1\n"
    scan_res = client.post("/api/scan", json={"yaml": yaml_content})
    assert scan_res.status_code == 201

    res_populated = client.get("/api/repos")
    assert res_populated.status_code == 200
    data = res_populated.get_json()
    assert data["total"] == 1
    repo = data["repos"][0]
    assert "pasted-yaml:" in repo["name"]
    assert repo["scan_count"] == 1
    assert repo["latest_scan_at"] is not None
    assert "latest_score" in repo

    # Test invalid limit and offset return 400
    res_bad_limit = client.get("/api/repos?limit=invalid")
    assert res_bad_limit.status_code == 400
    assert res_bad_limit.get_json()["error"]["code"] == "BAD_REQUEST"


def test_get_repo_history_endpoints(client):
    """Verify GET /api/repos/<id>/history returns chronological scan history or 404."""
    # 404 for unknown repo
    res_404 = client.get("/api/repos/repo-nonexistent/history")
    assert res_404.status_code == 404
    assert res_404.get_json()["error"]["code"] == "NOT_FOUND"

    # Add a scan
    yaml_content = "name: HistoryCI\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo 1\n"
    scan_res = client.post("/api/scan", json={"yaml": yaml_content})
    assert scan_res.status_code == 201
    scan_id = scan_res.get_json()["scan_id"]

    scan_detail = client.get(f"/api/scans/{scan_id}").get_json()
    repo_id = scan_detail["repo_id"]

    # Retrieve history
    res_hist = client.get(f"/api/repos/{repo_id}/history")
    assert res_hist.status_code == 200
    hist_data = res_hist.get_json()
    assert hist_data["repo_id"] == repo_id
    assert hist_data["total"] >= 1
    assert hist_data["history"][0]["scan_id"] == scan_id

    # Invalid limit parameter returns 400
    res_bad_param = client.get(f"/api/repos/{repo_id}/history?limit=invalid")
    assert res_bad_param.status_code == 400
    assert res_bad_param.get_json()["error"]["code"] == "BAD_REQUEST"


def test_compare_scans_endpoints_and_guards(client):
    """Verify scan comparison parameter validation, 404s, and cross-repo guards."""
    # Missing parameters returns 400
    res_missing = client.get("/api/repos/repo-1/compare")
    assert res_missing.status_code == 400
    assert res_missing.get_json()["error"]["code"] == "MISSING_COMPARISON_TARGETS"

    res_missing_b = client.get("/api/repos/repo-1/compare?a=scan-1")
    assert res_missing_b.status_code == 400
    assert res_missing_b.get_json()["error"]["code"] == "MISSING_COMPARISON_TARGETS"

    # Non-existent repository returns 404
    res_no_repo = client.get("/api/repos/repo-does-not-exist/compare?a=scan-1&b=scan-2")
    assert res_no_repo.status_code == 404
    assert res_no_repo.get_json()["error"]["code"] == "NOT_FOUND"

    # Create two scans in different repos (different pasted YAML content -> different synthetic repos)
    scan_1_res = client.post(
        "/api/scan",
        json={"yaml": "name: RepoA\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo A\n"},
    )
    scan_2_res = client.post(
        "/api/scan",
        json={"yaml": "name: RepoB\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo B\n"},
    )
    scan_1_id = scan_1_res.get_json()["scan_id"]
    scan_2_id = scan_2_res.get_json()["scan_id"]

    repo_1_id = client.get(f"/api/scans/{scan_1_id}").get_json()["repo_id"]
    repo_2_id = client.get(f"/api/scans/{scan_2_id}").get_json()["repo_id"]
    assert repo_1_id != repo_2_id

    # Non-existent baseline scan returns 404
    res_no_scan_a = client.get(f"/api/repos/{repo_1_id}/compare?a=scan-fake&b={scan_1_id}")
    assert res_no_scan_a.status_code == 404
    assert res_no_scan_a.get_json()["error"]["code"] == "NOT_FOUND"

    # Non-existent target scan returns 404
    res_no_scan_b = client.get(f"/api/repos/{repo_1_id}/compare?a={scan_1_id}&b=scan-fake")
    assert res_no_scan_b.status_code == 404
    assert res_no_scan_b.get_json()["error"]["code"] == "NOT_FOUND"

    # Cross-repo comparison attempt: comparing scan_2 under repo_1 must return 400
    res_cross = client.get(f"/api/repos/{repo_1_id}/compare?a={scan_1_id}&b={scan_2_id}")
    assert res_cross.status_code == 400
    assert res_cross.get_json()["error"]["code"] == "CROSS_REPO_COMPARISON_NOT_ALLOWED"


def test_ssrf_and_malicious_urls(client):
    """Verify SSRF, non-GitHub hosts, private IP ranges, and malformed URLs are rejected."""
    malicious_urls = [
        "http://169.254.169.254/latest/meta-data",
        "http://localhost:8080/repo",
        "http://127.0.0.1/evil",
        "file:///etc/passwd",
        "ftp://github.com/org/repo",
        "https://gitlab.com/org/repo",
        "https://evil-github.com/org/repo",
        "https://github.evil.com/org/repo",
        "https://admin:password@github.com/org/repo",
        "https://github.com/org/repo/../../etc",
    ]
    for url in malicious_urls:
        res = client.post("/api/scan", json={"repo_url": url})
        assert res.status_code == 400, f"Expected 400 for {url}, got {res.status_code}"
        assert res.get_json()["error"]["code"] == "INVALID_URL"


def test_payload_too_large(client):
    """Verify oversized HTTP bodies (>2MB) and oversized YAML (>1MB) return 413."""
    # 1. Oversized YAML payload (> 1MB) within valid JSON
    huge_yaml = "a" * (1024 * 1024 + 10)
    res_yaml = client.post("/api/scan", json={"yaml": huge_yaml})
    assert res_yaml.status_code == 413
    assert res_yaml.get_json()["error"]["code"] == "PAYLOAD_TOO_LARGE"

    # 2. Oversized HTTP body (> 2MB MAX_CONTENT_LENGTH)
    huge_body = "x" * (2 * 1024 * 1024 + 500)
    res_body = client.post("/api/scan", data=huge_body, content_type="application/json")
    assert res_body.status_code == 413
    assert res_body.get_json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_rate_limiting_enforcement(client, app):
    """Verify client IP rate limiter enforces limit, sends Retry-After header, and recovers after reset."""
    from app.api.limiter import limiter

    app.config["RATELIMIT_PER_MINUTE"] = 5
    limiter.reset()

    # First 5 requests within limit must succeed
    for _ in range(5):
        res = client.get("/api/health")
        assert res.status_code == 200

    # 6th request must be rate limited
    res_limited = client.get("/api/health")
    assert res_limited.status_code == 429
    assert res_limited.get_json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in res_limited.headers
    assert int(res_limited.headers["Retry-After"]) >= 1

    # Reset limiter and verify subsequent request succeeds
    limiter.reset()
    res_after_reset = client.get("/api/health")
    assert res_after_reset.status_code == 200


def test_upstream_github_errors_handling(client, monkeypatch):
    """Verify upstream GitHub API errors (404, rate limit, timeout) map to appropriate 502 status codes."""
    import app.api.routes as routes_mod
    from app.ingest.github_client import (
        GitHubNetworkError,
        GitHubRateLimitError,
        GitHubResourceNotFoundError,
    )

    # 1. 404 Upstream -> 502 UPSTREAM_NOT_FOUND
    def mock_not_found(*args, **kwargs):
        raise GitHubResourceNotFoundError("Repository 'octocat/missing' does not exist.")

    monkeypatch.setattr(routes_mod, "run_scan", mock_not_found)
    res_404 = client.post("/api/scan", json={"repo_url": "https://github.com/octocat/missing"})
    assert res_404.status_code == 502
    assert res_404.get_json()["error"]["code"] == "UPSTREAM_NOT_FOUND"

    # 2. Rate Limit Upstream -> 502 UPSTREAM_ERROR
    def mock_rate_limit(*args, **kwargs):
        raise GitHubRateLimitError("GitHub API rate limit exceeded.")

    monkeypatch.setattr(routes_mod, "run_scan", mock_rate_limit)
    res_rate = client.post("/api/scan", json={"repo_url": "https://github.com/octocat/repo"})
    assert res_rate.status_code == 502
    assert res_rate.get_json()["error"]["code"] == "UPSTREAM_ERROR"

    # 3. Network / Timeout Error -> 502 UPSTREAM_ERROR
    def mock_network_err(*args, **kwargs):
        raise GitHubNetworkError("Connection timed out.")

    monkeypatch.setattr(routes_mod, "run_scan", mock_network_err)
    res_net = client.post("/api/scan", json={"repo_url": "https://github.com/octocat/repo"})
    assert res_net.status_code == 502
    assert res_net.get_json()["error"]["code"] == "UPSTREAM_ERROR"


def test_request_logging_redacts_tokens_and_omits_yaml(client, caplog):
    """Verify request logging redacts authorization tokens, query secrets, and never dumps raw YAML bodies."""
    import logging

    secret_auth_token = "ghp_super_secret_auth_token_99999"
    secret_query_token = "query_secret_token_88888"
    sensitive_yaml_marker = "TOTALLY_SECRET_WORKFLOW_NAME_77777"

    with caplog.at_level(logging.INFO):
        response = client.post(
            f"/api/scan?token={secret_query_token}",
            headers={
                "Authorization": f"Bearer {secret_auth_token}",
                "X-GitHub-Token": secret_auth_token,
            },
            json={
                "yaml": f"name: {sensitive_yaml_marker}\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
            },
        )
        assert response.status_code == 201

    log_output = caplog.text
    # Sensitive tokens and YAML bodies must NEVER appear in logs
    assert secret_auth_token not in log_output
    assert secret_query_token not in log_output
    assert sensitive_yaml_marker not in log_output

    # Sanitized markers must be logged
    assert "[REDACTED]" in log_output
    assert "yaml_bytes=" in log_output


def test_api_end_to_end_flow(client, monkeypatch):
    """End-to-end integration test: scan -> get scan -> list repos -> repo history -> compare scans."""
    import app.ingest.github_client as gh_client_mod

    # Vulnerable workflow content for scan 1
    vulnerable_content = """
name: CI
on:
  pull_request_target:
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: echo ${{ github.event.issue.title }}
"""
    # Remediated workflow content for scan 2
    fixed_content = """
name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b
      - run: echo "Safe title"
"""

    current_content = [vulnerable_content]

    def mock_fetch(*args, **kwargs):
        return [(".github/workflows/ci.yml", current_content[0])]

    monkeypatch.setattr(gh_client_mod.GitHubClient, "fetch_workflows", mock_fetch)

    # 1. Trigger initial scan (vulnerable)
    res1 = client.post("/api/scan", json={"repo_url": "https://github.com/test-org/test-repo"})
    assert res1.status_code == 201
    scan1_id = res1.get_json()["scan_id"]

    # 2. Inspect scan 1 details
    scan1 = client.get(f"/api/scans/{scan1_id}").get_json()
    assert scan1["finding_count"] >= 2
    repo_id = scan1["repo_id"]
    assert scan1["repo_name"] == "test-org/test-repo"

    # 3. Trigger second scan (fixed) on the same repo
    current_content[0] = fixed_content
    res2 = client.post("/api/scan", json={"repo_url": "https://github.com/test-org/test-repo"})
    assert res2.status_code == 201
    scan2_id = res2.get_json()["scan_id"]

    # 4. List repositories: ensure repo has scan_count == 2
    repos_res = client.get("/api/repos")
    assert repos_res.status_code == 200
    repos_list = repos_res.get_json()["repos"]
    target_repo = next(r for r in repos_list if r["id"] == repo_id)
    assert target_repo["scan_count"] == 2
    assert target_repo["name"] == "test-org/test-repo"

    # 5. Check chronological repository history
    hist_res = client.get(f"/api/repos/{repo_id}/history")
    assert hist_res.status_code == 200
    hist_data = hist_res.get_json()
    assert hist_data["total"] == 2
    assert hist_data["history"][0]["scan_id"] == scan1_id
    assert hist_data["history"][1]["scan_id"] == scan2_id

    # 6. Compare scan 1 (baseline) and scan 2 (fixed)
    comp_res = client.get(f"/api/repos/{repo_id}/compare?a={scan1_id}&b={scan2_id}")
    assert comp_res.status_code == 200
    diff = comp_res.get_json()
    assert diff["score_delta"] < 0  # Risk score decreased
    assert diff["fixed_count"] >= 2
    assert diff["new_count"] == 0
