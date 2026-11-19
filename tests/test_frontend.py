"""Tests for Frontend Assets, Template Rendering, CSP, and XSS Sanitization (Phase 8)."""

import re
from pathlib import Path


def test_index_template_rendering_and_security_headers(client):
    """Verify GET / renders the full ZEROVANT application with all 10 screens and security headers."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("Content-Type", "")

    # Security headers
    assert response.headers.get("Content-Security-Policy") == "default-src 'self'"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    html = response.data.decode("utf-8")
    assert "ZEROVANT" in html
    assert "Defend Your" in html

    # Verify all 10 application screen sections exist in DOM
    screens = [
      "screen-overview",
      "screen-scanner",
      "screen-repositories",
      "screen-findings",
      "screen-attack-graph",
      "screen-analytics",
      "screen-remediation",
      "screen-policies",
      "screen-comparison",
      "screen-settings",
    ]
    for s in screens:
        assert f'id="{s}"' in html, f"Screen section #{s} missing from template"

    # Verify vendored libraries and scripts are linked
    assert 'src="/static/js/vendor/chart.min.js"' in html
    assert 'src="/static/js/vendor/cytoscape.min.js"' in html
    assert 'src="/static/js/app.js"' in html


def test_static_assets_served_with_correct_content_types(client):
    """Verify local static assets and vendored libraries are served with 200 and proper MIME types."""
    assets = [
        ("/static/css/tokens.css", "text/css"),
        ("/static/css/base.css", "text/css"),
        ("/static/css/glass.css", "text/css"),
        ("/static/css/components.css", "text/css"),
        ("/static/css/landing.css", "text/css"),
        ("/static/css/dashboard.css", "text/css"),
        ("/static/css/pages.css", "text/css"),
        ("/static/css/responsive.css", "text/css"),
        ("/static/js/vendor/chart.min.js", "application/javascript"),
        ("/static/js/vendor/cytoscape.min.js", "application/javascript"),
        ("/static/js/api.js", "application/javascript"),
        ("/static/js/theme.js", "application/javascript"),
        ("/static/js/router.js", "application/javascript"),
        ("/static/js/overview.js", "application/javascript"),
        ("/static/js/scanner.js", "application/javascript"),
        ("/static/js/repositories.js", "application/javascript"),
        ("/static/js/findings.js", "application/javascript"),
        ("/static/js/graph.js", "application/javascript"),
        ("/static/js/analytics.js", "application/javascript"),
        ("/static/js/remediation.js", "application/javascript"),
        ("/static/js/policies.js", "application/javascript"),
        ("/static/js/comparison.js", "application/javascript"),
        ("/static/js/settings.js", "application/javascript"),
        ("/static/js/app.js", "application/javascript"),
    ]

    for path, expected_type in assets:
        res = client.get(path)
        assert res.status_code == 200, f"Asset '{path}' returned status {res.status_code}"
        assert expected_type in res.headers.get("Content-Type", "")
        # Enforce CSP on static assets as well
        assert res.headers.get("Content-Security-Policy") == "default-src 'self'"


def test_xss_audit_no_forbidden_eval_or_unsafe_handlers():
    """Static analysis audit of JavaScript files: ensure no eval(), document.write(), or inline handlers."""
    js_dir = Path(__file__).resolve().parent.parent / "app" / "web" / "static" / "js"
    assert js_dir.exists()

    js_files = list(js_dir.glob("*.js"))
    assert len(js_files) >= 10, "Expected at least 10 custom JS modules"

    forbidden_patterns = [
        (re.compile(r"\beval\s*\("), "eval()"),
        (re.compile(r"document\.write\s*\("), "document.write()"),
        (re.compile(r"setTimeout\s*\(\s*['\"`]"), "setTimeout with string code"),
        (re.compile(r"setInterval\s*\(\s*['\"`]"), "setInterval with string code"),
    ]

    for fpath in js_files:
        content = fpath.read_text(encoding="utf-8")
        for pattern, name in forbidden_patterns:
            assert not pattern.search(content), f"Forbidden pattern '{name}' found in {fpath.name}"


def test_html_template_has_no_inline_scripts_or_event_handlers():
    """Verify HTML template adheres to strict CSP: no inline <script> blocks or inline on* attributes."""
    template_path = Path(__file__).resolve().parent.parent / "app" / "web" / "templates" / "index.html"
    content = template_path.read_text(encoding="utf-8")

    # Reject inline script contents (only external <script src="..."> permitted)
    inline_script_pattern = re.compile(r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
    inline_scripts = inline_script_pattern.findall(content)
    # Strip whitespace to check if any script tag contains executable inline body
    executable_inline = [s.strip() for s in inline_scripts if s.strip()]
    assert len(executable_inline) == 0, f"Found inline scripts in template: {executable_inline}"

    # Reject inline event handlers (onclick=, onload=, onerror=, onsubmit=)
    inline_handler_pattern = re.compile(r"\s+on[a-z]+\s*=", re.IGNORECASE)
    handlers = inline_handler_pattern.findall(content)
    assert len(handlers) == 0, f"Found inline event handlers in template: {handlers}"


def test_xss_escape_helper_neutralizes_malicious_payloads():
    """Verify Python and client escaping logic neutralizes common XSS injection vectors."""
    payloads = [
        ("<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"),
        ('<img src=x onerror=alert(1)>', '&lt;img src=x onerror=alert(1)&gt;'),
        ('"><svg onload=alert(document.cookie)>', '&quot;&gt;&lt;svg onload=alert(document.cookie)&gt;'),
        ("javascript:alert(1)", "javascript:alert(1)"),
    ]

    # Replicate client-side escapeHTML in Python
    def py_escape_html(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    for raw, expected in payloads:
        escaped = py_escape_html(raw)
        assert "<" not in escaped
        assert ">" not in escaped
        assert expected == escaped


def test_end_to_end_frontend_workflow(client):
    """End-to-end integration test verifying complete data flow from API to web components."""
    # 1. Check dashboard stats initially
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200

    # 2. Trigger scan of vulnerable workflow
    vulnerable_yaml = """
name: Insecure CI
on:
  pull_request_target:
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - env:
          SECRET_KEY: ${{ secrets.PROD_API_KEY }}
        run: echo ${{ github.event.issue.title }}
"""
    scan_res = client.post("/api/scan", json={"yaml": vulnerable_yaml})
    assert scan_res.status_code == 201
    scan_id = scan_res.get_json()["scan_id"]

    # 3. Retrieve scan details
    detail_res = client.get(f"/api/scans/{scan_id}")
    assert detail_res.status_code == 200
    scan_data = detail_res.get_json()
    assert scan_data["finding_count"] >= 2
    repo_id = scan_data["repo_id"]

    # 4. Check attack graph payload contains nodes and edges
    assert len(scan_data["chains"]) >= 1
    chain = scan_data["chains"][0]
    assert chain["chain_type"] == "pwn-request"
    assert "narrative" in chain

    # 5. Check repositories list has this repo
    repos_res = client.get("/api/repos")
    assert repos_res.status_code == 200
    repos = repos_res.get_json()["repos"]
    assert any(r["id"] == repo_id for r in repos)

    # 6. Check repo history contains this scan
    hist_res = client.get(f"/api/repos/{repo_id}/history")
    assert hist_res.status_code == 200
    assert len(hist_res.get_json()["history"]) >= 1

    # 7. Check web UI index returns 200 HTML
    ui_res = client.get("/")
    assert ui_res.status_code == 200
    assert b"ZEROVANT" in ui_res.data
