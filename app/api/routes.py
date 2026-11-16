"""Flask API route handlers."""

from flask import Blueprint, current_app, jsonify, request

from app.api.limiter import limiter
from app.api.schemas import ValidationError, validate_scan_request
from app.correlation.chains import CHAIN_DEFINITIONS
from app.ingest.github_client import (
    GitHubNetworkError,
    GitHubRateLimitError,
    GitHubResourceNotFoundError,
)
from app.pipeline import run_scan
from app.rules import default_registry
from app.storage.errors import StorageError
from app.storage.repository import ScanRepository

api_bp = Blueprint("api", __name__)


def get_repository() -> ScanRepository:
    """Retrieve or initialize the ScanRepository instance tied to current_app."""
    if "repository" not in current_app.extensions:
        db_path = current_app.config.get("DATABASE_PATH")
        current_app.extensions["repository"] = ScanRepository(db_path)
    return current_app.extensions["repository"]


@api_bp.before_request
def check_rate_limit():
    """Enforce client IP rate limiting on API endpoints."""
    if not current_app.config.get("RATELIMIT_ENABLED", True):
        return None

    client_ip = (
        request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        .split(",")[0]
        .strip()
    )

    limit = current_app.config.get("RATELIMIT_PER_MINUTE", 60)
    window_seconds = current_app.config.get("RATELIMIT_WINDOW_SECONDS", 60)

    allowed, retry_after = limiter.is_allowed(
        client_ip,
        limit=limit,
        window_seconds=window_seconds,
    )
    if not allowed:
        response = jsonify({
            "error": {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "Too many requests. Please retry after some time.",
            }
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response
    return None


@api_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for API service monitoring."""
    return jsonify({
        "status": "ok",
        "app": "cicd-auditor",
        "version": "1.0.0",
    }), 200


@api_bp.route("/rules", methods=["GET"])
def list_rules():
    """List static security rules with optional category and tier filtering."""
    category_filter = request.args.get("category", "").strip().lower()
    tier_filter = request.args.get("tier", "").strip().lower()

    rules = default_registry.list_rules()
    results = []
    for r in rules:
        cat = getattr(r, "category", "general")
        tier = getattr(r, "tier", "core")

        if category_filter and cat.lower() != category_filter:
            continue
        if tier_filter and tier.lower() != tier_filter:
            continue

        results.append({
            "id": r.id,
            "name": r.name,
            "title": r.description.split(".")[0] if r.description else r.name,
            "description": r.description,
            "severity": (
                r.default_severity.value
                if hasattr(r.default_severity, "value")
                else str(r.default_severity)
            ),
            "category": cat,
            "tier": tier,
            "tags": list(r.tags),
        })

    return jsonify({"rules": results, "total": len(results)}), 200


@api_bp.route("/chains", methods=["GET"])
def list_chains():
    """Catalogue of all 10 correlated attack chain definitions with narratives."""
    chains_data = [
        {
            "chain_type": cd.chain_type.value,
            "name": cd.name,
            "required_rules": list(cd.required_rules),
            "secondary_rules": list(cd.secondary_rules),
            "scope": cd.scope,
            "trigger_label": cd.trigger_label,
            "privilege_label": cd.privilege_label,
            "impact_label": cd.impact_label,
            "narrative_template": cd.narrative_template,
        }
        for cd in CHAIN_DEFINITIONS
    ]
    return jsonify({"chains": chains_data, "total": len(chains_data)}), 200


@api_bp.route("/stats", methods=["GET"])
def get_stats():
    """Retrieve holistic dashboard totals, severity distributions, and category breakdowns."""
    repo_mgr = get_repository()
    stats = repo_mgr.get_dashboard_stats()
    return jsonify(stats), 200


@api_bp.route("/scan", methods=["POST"])
def trigger_scan():
    """Trigger a static audit scan (synchronous execution)."""
    if not request.is_json:
        return jsonify({
            "error": {
                "code": "UNSUPPORTED_MEDIA_TYPE",
                "message": "Content-Type must be application/json.",
            }
        }), 415

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({
            "error": {
                "code": "BAD_REQUEST",
                "message": "Malformed JSON payload.",
            }
        }), 400

    try:
        validated = validate_scan_request(
            data,
            allow_local_path=current_app.config.get("ALLOW_LOCAL_PATH", False),
            max_yaml_size=current_app.config.get("MAX_YAML_SIZE", 1_048_576),
        )
    except ValidationError as ve:
        return jsonify({"error": {"code": ve.code, "message": ve.message}}), ve.status_code

    # Check for unparseable YAML early to return 422
    if validated["source_type"] == "pasted_yaml":
        from app.parser import load_workflows

        parsed_results = load_workflows(validated["source"], file_path="pasted.yml")
        if not parsed_results or all(not r.is_valid for r in parsed_results):
            err_msg = (
                ", ".join(str(e) for e in parsed_results[0].errors)
                if (parsed_results and parsed_results[0].errors)
                else "Failed to parse YAML content."
            )
            return jsonify({
                "error": {
                    "code": "UNPROCESSABLE_ENTITY",
                    "message": f"Malformed YAML: {err_msg}",
                }
            }), 422

    repo_mgr = get_repository()
    try:
        scan_id = run_scan(
            source=validated["source"],
            source_type=validated["source_type"],
            repo_url=validated.get("repo_url"),
            ref=validated.get("ref"),
            repository=repo_mgr,
        )
        return jsonify({
            "scan_id": scan_id,
            "status": "completed",
            "message": "Scan completed successfully.",
        }), 201

    except GitHubResourceNotFoundError as exc:
        return jsonify({
            "error": {
                "code": "UPSTREAM_NOT_FOUND",
                "message": str(exc),
            }
        }), 502
    except (GitHubRateLimitError, GitHubNetworkError) as exc:
        return jsonify({
            "error": {
                "code": "UPSTREAM_ERROR",
                "message": str(exc),
            }
        }), 502
    except StorageError as exc:
        current_app.logger.error("Storage error during scan: %s", exc)
        return jsonify({
            "error": {
                "code": "STORAGE_ERROR",
                "message": "Database error while storing scan results.",
            }
        }), 500
    except Exception as exc:
        current_app.logger.error("Unexpected scan failure: %s", exc)
        return jsonify({
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred during scan execution.",
            }
        }), 500


@api_bp.route("/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """Retrieve full scan details, findings, attack chains, and explanations."""
    repo_mgr = get_repository()
    scan = repo_mgr.get_scan(scan_id)
    if not scan:
        return jsonify({
            "error": {
                "code": "NOT_FOUND",
                "message": f"Scan with ID '{scan_id}' not found.",
            }
        }), 404

    # Sort findings by base_score descending, then line_number ascending
    scan["findings"].sort(
        key=lambda f: (-float(f.get("base_score", 0.0)), int(f.get("line_number", 0)))
    )

    return jsonify(scan), 200


@api_bp.route("/repos", methods=["GET"])
def list_repos():
    """List registered repositories with summary statistics and scan counts."""
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify({
            "error": {
                "code": "BAD_REQUEST",
                "message": "Query parameters 'limit' and 'offset' must be valid integers.",
            }
        }), 400

    repo_mgr = get_repository()
    repos = repo_mgr.list_repos(limit=limit, offset=offset)
    return jsonify({"repos": repos, "total": len(repos)}), 200


@api_bp.route("/repos/<repo_id>/history", methods=["GET"])
def get_repo_history(repo_id: str):
    """Retrieve chronological scan history for a repository."""
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
    except ValueError:
        return jsonify({
            "error": {
                "code": "BAD_REQUEST",
                "message": "Query parameter 'limit' must be an integer.",
            }
        }), 400

    repo_mgr = get_repository()
    repo = repo_mgr.get_repo(repo_id)
    if not repo:
        return jsonify({
            "error": {
                "code": "NOT_FOUND",
                "message": f"Repository with ID '{repo_id}' not found.",
            }
        }), 404

    history = repo_mgr.get_history(repo_id, limit=limit)
    return jsonify({
        "repo_id": repo_id,
        "repo_name": repo["name"],
        "repo_url": repo["url"],
        "history": history,
        "total": len(history),
    }), 200


@api_bp.route("/repos/<repo_id>/compare", methods=["GET"])
def compare_repo_scans(repo_id: str):
    """Compare two scans belonging to the given repository (a=baseline, b=target)."""
    scan_a_id = request.args.get("a", "").strip()
    scan_b_id = request.args.get("b", "").strip()

    if not scan_a_id or not scan_b_id:
        return jsonify({
            "error": {
                "code": "MISSING_COMPARISON_TARGETS",
                "message": "Both query parameters 'a' (baseline scan ID) and 'b' (target scan ID) are required.",
            }
        }), 400

    repo_mgr = get_repository()
    repo = repo_mgr.get_repo(repo_id)
    if not repo:
        return jsonify({
            "error": {
                "code": "NOT_FOUND",
                "message": f"Repository with ID '{repo_id}' not found.",
            }
        }), 404

    scan_a = repo_mgr.get_scan(scan_a_id)
    if not scan_a:
        return jsonify({
            "error": {
                "code": "NOT_FOUND",
                "message": f"Baseline scan '{scan_a_id}' not found.",
            }
        }), 404

    scan_b = repo_mgr.get_scan(scan_b_id)
    if not scan_b:
        return jsonify({
            "error": {
                "code": "NOT_FOUND",
                "message": f"Target scan '{scan_b_id}' not found.",
            }
        }), 404

    # Enforce that both scans belong to this repository
    if scan_a["repo_id"] != repo_id or scan_b["repo_id"] != repo_id:
        return jsonify({
            "error": {
                "code": "CROSS_REPO_COMPARISON_NOT_ALLOWED",
                "message": "Both comparison scans must belong to the specified repository.",
            }
        }), 400

    diff = repo_mgr.compare_scans(scan_a_id, scan_b_id)
    return jsonify(diff), 200
