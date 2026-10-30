"""Flask API route handlers."""

from flask import Blueprint, jsonify, request

api_bp = Blueprint("api", __name__)


@api_bp.route("/rules", methods=["GET"])
def get_rules():
    """List all registered static security rules."""
    from app.rules import ALL_RULES

    rules_meta = [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "default_severity": r.default_severity.value,
            "tags": r.tags,
        }
        for r in ALL_RULES
    ]
    return jsonify({"rules": rules_meta, "total": len(rules_meta)})


@api_bp.route("/scan", methods=["POST"])
def trigger_scan():
    """Trigger a new static audit scan.

    (Detailed implementation in Phase 5)
    """
    data = request.get_json() or {}
    return jsonify({
        "status": "received",
        "message": "Scan endpoint stub (Phase 5 implementation).",
        "target_type": data.get("target_type"),
    }), 202


@api_bp.route("/scans", methods=["GET"])
def list_scans():
    """List historical scans.

    (Detailed implementation in Phase 5)
    """
    return jsonify({"scans": [], "total": 0})

