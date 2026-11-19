"""Flask application factory."""

import os
from typing import Any

from flask import Flask, jsonify, render_template, request

from app.config import config_by_name


def create_app(config_name: str | None = None, test_config: dict[str, Any] | None = None) -> Flask:
    """Create and configure an instance of the Flask application."""
    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )

    resolved_config = config_name or os.environ.get("FLASK_ENV", "production")
    app_config = config_by_name.get(resolved_config, config_by_name["production"])
    app.config.from_object(app_config)
    if test_config:
        app.config.update(test_config)

    # Register blueprints
    from app.api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix="/api")

    # Request logging with sensitive data and raw YAML redaction
    @app.before_request
    def log_request_info():
        safe_params = {}
        sensitive_keys = {"token", "key", "secret", "auth", "password", "api_key"}
        for k, v in request.args.items():
            if k.lower() in sensitive_keys:
                safe_params[k] = "[REDACTED]"
            else:
                safe_params[k] = v

        body_summary = ""
        try:
            if request.is_json:
                data = request.get_json(silent=True)
                if isinstance(data, dict):
                    keys = list(data.keys())
                    has_yaml = "yaml" in data
                    yaml_len = len(data["yaml"]) if has_yaml and isinstance(data["yaml"], str) else 0
                    repo = data.get("repo_url")
                    body_summary = f"(JSON keys={keys}, yaml_bytes={yaml_len}, repo={repo})"
            elif request.content_length:
                body_summary = f"({request.content_length} bytes)"
        except Exception:
            body_summary = "(unreadable payload)"

        app.logger.info(
            "API Request: %s %s from %s %s params=%s",
            request.method,
            request.path,
            request.remote_addr,
            body_summary,
            safe_params,
        )

    # Security headers and response logging on every response
    @app.after_request
    def set_security_headers_and_log(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        app.logger.info(
            "API Response: %s %s -> %d",
            request.method,
            request.path,
            response.status_code,
        )
        return response

    # Global standardized error handlers
    @app.errorhandler(400)
    def bad_request(exc):
        msg = getattr(exc, "description", "Bad Request")
        return jsonify({"error": {"code": "BAD_REQUEST", "message": msg}}), 400

    @app.errorhandler(404)
    def not_found(exc):
        msg = getattr(exc, "description", "Resource Not Found")
        return jsonify({"error": {"code": "NOT_FOUND", "message": msg}}), 404

    @app.errorhandler(413)
    def payload_too_large(exc):
        return jsonify({
            "error": {
                "code": "PAYLOAD_TOO_LARGE",
                "message": "Request payload exceeds maximum permitted size.",
            }
        }), 413

    @app.errorhandler(415)
    def unsupported_media_type(exc):
        return jsonify({
            "error": {
                "code": "UNSUPPORTED_MEDIA_TYPE",
                "message": "Content-Type must be application/json.",
            }
        }), 415

    @app.errorhandler(422)
    def unprocessable_entity(exc):
        msg = getattr(exc, "description", "Unprocessable Entity")
        return jsonify({"error": {"code": "UNPROCESSABLE_ENTITY", "message": msg}}), 422

    @app.errorhandler(429)
    def rate_limit_exceeded(exc):
        return jsonify({
            "error": {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "Too many requests. Please retry after some time.",
            }
        }), 429

    @app.errorhandler(500)
    def internal_server_error(exc):
        return jsonify({
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected internal server error occurred.",
            }
        }), 500

    # Web UI Dashboard & Landing Page (Phase 8)
    @app.route("/")
    def index():
        if request.headers.get("Accept") == "application/json":
            return jsonify({
                "app": "CI/CD Pipeline Security Auditor",
                "status": "online",
                "api_documentation": "/api/health",
            }), 200
        return render_template("index.html")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "app": "cicd-auditor"}), 200

    return app
