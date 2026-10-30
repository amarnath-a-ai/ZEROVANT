"""Flask application factory."""

from flask import Flask

from app.config import config_by_name


def create_app(config_name="development"):
    """Create and configure an instance of the Flask application."""
    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )

    app_config = config_by_name.get(config_name, config_by_name["development"])
    app.config.from_object(app_config)

    # Register blueprints (routes will be fully wired in Phase 5)
    from app.api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.route("/health")
    def health():
        return {"status": "ok", "app": "cicd-auditor"}

    return app
