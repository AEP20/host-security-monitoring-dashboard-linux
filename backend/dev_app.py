import os
from flask import Flask, render_template

def create_app():
    api_mode = os.environ.get("HIDS_API_MODE", "mock")
    backend_url = os.environ.get("HIDS_BACKEND_URL", "")

    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static",
    )

    # Debug'ı app.debug yerine env'den güvenli şekilde oku
    is_debug = os.environ.get("FLASK_DEBUG") == "1" or os.environ.get("FLASK_ENV") == "development"

    # SAFETY GUARD
    if not is_debug and api_mode == "mock":
        raise RuntimeError(
            "SAFETY: Mock mode is not allowed without debug. "
            "Set HIDS_API_MODE=real or run with --debug."
        )

    if api_mode == "mock":
        from backend.api.mock_api import mock_api
        app.register_blueprint(mock_api)
        print("[DEV] Mock API enabled")
    else:
        if backend_url:
            from backend.api.mock_api import create_proxy_blueprint
            proxy_bp = create_proxy_blueprint(backend_url)
            app.register_blueprint(proxy_bp)
            print(f"[DEV] Proxying /api/* to {backend_url}")
        else:
            from backend.api.mock_api import unavailable_api
            app.register_blueprint(unavailable_api)
            print("[DEV] Real mode but no HIDS_BACKEND_URL set - API returns 503")

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/logs")
    def logs_page():
        return render_template("logs.html")

    @app.route("/processes")
    def processes_page():
        return render_template("processes.html")

    @app.route("/network")
    def network_page():
        return render_template("network.html")

    @app.route("/alerts")
    def alerts_page():
        return render_template("alerts.html")

    return app

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="0.0.0.0", port=3001, debug=debug)
