from flask import Flask, render_template
from backend.extensions import scheduler
from backend.database import init_db

from backend.api.system_api import system_api
from backend.api.metrics_api import metrics_api
from backend.api.logs_api import logs_api


def create_app():
    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static"
    )

    app.config.from_pyfile("config.py")

    app.register_blueprint(system_api, url_prefix="/api/system")
    app.register_blueprint(metrics_api, url_prefix="/api/metrics")
    app.register_blueprint(logs_api, url_prefix="/api/logs")


    init_db()

    scheduler.init_app(app)
    scheduler.start()

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    return app


app = create_app()
