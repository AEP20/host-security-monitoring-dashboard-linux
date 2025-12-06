from flask import Flask, render_template
from backend.database import init_db

from backend.api.system_api import system_api
from backend.api.metrics_api import metrics_api
from backend.api.logs_api import logs_api
from backend.api.processes_api import process_api as processes_api
from backend.core.scheduler.scheduler import Scheduler

from backend.logger import logger


def create_app():
    logger.info("[APP] Initializing Flask application")

    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static"
    )

    app.config.from_pyfile("config.py")

    app.register_blueprint(system_api, url_prefix="/api/system")
    app.register_blueprint(metrics_api, url_prefix="/api/metrics")
    app.register_blueprint(logs_api, url_prefix="/api/logs")
    app.register_blueprint(processes_api, url_prefix="/api/processes")

    logger.debug("[APP] Blueprints registered")

    init_db()
    logger.info("[APP] Database initialized")

    scheduler = Scheduler()
    scheduler.start()
    logger.info("[APP] Scheduler started")

    @app.route("/")
    def index():
        return render_template("dashboard.html")
    
    @app.route("/logs")
    def logs_page():
        return render_template("logs.html")
    
    @app.route("/processes")
    def processes_page():
        return render_template("processes.html")

    logger.info("[APP] Flask application created successfully")
    return app


app = create_app()
