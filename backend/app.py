from flask import Flask, render_template
from backend.database import init_db

from backend.api.system_api import system_api
from backend.api.metrics_api import metrics_api
from backend.api.network_api import network_api
from backend.api.logs_api import logs_api
from backend.api.processes_api import process_api as processes_api

from backend.core.scheduler.scheduler import Scheduler
from backend.core.storage.db_writer import DBWriter

from backend.logger import logger

# -------------------------------------------------
# SINGLETON SERVICES
# -------------------------------------------------
db_writer = DBWriter()
scheduler = Scheduler()


def create_app():
    logger.info("[APP] Initializing Flask application")

    app = Flask(
        __name__,
        template_folder="../frontend/templates",
        static_folder="../frontend/static"
    )

    app.config.from_pyfile("config.py")

    # -------------------------------------------------
    # BLUEPRINTS
    # -------------------------------------------------
    app.register_blueprint(system_api, url_prefix="/api/system")
    app.register_blueprint(metrics_api, url_prefix="/api/metrics")
    app.register_blueprint(logs_api, url_prefix="/api/logs")
    app.register_blueprint(processes_api, url_prefix="/api/process")
    app.register_blueprint(network_api, url_prefix="/api/network")

    logger.debug("[APP] Blueprints registered")

    # -------------------------------------------------
    # DATABASE INIT
    # -------------------------------------------------
    init_db()
    logger.info("[APP] Database initialized")

    # -------------------------------------------------
    # START BACKGROUND SERVICES
    # -------------------------------------------------
    db_writer.start()
    logger.info("[APP] DBWriter started")

    scheduler.start()
    logger.info("[APP] Scheduler started")

    # -------------------------------------------------
    # SHUTDOWN HANDLER
    # -------------------------------------------------
    # @app.teardown_appcontext
    def shutdown(exception=None):
        logger.info("[APP] Shutting down background services")

        try:
            scheduler.stop()
            logger.info("[APP] Scheduler stopped")
        except Exception:
            logger.exception("[APP] Failed to stop scheduler")

        try:
            db_writer.stop()
            logger.info("[APP] DBWriter stopped")
        except Exception:
            logger.exception("[APP] Failed to stop DBWriter")

    # -------------------------------------------------
    # FRONTEND ROUTES
    # -------------------------------------------------
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

    logger.info("[APP] Flask application created successfully")
    return app


app = create_app()
