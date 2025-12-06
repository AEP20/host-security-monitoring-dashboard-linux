from flask import Blueprint

from .system_api import system_bp
from .metrics_api import metrics_bp
from .logs_api import logs_bp
from .processes_api import processes_bp
from .network_api import network_bp
from .alerts_api import alerts_bp
from .config_api import config_bp

def register_api(app):
    app.register_blueprint(system_bp, url_prefix="/api/system")
    app.register_blueprint(metrics_bp, url_prefix="/api/metrics")
    app.register_blueprint(logs_bp, url_prefix="/api/logs")
    app.register_blueprint(processes_bp, url_prefix="/api/processes")
    app.register_blueprint(network_bp, url_prefix="/api/network")

    # ileride aktif olacaklar
    app.register_blueprint(alerts_bp, url_prefix="/api/alerts")
    app.register_blueprint(config_bp, url_prefix="/api/config")
