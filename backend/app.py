from flask import Flask
from backend.extensions import db, scheduler
from backend.api.system_api import system_api


def create_app():
    app = Flask(__name__)
    
    app.config.from_pyfile("config.py")
    app.register_blueprint(system_api)

    db.init_app(app)

    scheduler.init_app(app)
    scheduler.start()

    from backend.api.metrics_api import metrics_api
    app.register_blueprint(metrics_api, url_prefix="/api/metrics")

    return app

app = create_app()



# create_app() fonksiyonu olur:
# config.py’den ayarları yükler
# extensions.py içindeki db, scheduler vs. init eder
# API blueprint’lerini register eder (metrics_api, logs_api, alerts_api, …)
# Jinja template klasörünü frontend/templates’e bağlar
