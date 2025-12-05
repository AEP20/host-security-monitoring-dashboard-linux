from flask import Flask
from backend.extensions import scheduler
from backend.api.system_api import system_api
from backend.database import init_db


def create_app():
    app = Flask(__name__)
    
    app.config.from_pyfile("config.py")
    app.register_blueprint(system_api)

    init_db()

    scheduler.init_app(app)
    scheduler.start()

    # from backend.api.metrics_api import metrics_api
    # app.register_blueprint(metrics_api, url_prefix="/api/metrics")

    return app


app = create_app()
