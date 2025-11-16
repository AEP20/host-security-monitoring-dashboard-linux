from flask import Flask
from backend.extensions import db, scheduler

def create_app():
    app = Flask(__name__)
    
    app.config.from_pyfile("config.py")

    db.init_app(app)

    scheduler.init_app(app)
    scheduler.start()

    from backend.api.metrics_api import metrics_api
    app.register_blueprint(metrics_api, url_prefix="/api/metrics")

    return app

app = create_app()
