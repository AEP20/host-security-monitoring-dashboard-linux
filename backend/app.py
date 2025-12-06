from flask import Flask
from backend.extensions import scheduler
from backend.database import init_db
from backend.api import logs_api, metrics_api, system_api

def create_app():
    app = Flask(__name__)
    
    app.config.from_pyfile("config.py")
    app.register_blueprint(system_api)
    app.register_blueprint(metrics_api)
    app.register_blueprint(logs_api)

    init_db()

    scheduler.init_app(app)
    scheduler.start()

    return app


app = create_app()

def start():
    app.run(host="0.0.0.0", port=5000)

start()
