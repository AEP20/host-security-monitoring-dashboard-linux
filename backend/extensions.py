# “Uygulamanın yanına eklenen global araçlar” burada tanımlanır ve create_app() içinde init edilir.
# backend/extensions.py

from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler

# Global instance'lar (Flask app'e create_app içinde bağlanacak)
db = SQLAlchemy()
scheduler = APScheduler()
