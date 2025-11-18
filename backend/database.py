import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Base'i import etmezsen create_all çalışmaz
from backend.models.base import Base

# Modelleri import ETMELİYİZ ki Base.metadata dolsun
from backend.models import log_model, metric_model, alert_model, config_model

# Tüm servisler, testler ve backend için tek DB yolu:
DB_PATH = "/opt/HIDS/state/hids.db"

# Klasör yoksa oluştur
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    echo=False
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

def init_db():
    Base.metadata.create_all(bind=engine)
