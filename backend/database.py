# backend/database.py

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models.base import Base
from backend.models.metric_model import MetricModel

DB_PATH = "/var/lib/hids/hids.db"

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
    
def save_metric_snapshot(event: dict):
    db = SessionLocal()
    obj = MetricModel(snapshot=event)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    db.close()
    return obj
