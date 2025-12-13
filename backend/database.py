# backend/database.py

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from backend.models.base import Base

DB_PATH = "/var/lib/hids/hids.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# -------------------------------------------------
# ENGINE
# -------------------------------------------------
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 30,           
    },
    pool_pre_ping=True,
    echo=False,
)

# -------------------------------------------------
# SESSION FACTORY
# -------------------------------------------------
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

# -------------------------------------------------
# INIT
# -------------------------------------------------
def init_db():
    """
    - Tabloları oluşturur
    - SQLite için WAL modunu aktif eder
    """
    Base.metadata.create_all(bind=engine)

    # SQLite pragmaları
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.execute(text("PRAGMA synchronous=NORMAL;"))
        conn.execute(text("PRAGMA temp_store=MEMORY;"))
