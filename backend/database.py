# SQLite dosyasını oluşturmak / bağlanmak
# tablo yaratma fonksiyonu (init_db)
# basit helper fonksiyonlar (ör: get_connection(), execute_query())

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models.base import Base

engine = create_engine("sqlite:///hids.db", echo=False)
SessionLocal = sessionmaker(bind=engine, autoflush=False)

def init_db():
    Base.metadata.create_all(bind=engine)
