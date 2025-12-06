# backend/models/metric_model.py

from sqlalchemy import Column, Integer, DateTime, JSON
from backend.models.base import Base, current_time
from backend.database import SessionLocal  

class MetricModel(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=current_time, index=True)

    # Tüm snapshot tek JSON olarak tutulur
    snapshot = Column(JSON, nullable=False)

    @staticmethod
    def create(event: dict):
        db = SessionLocal()
        obj = MetricModel(snapshot=event)
        db.add(obj)
        db.commit()
        db.refresh(obj)
        db.close()
        return obj

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "snapshot": self.snapshot
        }
