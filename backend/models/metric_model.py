# backend/models/metric_model.py

from sqlalchemy import Column, Integer, DateTime, JSON
from backend.models.base import Base, current_time


class MetricModel(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=current_time, index=True)
    snapshot = Column(JSON, nullable=False)

    # ---------------------------------------------------
    #            STATIC CREATE METHOD
    # ---------------------------------------------------
    @staticmethod
    def create(event: dict, session):
        obj = MetricModel(
            snapshot=event
        )

        session.add(obj)
        return obj

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "snapshot": self.snapshot
        }
