from sqlalchemy import Column, Integer, Float, DateTime
from backend.models.base import Base, current_time

class MetricModel(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=current_time, index=True)

    cpu_usage = Column(Float, nullable=False)
    ram_usage = Column(Float, nullable=False)
    disk_usage = Column(Float, nullable=False)

    net_in = Column(Integer, nullable=True)
    net_out = Column(Integer, nullable=True)
    process_count = Column(Integer, nullable=True)
    uptime_seconds = Column(Integer, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "cpu_usage": self.cpu_usage,
            "ram_usage": self.ram_usage,
            "disk_usage": self.disk_usage,
            "net_in": self.net_in,
            "net_out": self.net_out,
            "process_count": self.process_count,
            "uptime_seconds": self.uptime_seconds,
        }
