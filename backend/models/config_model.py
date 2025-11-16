#config modal

from sqlalchemy import Column, Integer, String, DateTime, Text
from backend.models.base import Base, current_time

class ConfigCheckModel(Base):
    __tablename__ = "config_checks"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=current_time, index=True)

    check_name = Column(String(200), nullable=False)   # ex: SSH Root Login Check
    status = Column(String(20), nullable=False)         # PASS, WARN, FAIL
    severity = Column(String(20), nullable=False)       # LOW, MEDIUM, HIGH

    hostname = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "check_name": self.check_name,
            "status": self.status,
            "severity": self.severity,
            "hostname": self.hostname,
            "details": self.details,
        }
