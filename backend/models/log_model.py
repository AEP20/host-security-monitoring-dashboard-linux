from sqlalchemy import Column, Integer, String, DateTime, Text
from backend.models.base import Base, current_time

class LogEventModel(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=current_time, index=True)

    log_source = Column(String(50), nullable=False)       # auth, syslog, kernel, dpkg
    event_type = Column(String(100), nullable=False)      # FAILED_LOGIN, etc.

    message = Column(Text, nullable=False)
    user = Column(String(100), nullable=True)
    ip_address = Column(String(100), nullable=True)
    process_name = Column(String(200), nullable=True)

    extra_data = Column(Text, nullable=True)  # JSON string

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "log_source": self.log_source,
            "event_type": self.event_type,
            "message": self.message,
            "user": self.user,
            "ip_address": self.ip_address,
            "process_name": self.process_name,
            "extra_data": self.extra_data,
        }
