from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from backend.models.base import Base, current_time


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=current_time, index=True)

    # Hangi rule tetikledi?
    rule_name = Column(String(100), nullable=False)

    # Severity HIGH/MEDIUM/LOW
    severity = Column(String(20), nullable=False)

    # Alert açıklaması
    message = Column(Text, nullable=False)

    # Hangi log event’e bağlı (optional)
    log_event_id = Column(Integer, ForeignKey("log_events.id"), nullable=True)

    # ---------------------------------------------------
    #            STATIC CREATE METHOD
    # ---------------------------------------------------
    @staticmethod
    def create(event: dict, session):
        obj = AlertModel(
            rule_name=event.get("rule_name"),
            severity=event.get("severity"),
            message=event.get("message"),
            log_event_id=event.get("log_event_id"),
        )

        session.add(obj)
        return obj


    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "rule_name": self.rule_name,
            "severity": self.severity,
            "message": self.message,
            "log_event_id": self.log_event_id,
        }
