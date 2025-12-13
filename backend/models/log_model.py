# log model

from sqlalchemy import Column, Integer, String, DateTime, Text
from backend.models.base import Base, current_time


class LogEventModel(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=current_time, index=True)

    # Kaynak log dosyası (auth, syslog, kernel, dpkg, ufw)
    log_source = Column(String(50), nullable=False)

    # Normalize event tipi (FAILED_LOGIN, PACKAGE_INSTALL, KERNEL_WARNING)
    event_type = Column(String(100), nullable=False)

    # Event ana kategorisi (AUTH, SYSTEM, KERNEL, PACKAGE, FIREWALL)
    category = Column(String(50), nullable=True)

    # Rule engine severity
    severity = Column(String(20), nullable=True)  # LOW, MEDIUM, HIGH

    # Ham log (orijinal satır)
    raw_log = Column(Text, nullable=True)

    # Parser sonrası özet
    message = Column(Text, nullable=False)
    user = Column(String(100), nullable=True)
    ip_address = Column(String(100), nullable=True)
    process_name = Column(String(200), nullable=True)
    # hostname = Column(String(100), nullable=True)

    # Rule engine tarafından tetiklenen kural
    rule_triggered = Column(String(100), nullable=True)

    # Ek alanlar (JSON string)
    extra_data = Column(Text, nullable=True)

    # ---------------------------------------------------
    #            STATIC CREATE METHOD
    # ---------------------------------------------------
    @staticmethod
    def create(event: dict, session):
        obj = LogEventModel(
            timestamp=event.get("timestamp"),
            log_source=event.get("log_source"),
            event_type=event.get("event_type"),
            category=event.get("category"),
            severity=event.get("severity"),
            raw_log=event.get("raw"),
            message=event.get("message"),
            user=event.get("user"),
            ip_address=event.get("ip"),
            process_name=event.get("process"),
            rule_triggered=None,
            extra_data=event.get("extra_data"),
        )

        session.add(obj)
        return obj


    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "log_source": self.log_source,
            "event_type": self.event_type,
            "category": self.category,
            "severity": self.severity,
            "raw_log": self.raw_log,
            "message": self.message,
            "user": self.user,
            "ip_address": self.ip_address,
            "process_name": self.process_name,
            # "hostname": self.hostname,
            "rule_triggered": self.rule_triggered,
            "extra_data": self.extra_data,
        }
