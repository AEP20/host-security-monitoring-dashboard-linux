# backend/models/alert_evidence_model.py

from sqlalchemy import Column, Integer, String, DateTime, Index
from backend.models.base import Base, current_time


class AlertEvidenceModel(Base):
    """
    Alert ↔ Event association table (generic)

    One alert can have many events
    One event can belong to many alerts
    """

    __tablename__ = "alert_evidence"

    id = Column(Integer, primary_key=True)

    # FK-like (bilinçli olarak gerçek FK kullanmıyoruz)
    alert_id = Column(Integer, nullable=False, index=True)

    # Generic event reference
    event_type = Column(String(50), nullable=False)
    event_id = Column(Integer, nullable=False)

    # TRIGGER / SUPPORT / CONTEXT
    role = Column(String(20), nullable=False)

    # Order of event inside alert (optional but powerful)
    sequence = Column(Integer, nullable=True)

    timestamp = Column(DateTime, default=current_time, index=True)

    # --------------------------------------------------
    # STATIC CREATE
    # --------------------------------------------------
    @staticmethod
    def create(
        *,
        alert_id: int,
        event_type: str,
        event_id: int,
        role: str,
        sequence: int | None = None,
    ):
        return AlertEvidenceModel(
            alert_id=alert_id,
            event_type=event_type,
            event_id=event_id,
            role=role,
            sequence=sequence,
        )


# Helpful composite index for alert detail queries
Index(
    "ix_alert_evidence_alert_event",
    AlertEvidenceModel.alert_id,
    AlertEvidenceModel.event_type,
)
