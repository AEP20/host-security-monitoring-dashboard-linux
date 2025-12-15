from datetime import timedelta
from typing import Dict, Any, List
from backend.database import SessionLocal
from backend.logger import logger
from backend.models.alert_model import AlertModel
from backend.models.alert_evidence_model import AlertEvidenceModel
from backend.models.log_model import LogEventModel


class DBWriter:
    ...
    # -------------------------------------------------
    # ALERT + EVIDENCE
    # -------------------------------------------------
    def _save_alert_with_evidence(self, payload: Dict[str, Any]):
        alert_data = payload.get("alert")
        evidence_list = payload.get("evidence", [])

        if not alert_data:
            logger.warning("[DBWriter] ALERT payload missing alert data")
            return

        def resolve_evidence(session, alert_obj) -> List[Dict[str, Any]]:
            extra = alert_data.get("extra") or {}
            cfg = extra.get("evidence_resolve") or {}

            if cfg.get("source") != "log_events":
                return []

            ip = extra.get("ip")
            user = extra.get("user")
            window_seconds = extra.get("window_seconds")

            if not ip or not window_seconds:
                return []

            end_ts = alert_obj.timestamp
            start_ts = end_ts - timedelta(seconds=int(window_seconds))

            q = session.query(LogEventModel.id).filter(
                LogEventModel.timestamp >= start_ts,
                LogEventModel.timestamp <= end_ts,
                LogEventModel.ip == ip,
            )

            if user:
                q = q.filter(LogEventModel.user == user)

            event_types = cfg.get("event_types")
            if event_types:
                q = q.filter(LogEventModel.event_type.in_(event_types))

            if cfg.get("category"):
                q = q.filter(LogEventModel.category == cfg["category"])

            rows = q.order_by(LogEventModel.timestamp.asc()).all()
            if not rows:
                return []

            resolved = []
            for idx, (event_id,) in enumerate(rows):
                resolved.append({
                    "event_type": "LOG_EVENT",
                    "event_id": event_id,
                    "role": "SUPPORT",
                    "sequence": idx + 1,
                })

            resolved[-1]["role"] = "TRIGGER"
            return resolved

        def op(session):
            alert_obj = AlertModel.create(alert_data, session=session)
            session.flush()  # alert.id + timestamp hazır

            evs = evidence_list or resolve_evidence(session, alert_obj)

            written = 0
            for ev in evs:
                if not ev.get("event_id"):
                    continue

                session.add(
                    AlertEvidenceModel.create(
                        alert_id=alert_obj.id,
                        event_type=ev["event_type"],
                        event_id=ev["event_id"],
                        role=ev["role"],
                        sequence=ev["sequence"],
                    )
                )
                written += 1

            logger.debug(
                f"[DBWriter] Alert saved id={alert_obj.id} evidence_written={written}"
            )

        self._with_retry(op, event_type="ALERT")
