# backend/api/alerts_api.py

from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.database import SessionLocal
from backend.logger import logger

from backend.models.alert_model import AlertModel
from backend.models.alert_evidence_model import AlertEvidenceModel
from backend.models.log_model import LogEventModel
from backend.models.process_event_model import ProcessEventModel
from backend.models.network_event_model import NetworkEventModel

alerts_api = Blueprint("alerts_api", __name__)

# ======================================================
# GET /api/alerts
#
# Query params:
#   ?severity=HIGH
#   ?rule_name=AUTH_001
#   ?limit=100
#   ?offset=0
#
# Bu endpoint SADECE alert listesi döner
# Evidence / event detayına girmez
# ======================================================
@alerts_api.get("")
def get_alerts():
    session = SessionLocal()
    try:
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))

        q = session.query(AlertModel)

        severity = request.args.get("severity")
        rule_name = request.args.get("rule_name")

        if severity:
            q = q.filter(AlertModel.severity == severity)

        if rule_name:
            q = q.filter(AlertModel.rule_name == rule_name)

        q = q.order_by(AlertModel.timestamp.desc())
        rows = q.limit(limit).offset(offset).all()

        logger.info(
            f"[alerts] Returned {len(rows)} alerts "
            f"(limit={limit}, offset={offset})"
        )

        return success(data=[r.to_dict() for r in rows])

    except Exception as e:
        logger.exception("[alerts] Failed to fetch alerts")
        return error("Failed to load alerts", exception=e)

    finally:
        session.close()


# ======================================================
# GET /api/alerts/<id>
#
# Alert DETAIL endpoint
#
# Dönen yapı:
# {
#   alert: {...},
#   evidence: [
#     {
#       role,
#       sequence,
#       event_type,
#       event: {...}   <-- gerçek event kaydı
#     }
#   ]
# }
# ======================================================
@alerts_api.get("/<int:alert_id>")
def get_alert_detail(alert_id):
    session = SessionLocal()
    try:
        # --------------------------------------------------
        # FETCH ALERT
        # --------------------------------------------------
        alert = session.query(AlertModel).get(alert_id)

        if not alert:
            return error("Alert not found", status_code=404)

        # --------------------------------------------------
        # FETCH EVIDENCE 
        # --------------------------------------------------
        evidences = (
            session.query(AlertEvidenceModel)
            .filter(AlertEvidenceModel.alert_id == alert_id)
            .order_by(AlertEvidenceModel.sequence.asc().nullslast())
            .all()
        )

        evidence_payload = []

        # --------------------------------------------------
        # FIND THE EVENTS RELATED TO THE EVIDENCE
        # --------------------------------------------------
        for ev in evidences:
            event_data = None

            if ev.event_type == "LOG_EVENT":
                obj = session.query(LogEventModel).get(ev.event_id)
                event_data = obj.to_dict() if obj else None

            elif ev.event_type.startswith("PROCESS_"):
                obj = session.query(ProcessEventModel).get(ev.event_id)
                event_data = obj.to_dict() if obj else None

            elif ev.event_type.startswith("NET_") or ev.event_type.startswith("CONNECTION_"):
                obj = session.query(NetworkEventModel).get(ev.event_id)
                event_data = obj.to_dict() if obj else None

            if not event_data:
                logger.warning(
                    f"[alerts] Evidence event not found "
                    f"(type={ev.event_type}, id={ev.event_id})"
                )

            evidence_payload.append({
                "role": ev.role,
                "sequence": ev.sequence,
                "event_type": ev.event_type,
                "event": event_data,
            })

        # --------------------------------------------------
        # FINAL RESPONSE
        # --------------------------------------------------
        return success(data={
            "alert": alert.to_dict(),
            "evidence": evidence_payload,
        })

    except Exception as e:
        logger.exception("[alerts] Failed to fetch alert detail")
        return error("Failed to load alert detail", exception=e)

    finally:
        session.close()
