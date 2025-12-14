# alerts_api.py

# /api/alerts
# → High/Medium/Low alert listesi

from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.database import SessionLocal
from backend.models.alert_model import AlertModel
from backend.logger import logger

alerts_api = Blueprint("alerts_api", __name__)


# ======================================================
# GET /api/alerts
# Query params:
#   ?severity=HIGH
#   ?rule_name=PROC_001
#   ?limit=100
#   ?offset=0
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
# ======================================================
@alerts_api.get("/<int:alert_id>")
def get_alert_detail(alert_id):
    session = SessionLocal()
    try:
        row = session.query(AlertModel).get(alert_id)

        if not row:
            return error("Alert not found", status_code=404)

        return success(data=row.to_dict())

    except Exception as e:
        logger.exception("[alerts] Failed to fetch alert detail")
        return error("Failed to load alert detail", exception=e)

    finally:
        session.close()
