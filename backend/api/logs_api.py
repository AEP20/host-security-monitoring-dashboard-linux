from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.database import SessionLocal
from backend.models.log_model import LogEventModel
from backend.models.alert_model import AlertModel
from backend.models.alert_evidence_model import AlertEvidenceModel
import os
from backend.logger import logger

logs_api = Blueprint("logs_api", __name__)


# -------------------------------------------
# GET /api/logs/events
# Returns parsed LogEventModel entries
# Supports filtering, pagination, search
# -------------------------------------------

@logs_api.get("/events")
def get_log_events():
    try:
        db = SessionLocal()
        limit = int(request.args.get("limit", 500))
        offset = int(request.args.get("offset", 0))
        query = db.query(LogEventModel).order_by(LogEventModel.timestamp.desc())

        if request.args.get("severity"):
            query = query.filter(LogEventModel.severity == request.args["severity"])
        if request.args.get("source"):
            query = query.filter(LogEventModel.log_source == request.args["source"])
        if request.args.get("category"):
            query = query.filter(LogEventModel.category == request.args["category"])
        if request.args.get("event_type"):
            query = query.filter(LogEventModel.event_type == request.args["event_type"])
        if request.args.get("search"):
            term = f"%{request.args['search']}%"
            query = query.filter(LogEventModel.message.ilike(term))

        rows = query.limit(limit).offset(offset).all()
        log_ids = [r.id for r in rows]
        
        related_alerts_map = {uid: [] for uid in log_ids}
        
        if log_ids:
            direct_alerts = db.query(AlertModel).filter(AlertModel.log_event_id.in_(log_ids)).all()
            for alert in direct_alerts:
                if alert.log_event_id in related_alerts_map:
                    related_alerts_map[alert.log_event_id].append(alert)

            evidence_items = db.query(AlertEvidenceModel).filter(
                AlertEvidenceModel.event_type == 'LOG_EVENT',
                AlertEvidenceModel.event_id.in_(log_ids)
            ).all()

            if evidence_items:
                evidence_alert_ids = [ev.alert_id for ev in evidence_items]
                linked_alerts = db.query(AlertModel).filter(AlertModel.id.in_(evidence_alert_ids)).all()
                alert_lookup = {a.id: a for a in linked_alerts}

                for ev in evidence_items:
                    if ev.event_id in related_alerts_map and ev.alert_id in alert_lookup:
                        related_alerts_map[ev.event_id].append(alert_lookup[ev.alert_id])

        results = []
        expand_details = request.args.get("expand") == "true"

        for row in rows:
            d = row.to_dict()
            alerts = related_alerts_map.get(row.id, [])
            
            unique_alerts = {}
            for a in alerts:
                unique_alerts[a.id] = a
            
            final_alerts = list(unique_alerts.values())
            d["related_alerts_count"] = len(final_alerts)
            
            severities = [a.severity for a in final_alerts]
            
            if "CRITICAL" in severities:
                d["related_alerts_max_severity"] = "CRITICAL"
            elif "HIGH" in severities:
                d["related_alerts_max_severity"] = "HIGH"
            elif "MEDIUM" in severities:
                d["related_alerts_max_severity"] = "MEDIUM"
            elif "LOW" in severities:
                d["related_alerts_max_severity"] = "LOW"
            else:
                d["related_alerts_max_severity"] = None

            if expand_details:
                d["related_alerts"] = [{
                    "id": a.id,
                    "rule_name": a.rule_name,
                    "severity": a.severity,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None
                } for a in final_alerts]

            results.append(d)

        db.close()
        return success(data=results)

    except Exception as e:
        if 'db' in locals(): db.close()
        return error("Failed to retrieve log events", exception=e, status_code=500)



# -------------------------------------------
# GET /api/logs/internal
# Returns internal HIDS application logs
# -------------------------------------------

@logs_api.get("/internal")
def get_internal_logs():
    INTERNAL_LOG_PATH = "/var/log/hids/app.log"
    logger.debug(f"[logs/internal] Reading internal logs from {INTERNAL_LOG_PATH}")

    try:
        if not os.path.exists(INTERNAL_LOG_PATH):
            logger.warning("[logs/internal] Internal log file not found")
            return success(message="Internal log file not found", data="")

        MAX_LINES = 500
        MAX_BYTES = 50000  # 50 KB limit

        with open(INTERNAL_LOG_PATH, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()

            if file_size <= MAX_BYTES:
                f.seek(0)
                raw = f.read()
            else:
                f.seek(-MAX_BYTES, os.SEEK_END)
                raw = f.read()

        text = raw.decode(errors="ignore")
        lines = text.splitlines()

        content = "\n".join(lines[-MAX_LINES:])

        logger.info(f"[logs/internal] Returning last {len(lines[-MAX_LINES:])} lines (max {MAX_BYTES} bytes)")

        return success(data=content)

    except Exception as e:
        logger.exception(f"[logs/internal] Unhandled exception: {e}")
        return error("Failed to read internal logs", exception=e, status_code=500)
