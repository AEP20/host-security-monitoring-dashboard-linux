# logs_api.py


from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.database import SessionLocal
from backend.models.log_model import LogEventModel
import os

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

        # Pagination
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))

        # Filters
        severity = request.args.get("severity")
        source = request.args.get("source")
        category = request.args.get("category")
        event_type = request.args.get("event_type")
        search = request.args.get("search")

        query = db.query(LogEventModel).order_by(LogEventModel.timestamp.desc())

        if severity:
            query = query.filter(LogEventModel.severity == severity)

        if source:
            query = query.filter(LogEventModel.log_source == source)

        if category:
            query = query.filter(LogEventModel.category == category)

        if event_type:
            query = query.filter(LogEventModel.event_type == event_type)

        if search:
            search_term = f"%{search}%"
            query = query.filter(LogEventModel.message.ilike(search_term))

        rows = query.limit(limit).offset(offset).all()
        db.close()

        data = [row.to_dict() for row in rows]

        return success(data=data)

    except Exception as e:
        return error("Failed to retrieve log events", exception=e, status_code=500)



# -------------------------------------------
# GET /api/logs/internal
# Returns internal HIDS application logs
# -------------------------------------------
@logs_api.get("/internal")
def get_internal_logs():
    """
    Reads internal log file (HIDS debugging logs).
    Useful during development & monitoring.
    """

    INTERNAL_LOG_PATH = "/var/log/hids/app.log"

    try:
        if not os.path.exists(INTERNAL_LOG_PATH):
            return success(
                message="Internal log file not found",
                data=""
            )

        with open(INTERNAL_LOG_PATH, "r") as f:
            content = f.read()

        return success(data=content)

    except Exception as e:
        return error("Failed to read internal logs", exception=e, status_code=500)
