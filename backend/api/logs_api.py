# logs_api.py


from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.database import SessionLocal
from backend.models.log_model import LogEventModel
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
    logger.debug(f"[logs/events] Query params: {dict(request.args)}")

    try:
        db = SessionLocal()

        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))

        query = db.query(LogEventModel).order_by(LogEventModel.timestamp.desc())

        # filters debug
        for name in ["severity", "source", "category", "event_type", "search"]:
            if request.args.get(name):
                logger.debug(f"[logs/events] Applying filter {name}={request.args.get(name)}")

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
            logger.debug(f"[logs/events] Search term applied: {term}")

        rows = query.limit(limit).offset(offset).all()
        db.close()

        logger.info(f"[logs/events] Returned {len(rows)} events (limit={limit}, offset={offset})")

        return success(data=[row.to_dict() for row in rows])

    except Exception as e:
        logger.exception(f"[logs/events] Unhandled exception: {e}")
        return error("Failed to retrieve log events", exception=e, status_code=500)



# -------------------------------------------
# GET /api/logs/internal
# Returns internal HIDS application logs
# -------------------------------------------

@logs_api.get("/internal")
def get_internal_logs():
    INTERNAL_LOG_PATH = "/var/log/hids/app.log"
    # print(f"[DEBUG][logs/internal] Reading internal logs from {INTERNAL_LOG_PATH}")
    logger.debug(f"[logs/internal] Reading internal logs from {INTERNAL_LOG_PATH}")

    try:
        if not os.path.exists(INTERNAL_LOG_PATH):
            logger.warning("[logs/internal] Internal log file not found")
            return success(message="Internal log file not found", data="")

        with open(INTERNAL_LOG_PATH, "r") as f:
            content = f.read()

        logger.info("[logs/internal] Returning internal log content")

        return success(data=content)

    except Exception as e:
        logger.exception(f"[logs/internal] Unhandled exception: {e}")
        return error("Failed to read internal logs", exception=e, status_code=500)
