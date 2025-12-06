# metrics_api.py

from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.database import SessionLocal
from backend.models.metric_model import MetricModel
from backend.logger import logger


metrics_api = Blueprint("metrics_api", __name__)


# -------------------------------------------
# GET /api/metrics/latest
# Returns latest METRIC_SNAPSHOT stored in DB
# -------------------------------------------

@metrics_api.get("/latest")
def get_latest_metrics():
    logger.debug("[metrics/latest] Querying latest metric snapshot")

    try:
        db = SessionLocal()
        latest = (
            db.query(MetricModel)
            .order_by(MetricModel.timestamp.desc())
            .first()
        )
        db.close()

        logger.info(f"[metrics/latest] Latest metric found: {bool(latest)}")

        if not latest:
            return success(data=None)

        # -----------------------------
        #  EXTRACT FIELDS FOR DASHBOARD
        # -----------------------------
        snap = latest.to_dict().get("snapshot", {})

        cpu_percent = snap.get("cpu", {}).get("total_percent")
        ram_percent = snap.get("memory", {}).get("ram", {}).get("percent")
        uptime_seconds = snap.get("system", {}).get("uptime_seconds")
        timestamp = latest.timestamp.isoformat()

        enriched = {
            **latest.to_dict(),
            "cpu_percent": cpu_percent,
            "ram_percent": ram_percent,
            "uptime_seconds": uptime_seconds,
            "timestamp": timestamp,
        }

        logger.debug("[metrics/latest] Metric enrichment completed")

        return success(data=enriched)

    except Exception as e:
        logger.exception(f"[metrics/latest] Exception: {e}")
        return error("Failed to retrieve latest metrics", exception=e, status_code=500)




# -------------------------------------------
# GET /api/metrics/timeline?limit=50
# Returns N most recent metric snapshots for graphing
# -------------------------------------------

@metrics_api.get("/timeline")
def metrics_timeline():
    logger.debug(f"[metrics/timeline] Called with limit={request.args.get('limit')}")

    try:
        limit = int(request.args.get("limit", 50))

        db = SessionLocal()
        rows = (
            db.query(MetricModel)
            .order_by(MetricModel.timestamp.desc())
            .limit(limit)
            .all()
        )
        db.close()

        logger.info(f"[metrics/timeline] Retrieved {len(rows)} rows")

        rows = rows[::-1]
        return success(data=[row.to_dict() for row in rows])

    except Exception as e:
        logger.exception(f"[metrics/timeline] Exception: {e}")
        return error("Failed to retrieve metric timeline", exception=e, status_code=500)
