# metrics_api.py

from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.database import SessionLocal
from backend.models.metric_model import MetricModel


metrics_api = Blueprint("metrics_api", __name__)


# -------------------------------------------
# GET /api/metrics/latest
# Returns latest METRIC_SNAPSHOT stored in DB
# -------------------------------------------
@metrics_api.get("/latest")
def get_latest_metrics():
    try:
        db = SessionLocal()
        latest = (
            db.query(MetricModel)
            .order_by(MetricModel.timestamp.desc())
            .first()
        )
        db.close()

        if not latest:
            return success(message="No metric snapshots recorded yet.", data=None)

        return success(data=latest.to_dict())

    except Exception as e:
        return error("Failed to retrieve latest metrics", exception=e, status_code=500)



# -------------------------------------------
# GET /api/metrics/timeline?limit=50
# Returns N most recent metric snapshots for graphing
# -------------------------------------------
@metrics_api.get("/timeline")
def metrics_timeline():
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

        # En güncelden eskiye → biz ters çevirelim, grafikler soldan sağa akar
        rows = rows[::-1]

        data = [row.to_dict() for row in rows]

        return success(data=data)

    except Exception as e:
        return error("Failed to retrieve metric timeline", exception=e, status_code=500)
