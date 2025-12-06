from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.models.process_event_model import ProcessEventModel
from backend.database import SessionLocal
from backend.logger import logger
import psutil

process_api = Blueprint("process_api", __name__)


# ======================================================
# GET /api/process/events → tüm event geçmişi
# ======================================================
@process_api.get("/events")
def get_process_events():
    session = SessionLocal()
    try:
        q = session.query(ProcessEventModel)

        # filtreler
        event_type = request.args.get("type")
        pid = request.args.get("pid")

        if event_type:
            q = q.filter(ProcessEventModel.event_type == event_type)

        if pid:
            q = q.filter(ProcessEventModel.pid == int(pid))

        q = q.order_by(ProcessEventModel.timestamp.desc())
        rows = [r.to_dict() for r in q.all()]

        return success(data=rows)

    except Exception as e:
        logger.exception("Failed to fetch process events")
        return error("Failed to load process events", exception=e)

    finally:
        session.close()


# ======================================================
# GET /api/process/events/<id> → tek event
# ======================================================
@process_api.get("/events/<int:event_id>")
def get_event_detail(event_id):
    session = SessionLocal()
    try:
        row = session.query(ProcessEventModel).get(event_id)
        if not row:
            return error("Event not found")

        return success(data=row.to_dict())

    except Exception as e:
        logger.exception("Failed to fetch event detail")
        return error("Error loading event", exception=e)

    finally:
        session.close()


# ======================================================
# GET /api/process/active → şu an çalışan process'ler
# (psutil snapshot)
# ======================================================
@process_api.get("/active")
def active_processes():
    try:
        listing = []
        for p in psutil.process_iter():
            try:
                with p.oneshot():
                    listing.append({
                        "pid": p.pid,
                        "name": p.name(),
                        "cmdline": " ".join(p.cmdline()) if p.cmdline() else "",
                        "cpu": p.cpu_percent(interval=0.0),
                        "mem": p.memory_percent(),
                        "username": p.username(),
                    })
            except Exception:
                continue

        return success(data=listing)

    except Exception as e:
        logger.exception("Failed to fetch active processes")
        return error("Active process fetch failed", exception=e)


# ======================================================
# DELETE /api/process/<pid> → kill
# ======================================================
@process_api.delete("/<int:pid>")
def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.kill()
        return success(message=f"Process {pid} terminated")

    except psutil.NoSuchProcess:
        return error("Process not found")

    except psutil.AccessDenied:
        return error("Access denied")

    except Exception as e:
        logger.exception("Kill failed")
        return error("Failed to kill process", exception=e)