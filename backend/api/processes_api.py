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
    logger.debug("[API][PROCESS_EVENTS] Request received")

    start_ts = time.time()
    session = None

    try:
        logger.debug("[API][PROCESS_EVENTS] Creating DB session")
        session = SessionLocal()

        logger.debug("[API][PROCESS_EVENTS] Building query")
        q = session.query(ProcessEventModel)

        # filtreler
        event_type = request.args.get("type")
        pid = request.args.get("pid")

        if event_type:
            logger.debug(f"[API][PROCESS_EVENTS] Filter type={event_type}")
            q = q.filter(ProcessEventModel.event_type == event_type)

        if pid:
            logger.debug(f"[API][PROCESS_EVENTS] Filter pid={pid}")
            q = q.filter(ProcessEventModel.pid == int(pid))

        logger.debug("[API][PROCESS_EVENTS] Ordering query")
        q = q.order_by(ProcessEventModel.timestamp.desc())

        logger.debug("[API][PROCESS_EVENTS] Executing query (q.all())")
        rows_raw = q.all()   # 👈 MUHTEMEL KİLİTLENEN YER

        logger.debug(f"[API][PROCESS_EVENTS] Query returned {len(rows_raw)} rows")

        logger.debug("[API][PROCESS_EVENTS] Serializing rows")
        rows = [r.to_dict() for r in rows_raw]

        elapsed = round(time.time() - start_ts, 3)
        logger.info(f"[API][PROCESS_EVENTS] OK ({elapsed}s) rows={len(rows)}")

        return success(data=rows)

    except Exception as e:
        logger.exception("[API][PROCESS_EVENTS] Failed")
        return error("Failed to load process events", exception=e)

    finally:
        if session:
            logger.debug("[API][PROCESS_EVENTS] Closing DB session")
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