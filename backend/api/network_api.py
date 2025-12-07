# backend/api/network_api.py

from flask import Blueprint, request
from backend.api.utils.response_wrapper import success, error
from backend.models.network_event_model import NetworkEventModel
from backend.database import SessionLocal
from backend.logger import logger
import psutil
import socket

network_api = Blueprint("network_api", __name__)


# ======================================================
# GET /api/network/events  → tüm network event geçmişi
# Filtreler:
#    ?type=NET_NEW_CONNECTION
#    ?pid=123
#    ?protocol=tcp
# ======================================================
@network_api.get("/events")
def get_network_events():
    session = SessionLocal()
    try:
        q = session.query(NetworkEventModel)

        # filtreler
        event_type = request.args.get("type")
        pid = request.args.get("pid")
        protocol = request.args.get("protocol")

        if event_type:
            q = q.filter(NetworkEventModel.event_type == event_type)

        if pid:
            q = q.filter(NetworkEventModel.pid == int(pid))

        if protocol:
            q = q.filter(NetworkEventModel.protocol == protocol)

        q = q.order_by(NetworkEventModel.timestamp.desc())
        rows = [r.to_dict() for r in q.all()]

        return success(data=rows)

    except Exception as e:
        logger.exception("Failed to fetch network events")
        return error("Failed to load network events", exception=e)
    finally:
        session.close()


# ======================================================
# GET /api/network/events/<id> → tek event
# ======================================================
@network_api.get("/events/<int:event_id>")
def get_network_event_detail(event_id):
    session = SessionLocal()
    try:
        row = session.query(NetworkEventModel).get(event_id)
        if not row:
            return error("Network event not found")

        return success(data=row.to_dict())

    except Exception as e:
        logger.exception("Failed to load network event detail")
        return error("Failed to load event", exception=e)
    finally:
        session.close()


# ======================================================
# GET /api/network/active → aktif network bağlantıları (snapshot)
# psutil → ESTABLISHED, LISTEN vs.
# ======================================================
@network_api.get("/active")
def active_network_connections():
    try:
        conns = psutil.net_connections(kind="inet")
        results = []

        for c in conns:
            l_ip = getattr(c.laddr, "ip", None) if c.laddr else None
            l_port = getattr(c.laddr, "port", None) if c.laddr else None
            r_ip = getattr(c.raddr, "ip", None) if c.raddr else None
            r_port = getattr(c.raddr, "port", None) if c.raddr else None

            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"

            try:
                pname = psutil.Process(c.pid).name() if c.pid else "unknown"
            except Exception:
                pname = "unknown"

            results.append({
                "pid": c.pid,
                "process_name": pname,
                "protocol": proto,
                "laddr_ip": l_ip,
                "laddr_port": l_port,
                "raddr_ip": r_ip,
                "raddr_port": r_port,
                "status": c.status,
            })

        return success(data=results)

    except Exception as e:
        logger.exception("Failed to fetch active network snapshot")
        return error("Failed to fetch active connections", exception=e)
