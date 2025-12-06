# backend/api/system_api.py

from flask import Blueprint
import psutil
import time

from backend.api.utils.response_wrapper import success, error


system_api = Blueprint("system_api", __name__)

# HIDS’in kendi çalışma süresi için (system uptime değil)
HIDS_START_TIME = time.time()


# -------------------------------------------
# Helper Functions
# -------------------------------------------

def get_hids_uptime_seconds():
    """HIDS uygulamasının ne kadar süredir çalıştığını döner."""
    return int(time.time() - HIDS_START_TIME)


def get_system_uptime_seconds():
    """Linux sisteminin ne kadar süredir açık olduğunu döner."""
    boot_time = psutil.boot_time()
    return int(time.time() - boot_time)


def get_thread_states():
    """
    Scheduler içerisindeki thread’lerin is_alive() durumunu döner.
    scheduler_instance → scheduler.start() içinde set edilir.
    """
    try:
        from backend.core.scheduler.scheduler import scheduler_instance

        if not scheduler_instance:
            return {"error": "Scheduler not initialized"}

        states = {}
        for idx, t in enumerate(scheduler_instance.threads):
            states[f"thread_{idx}"] = t.is_alive()

        return states

    except Exception as e:
        return {"exception": str(e)}


# -------------------------------------------
# System Status Endpoint
# -------------------------------------------

@system_api.get("/api/system/status")
def system_status():
    """
    Ana health-check endpoint.
    - CPU / Memory (real-time)
    - HIDS uptime
    - System uptime
    - Process count
    - Scheduler threads health
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=0.15)
        mem = psutil.virtual_memory()

        data = {
            "hids_uptime_seconds": get_hids_uptime_seconds(),
            "system_uptime_seconds": get_system_uptime_seconds(),

            "cpu_percent": cpu_percent,
            "memory_percent": mem.percent,
            "memory_used_mb": round(mem.used / 1024 / 1024, 2),
            "memory_total_mb": round(mem.total / 1024 / 1024, 2),

            "process_count": len(psutil.pids()),

            "scheduler_threads": get_thread_states(),
        }

        return success(data=data)

    except Exception as e:
        return error("Failed to retrieve system status", exception=e, status_code=500)

from threading import enumerate as list_threads
from backend.api.utils.response_wrapper import success

import time

last_heartbeats = {}  # scheduler update edecek


@system_api.get("/api/system/threads")
def get_thread_health():
    threads = []
    now = time.time()

    for t in list_threads():
        name = t.name
        alive = t.is_alive()

        hb = last_heartbeats.get(name)
        hb_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(hb)) if hb else "N/A"

        threads.append({
            "name": name,
            "alive": alive,
            "last_heartbeat": hb_str
        })

    return success(data=threads)
