from flask import Blueprint
import psutil
import time

from backend.api.utils.response_wrapper import success, error
from backend.logger import logger

system_api = Blueprint("system_api", __name__)

HIDS_START_TIME = time.time()

def get_hids_uptime_seconds():
    return int(time.time() - HIDS_START_TIME)

def get_system_uptime_seconds():
    return int(time.time() - psutil.boot_time())

def get_thread_states():
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
#             SYSTEM STATUS
# -------------------------------------------
def format_seconds(seconds):
    mins, sec = divmod(int(seconds), 60)
    hrs, mins = divmod(mins, 60)
    days, hrs = divmod(hrs, 24)

    if days > 0:
        return f"{days}d {hrs}h {mins}m"
    elif hrs > 0:
        return f"{hrs}h {mins}m"
    else:
        return f"{mins}m"


@system_api.get("/status")
def system_status():
    logger.info("[system_status] System status endpoint called")

    try:
        cpu_percent = psutil.cpu_percent(interval=0.15)
        mem = psutil.virtual_memory()

        logger.debug(f"[system_status] CPU={cpu_percent}%, MEM={mem.percent}%")

        sys_up = get_system_uptime_seconds()

        data = {
            "hids_uptime_seconds": get_hids_uptime_seconds(),
            "system_uptime_seconds": sys_up,
            "system_uptime_human": format_seconds(sys_up),

            "cpu_percent": cpu_percent,
            "memory_percent": mem.percent,
            "memory_used_mb": round(mem.used / 1024 / 1024, 2),
            "memory_total_mb": round(mem.total / 1024 / 1024, 2),

            "process_count": len(psutil.pids()),
            "scheduler_threads": get_thread_states(),
        }

        logger.info("[system_status] Returning system status successfully")
        return success(data=data)

    except Exception as e:
        logger.exception(f"[system_status] Exception occurred: {e}")
        return error("Failed to retrieve system status", exception=e)


# -------------------------------------------
#             THREAD HEALTH
# -------------------------------------------

from threading import enumerate as list_threads
last_heartbeats = {}

@system_api.get("/threads")
def get_thread_health():
    logger.info("[threads] Thread health endpoint called")

    threads = []
    now = time.time()

    from backend.core.scheduler.scheduler import scheduler_instance

    scheduler_hb = {}
    if scheduler_instance:
        scheduler_hb = scheduler_instance.heartbeat  

    for t in list_threads():
        hb = scheduler_hb.get(t.name)  # ← doğru kaynağı oku

        hb_str = (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(hb))
            if hb else "N/A"
        )

        threads.append({
            "name": t.name,
            "alive": t.is_alive(),
            "last_heartbeat": hb_str,
        })

    return success(data=threads)
