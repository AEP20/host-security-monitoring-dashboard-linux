from flask import Blueprint
import psutil
import time

from backend.api.utils.response_wrapper import success, error

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
@system_api.get("/status")
def system_status():
    print("[DEBUG][system_status] Called /api/status endpoint")

    try:
        cpu_percent = psutil.cpu_percent(interval=0.15)
        mem = psutil.virtual_memory()

        print(f"[DEBUG][system_status] CPU={cpu_percent}%, MEM={mem.percent}%")

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

        print("[DEBUG][system_status] Returning success")
        return success(data=data)

    except Exception as e:
        print(f"[ERROR][system_status] Exception: {e}")
        return error("Failed to retrieve system status", exception=e)


# -------------------------------------------
#             THREAD HEALTH
# -------------------------------------------

from threading import enumerate as list_threads
last_heartbeats = {}

@system_api.get("/threads")
def get_thread_health():
    print("[DEBUG][threads] Called /api/threads")

    threads = []
    now = time.time()

    for t in list_threads():
        hb = last_heartbeats.get(t.name)

        print(f"[DEBUG][threads] {t.name}: alive={t.is_alive()}, hb={hb}")

        hb_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(hb)) if hb else "N/A"

        threads.append({
            "name": t.name,
            "alive": t.is_alive(),
            "last_heartbeat": hb_str,
        })

    print(f"[DEBUG][threads] Returning {len(threads)} threads")
    return success(data=threads)
