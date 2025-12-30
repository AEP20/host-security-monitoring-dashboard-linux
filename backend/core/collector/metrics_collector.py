# metrics_collector.py
# CPU, RAM, disk, network vb bilgisi toplamak.

# Nasıl çalışmalı?
# psutil:
# cpu_percent()
# virtual_memory()
# disk_usage()
# load average
# Snapshot (anlık görüntü)

import os
import time
import psutil
from backend.logger import logger


class MetricsCollector:

    def __init__(self, include_per_disk=False, include_per_nic=False):
        self.include_per_disk = include_per_disk
        self.include_per_nic = include_per_nic
        logger.info(f"[MetricsCollector] Initialized (per_disk={include_per_disk}, per_nic={include_per_nic})")

    # Public API
    def collect(self):
        logger.debug("[MetricsCollector] collect() invoked")
        return self.snapshot()

    def snapshot(self):
        now = time.time()
        logger.debug(f"[MetricsCollector] Snapshot started at {now}")

        cpu = self._collect_cpu()
        mem = self._collect_memory()
        disk = self._collect_disk()
        net = self._collect_network()
        sysinfo = self._collect_system()

        logger.info("[MetricsCollector] Snapshot completed successfully")

        return {
            "type": "METRIC_SNAPSHOT",
            "timestamp": now,
            "cpu": cpu,
            "memory": mem,
            "disk": disk,
            "network": net,
            "system": sysinfo,
        }

    # ---------------------------------------------------
    # CPU
    # ---------------------------------------------------
    def _collect_cpu(self):
        logger.debug("[MetricsCollector][CPU] Collecting CPU metrics")

        total_percent = psutil.cpu_percent(interval=0.1)
        per_cpu_percent = psutil.cpu_percent(interval=None, percpu=True)

        load1 = load5 = load15 = None
        if hasattr(os, "getloadavg"):
            try:
                load1, load5, load15 = os.getloadavg()
            except OSError:
                logger.warning("[MetricsCollector][CPU] getloadavg() unavailable")
                pass

        logger.debug(f"[MetricsCollector][CPU] total_percent={total_percent}, load1={load1}")

        return {
            "total_percent": total_percent,
            "per_cpu_percent": per_cpu_percent,
            "load_average": {
                "1m": load1,
                "5m": load5,
                "15m": load15,
            },
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
        }

    # ---------------------------------------------------
    # MEMORY
    # ---------------------------------------------------
    def _collect_memory(self):
        logger.debug("[MetricsCollector][MEM] Collecting memory metrics")

        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        logger.debug(f"[MetricsCollector][MEM] ram_percent={mem.percent}")

        return {
            "ram": {
                "total": mem.total,
                "used": mem.used,
                "available": mem.available,
                "free": mem.free,
                "percent": mem.percent,
            },
            "swap": {
                "total": swap.total,
                "used": swap.used,
                "free": swap.free,
                "percent": swap.percent,
            },
        }

    # ---------------------------------------------------
    # DISK
    # ---------------------------------------------------
    def _collect_disk(self):
        logger.debug(f"[MetricsCollector][DISK] Collecting disk metrics (per_disk={self.include_per_disk})")

        disks = []

        if self.include_per_disk:
            for part in psutil.disk_partitions(all=False):
                mount = part.mountpoint
                try:
                    usage = psutil.disk_usage(mount)
                except PermissionError:
                    logger.warning(f"[MetricsCollector][DISK] Permission denied for mount {mount}")
                    continue

                logger.debug(f"[MetricsCollector][DISK] {mount}: percent={usage.percent}")

                disks.append(
                    {
                        "mount": mount,
                        "fstype": part.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent,
                    }
                )
        else:
            try:
                usage = psutil.disk_usage("/")
                logger.debug(f"[MetricsCollector][DISK] root: percent={usage.percent}")

                disks.append(
                    {
                        "mount": "/",
                        "fstype": None,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent,
                    }
                )
            except Exception as e:
                logger.error(f"[MetricsCollector][DISK] Failed to read '/': {e}")
                pass

        return disks

    # ---------------------------------------------------
    # NETWORK IO
    # ---------------------------------------------------
    def _collect_network(self):
        logger.debug(f"[MetricsCollector][NET] Collecting network IO (per_nic={self.include_per_nic})")

        net = psutil.net_io_counters(pernic=self.include_per_nic)

        if self.include_per_nic:
            result = {}
            for iface, stats in net.items():
                logger.debug(f"[MetricsCollector][NET] iface={iface}, sent={stats.bytes_sent}, recv={stats.bytes_recv}")
                result[iface] = {
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv,
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv,
                    "errin": stats.errin,
                    "errout": stats.errout,
                    "dropin": stats.dropin,
                    "dropout": stats.dropout,
                }
            return result

        logger.debug(f"[MetricsCollector][NET] sent={net.bytes_sent}, recv={net.bytes_recv}")

        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "errin": net.errin,
            "errout": net.errout,
            "dropin": net.dropin,
            "dropout": net.dropout,
        }

    # ---------------------------------------------------
    # SYSTEM INFO
    # ---------------------------------------------------
    def _collect_system(self):
        logger.debug("[MetricsCollector][SYS] Collecting system info")

        boot_time = psutil.boot_time()
        now = time.time()
        uptime_seconds = now - boot_time

        logger.debug(f"[MetricsCollector][SYS] uptime_seconds={uptime_seconds}")

        return {
            "type": "METRIC_SNAPSHOT",
            "boot_time": boot_time,
            "uptime_seconds": uptime_seconds,
        }


# Lokal test
if __name__ == "__main__":
    import json
    collector = MetricsCollector(include_per_disk=True, include_per_nic=False)
    snapshot = collector.snapshot()
    print(json.dumps(snapshot, indent=2))
