# metrics_collector.py
# CPU, RAM, disk, network vb bilgisi toplamak.

# Nasıl çalışmalı?
# psutil:
# cpu_percent()
# virtual_memory()
# disk_usage()
# load average
# Snapshot (anlık görüntü)

# <!-- | Collector      | Önerilen Zaman          |
# | -------------- | ----------------------- |
# | metrics        | 60 sn                   |
# | processes      | 10–30 sn                |
# | network        | 10 sn                   |
# | logs           | 2 sn (en hızlı büyüyen) |
# | config checker | 15–30 dk                | -->


# <!-- | Collector | Veri tipi  | Parsing    | Rule Engine            | DB                  |
# | --------- | ---------- | ---------- | ---------------------- | ------------------- |
# | Logs      | ham text   | ✔️ gerekli | ✔️                     | log_events          |
# | Metrics   | structured | ❌          | ✔️ (usage alert)       | metrics             |
# | Network   | structured | ❌          | ✔️ (port exposure)     | network_connections |
# | Process   | structured | ❌          | ✔️ (malicious process) | processes           | -->


# <!-- | Collector            | Parser var mı? | DB’ye yazar mı?   | Rule Engine kullanır mı?   |
# | -------------------- | -------------- | ----------------- | -------------------------- |
# | **LogCollector**     | ✔ Evet         | ✔ Evet            | ✔ Evet                     |
# | **MetricsCollector** | ✖ Hayır        | ✔ Snapshot yazar  | ✔ Evet                     |
# | **ProcessCollector** | ✖ Hayır        | ✖ Snapshot yazmaz | ✔ Evet (snapshot kullanır) |
# | **NetworkCollector** | ✖ Hayır        | ✖ Snapshot yazmaz | ✔ Evet (snapshot kullanır) | -->

import os
import time
import psutil


class MetricsCollector:

    def __init__(self, include_per_disk=False, include_per_nic=False):
        self.include_per_disk = include_per_disk
        self.include_per_nic = include_per_nic
        print(f"[DEBUG][MetricsCollector] Initialized include_per_disk={include_per_disk}, include_per_nic={include_per_nic}")

    # Public API
    def collect(self):
        print("[DEBUG][MetricsCollector] collect() called")
        return self.snapshot()

    def snapshot(self):
        now = time.time()
        print(f"[DEBUG][MetricsCollector] snapshot() started at {now}")

        cpu = self._collect_cpu()
        mem = self._collect_memory()
        disk = self._collect_disk()
        net = self._collect_network()
        sysinfo = self._collect_system()

        print("[DEBUG][MetricsCollector] snapshot() completed — CPU/MEM/DISK/NET/SYS collected")

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
        print("[DEBUG][MetricsCollector][CPU] Collecting CPU metrics")

        total_percent = psutil.cpu_percent(interval=0.1)
        per_cpu_percent = psutil.cpu_percent(interval=None, percpu=True)

        load1 = load5 = load15 = None
        if hasattr(os, "getloadavg"):
            try:
                load1, load5, load15 = os.getloadavg()
            except OSError:
                print("[WARN][MetricsCollector][CPU] getloadavg() not available")
                pass

        print(f"[DEBUG][MetricsCollector][CPU] total_percent={total_percent}, load1={load1}")

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
        print("[DEBUG][MetricsCollector][MEM] Collecting memory metrics")

        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        print(f"[DEBUG][MetricsCollector][MEM] ram_used={mem.used}, ram_percent={mem.percent}")

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
        print(f"[DEBUG][MetricsCollector][DISK] Collecting disk metrics (per-disk={self.include_per_disk})")

        disks = []

        if self.include_per_disk:
            for part in psutil.disk_partitions(all=False):
                mount = part.mountpoint
                try:
                    usage = psutil.disk_usage(mount)
                except PermissionError:
                    print(f"[WARN][MetricsCollector][DISK] Permission denied for mount {mount}")
                    continue

                print(f"[DEBUG][MetricsCollector][DISK] {mount}: used={usage.used}, percent={usage.percent}")

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
                print(f"[DEBUG][MetricsCollector][DISK] root/: used={usage.used}, percent={usage.percent}")

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
                print(f"[ERROR][MetricsCollector][DISK] Failed to read disk '/': {e}")
                pass

        return disks

    # ---------------------------------------------------
    # NETWORK IO (NOT CONNECTIONS)
    # ---------------------------------------------------
    def _collect_network(self):
        print(f"[DEBUG][MetricsCollector][NET] Collecting network IO (per_nic={self.include_per_nic})")

        net = psutil.net_io_counters(pernic=self.include_per_nic)

        if self.include_per_nic:
            result = {}
            for iface, stats in net.items():
                print(f"[DEBUG][MetricsCollector][NET] iface {iface}: sent={stats.bytes_sent}, recv={stats.bytes_recv}")
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

        print(f"[DEBUG][MetricsCollector][NET] sent={net.bytes_sent}, recv={net.bytes_recv}")

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
    # SYSTEM INFO (NO PROCESS DATA)
    # ---------------------------------------------------
    def _collect_system(self):
        print("[DEBUG][MetricsCollector][SYS] Collecting system info")

        boot_time = psutil.boot_time()
        now = time.time()
        uptime_seconds = now - boot_time

        print(f"[DEBUG][MetricsCollector][SYS] uptime_seconds={uptime_seconds}")

        return {
            "type": "METRIC_SNAPSHOT",
            "boot_time": boot_time,
            "uptime_seconds": uptime_seconds,
        }


# Lokal test için
if __name__ == "__main__":
    import json
    collector = MetricsCollector(include_per_disk=True, include_per_nic=False)
    snapshot = collector.snapshot()
    print(json.dumps(snapshot, indent=2))
