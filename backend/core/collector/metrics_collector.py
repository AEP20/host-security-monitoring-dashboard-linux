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

    
    def collect(self):
     
        return self.snapshot()

    def snapshot(self):
        """
        Anlık sistem metriklerini tek bir dict içinde toplar.
        """
        now = time.time()

        return {
            "timestamp": now,
            "cpu": self._collect_cpu(),
            "memory": self._collect_memory(),
            "disk": self._collect_disk(),
            "network": self._collect_network(),
            "system": self._collect_system(),
        }

    # ---- Internal helpers ----

    def _collect_cpu(self):
        """
        CPU kullanım bilgisi + load average.
        """
        
        total_percent = psutil.cpu_percent(interval=0.1)
        per_cpu_percent = psutil.cpu_percent(interval=None, percpu=True)

        load1 = load5 = load15 = None
        if hasattr(os, "getloadavg"):
            try:
                load1, load5, load15 = os.getloadavg()
            except OSError:
                
                pass

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

    def _collect_memory(self):
        """
        RAM + swap kullanımı.
        """
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

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

    def _collect_disk(self):
    
        disks = []

        if self.include_per_disk:
            for part in psutil.disk_partitions(all=False):
                mount = part.mountpoint
                try:
                    usage = psutil.disk_usage(mount)
                except PermissionError:
              
                    continue

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
            except Exception:
                pass

        return disks

    def _collect_network(self):
    
        net = psutil.net_io_counters(pernic=self.include_per_nic)

        if self.include_per_nic:
            # Her interface için ayrı ayrı
            result = {}
            for iface, stats in net.items():
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

        # Sistem genel toplam
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

    def _collect_system(self):
      
        boot_time = psutil.boot_time()
        now = time.time()
        uptime_seconds = now - boot_time

        # Process sayısı – çok ağır olmaması için sadece pids uzunluğunu al
        try:
            process_count = len(psutil.pids())
        except Exception:
            process_count = None

        return {
            "boot_time": boot_time,
            "uptime_seconds": uptime_seconds,
            "process_count": process_count,
        }


# Lokal test için: python metrics_collector.py
if __name__ == "__main__":
    import json

    collector = MetricsCollector(include_per_disk=True, include_per_nic=False)
    snapshot = collector.snapshot()
    print(json.dumps(snapshot, indent=2))
