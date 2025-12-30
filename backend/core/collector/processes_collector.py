#process_collector

# Çalışan process’leri toplamak.
# psutil ile process listesi
# CPU / RAM tüketimi
# process path’i (binary nerede)
# user (root mu vs.)

# 📌 A) psutil

# Process toplamada psutil kullanılır:
# psutil.process_iter()
# psutil.Process(pid).as_dict()
# cpu_percent()
# memory_info()
# create_time()
# exe(), cmdline(), username()
# connections() (opsiyonel)

# Görev Tablosu
# Aşağıdaki tablo Process Collector’ın üretmesi gereken STATE ve EVENT verilerini gösterir:

# Görev	Tür	Açıklama
# Process snapshot	STATE	Sistemdeki tüm processlerin PID, exe, cmdline vb. anlık durumu
# Yeni process tespiti	EVENT	Önceki snapshot’ta olmayan PID → şu anda olan
# Process kapanması	EVENT	Önceki snapshot’ta olan PID → şu anda olmayan
# Process metadata değişimi	EVENT	Process var ama command/exe değişmiş (çok kritik, genelde malware)
# Process CPU/RAM usage	STATE	Per-process usage (rule engine CPU spike için kullanabilir)
# Parent-child ilişki	STATE	PID → PPID bağları
# Process start info	STATE	exe path, username, command-line arguments
# Malicious indicator flags	STATE	(opsiyonel) suspicious exe path, hidden process, deleted binary, vb.

# Toplanması Gereken Process Alanları
# pid
# ppid
# name
# exe
# cmdline
# username
# create_time
# cpu_percent
# memory_rss
# memory_vms
# cwd (opsiyonel)
# open_files (opsiyonel)
# connections (opsiyonel)


# C) Hangi Event’ler Oluşturulmalı?

# ✔ NEW_PROCESS
# Ör:
# PID 4432 yeni başladı
# exe: "/usr/bin/python3"
# cmdline: ["python3", "server.py"]

# ✔ TERMINATED_PROCESS
# Ör:
# PID 128 kapanmış
# runtime: 5.3s

# ✔ PROCESS_EXEC_CHANGED
# Process aynı PID ama binary değişmiş:
# Çok kritik → genelde process hijacking / binary swap göstergesi.

# ✔ CMDLINE_CHANGED
# PID aynı, exe aynı ama argümanlar değişmiş
# Kötü amaçlı injection veya process manipülasyonu olabilir.

# ✔ PROCESS_PRIV_ESCALATION (opsiyonel)
# Normal user’den root user’a geçen process (username değişimi)
# Bu OSSEC / Wazuh’ta default bir kuraldır.


# 1) Local JSON cache → previous snapshot olarak yüklenir
# Cache’de sadece PID listesi ve temel metadata tutulur:
# /var/lib/hids-cache/process_prev.json

# 2) psutil ile current snapshot toplanır
# Tüm process bilgisi çıkarılır:
# pid → process.as_dict()
# cpu_percent
# memory_info
# exe + cmdline + username
# ppid ilişkisi

# 3) previous vs current → diff yapılır
# Yeni PID var mı? → NEW_PROCESS
# Eksik PID var mı? → TERMINATED_PROCESS
# PID aynı ama exe değişmiş mi?
# PID aynı ama cmdline değişmiş mi?
# PID aynı ama username değişmiş mi? (priv escalation)

# 4) Event üretilir ve DB / message queue’ya gönderilir
# Event örneği:
# {
#   "type": "NEW_PROCESS",
#   "pid": 4432,
#   "exe": "/usr/bin/python3",
#   "cmdline": ["python3", "server.py"],
#   "username": "www-data",
#   "timestamp": ...
# }
# 5) current snapshot → RAM’de previous olarak overwrite edilir
# self.previous = current

# 6) current snapshot → local cache’e overwrite edilir
# Cache sayesinde collector restart edilirse diff kaybolmaz.

import psutil
import json
import os
import time
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.logger import logger

CACHE_PATH = "/var/lib/hids-cache/process_prev.json"

class ProcessCollector:
    """
    ProcessCollector
    ----------------
    - psutil ile process snapshot toplar
    - previous snapshot ile diff alıp event üretir
    - previous snapshot'ı local JSON cache'te saklar
    - snapshot'ları DB'ye YAZMAZ, sadece event üretir (DB işi başka layer'ın)
    """

    def __init__(
        self,
        cache_path: str = CACHE_PATH,
        include_hash: bool = False,
        include_details: bool = False,
    ) -> None:
        self.cache_path = cache_path
        self.include_hash = include_hash
        self.include_details = include_details

        self._hash_cache: Dict[str, Optional[str]] = {}
        self.previous: Dict[str, Dict[str, Any]] = self.load_previous()

        logger.info(
            f"[ProcessCollector] Initialized (hash={include_hash}, details={include_details}) "
            f"cache={cache_path}"
        )

    # ---------------------------------------------------
    # 1) PREVIOUS SNAPSHOT LOAD
    # ---------------------------------------------------
    def load_previous(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(self.cache_path):
            logger.warning("[ProcessCollector] No previous snapshot found")
            return {}

        try:
            with open(self.cache_path, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    logger.debug("[ProcessCollector] Loaded previous snapshot")
                    return data
                return {}
        except Exception as e:
            logger.error(f"[ProcessCollector] Failed loading previous snapshot: {e}")
            return {}

    # ---------------------------------------------------
    # 2) WRITE CACHE
    # ---------------------------------------------------
    def save_previous(self, snapshot: Dict[str, Dict[str, Any]]) -> None:
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w") as f:
                json.dump(snapshot, f)
            logger.debug("[ProcessCollector] Snapshot saved to cache")
        except Exception as e:
            logger.error(f"[ProcessCollector] Failed saving snapshot: {e}")

    # ---------------------------------------------------
    # 3) EXE HASH HELPER FUNC
    # ---------------------------------------------------
    def _hash_executable(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None
        if path in self._hash_cache:
            return self._hash_cache[path]

        try:
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
                self._hash_cache[path] = digest
                logger.debug(f"[ProcessCollector] Computed exe hash for {path}")
                return digest
        except Exception:
            self._hash_cache[path] = None
            logger.warning(f"[ProcessCollector] Unable to hash executable: {path}")
            return None

    # ---------------------------------------------------
    # 4) CURRENT SNAPSHOT FETCH
    # ---------------------------------------------------
    def collect_snapshot(self) -> Dict[str, Dict[str, Any]]:
        logger.debug("[ProcessCollector] Collecting process snapshot")
        snapshot: Dict[str, Dict[str, Any]] = {}
        now = time.time()

        for p in psutil.process_iter(
            attrs=[
                "pid",
                "ppid",
                "name",
                "exe",
                "cmdline",
                "username",
                "create_time",
                "status",
            ]
        ):
            try:
                info = p.info
                pid = info.get("pid")
                if pid is None:
                    continue

                pid_str = str(pid)
                cpu_percent = p.cpu_percent(interval=None)

                try:
                    mem = p.memory_info()
                    rss = mem.rss
                    vms = mem.vms
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rss = vms = None

                exe = info.get("exe")
                exe_deleted = False
                if exe and ("(deleted)" in exe or not os.path.exists(exe)):
                    exe_deleted = True

                cwd = None
                open_files = None
                if self.include_details:
                    try:
                        cwd = p.cwd()
                    except Exception:
                        pass
                    try:
                        open_files = [f.path for f in p.open_files()]
                    except Exception:
                        pass

                exe_hash = None
                if self.include_hash and exe and not exe_deleted:
                    exe_hash = self._hash_executable(exe)

                snapshot[pid_str] = {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "exe": exe,
                    "cmdline": info.get("cmdline"),
                    "username": info.get("username"),
                    "status": info.get("status"),
                    "create_time": info.get("create_time"),
                    "collected_at": now,
                    "cpu_percent": cpu_percent,
                    "memory_rss": rss,
                    "memory_vms": vms,
                    "exe_deleted": exe_deleted,
                    "exe_hash": exe_hash,
                    "cwd": cwd,
                    "open_files": open_files,
                }

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.error(f"[ProcessCollector] Unexpected error collecting process: {e}")
                continue

        logger.info(f"[ProcessCollector] Snapshot collected ({len(snapshot)} processes)")
        return snapshot

    # ---------------------------------------------------
    # 5) DIFF ENGINE
    # ---------------------------------------------------
    def diff_processes(
        self,
        previous: Dict[str, Dict[str, Any]],
        current: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        events: List[Dict[str, Any]] = []
        now_iso = datetime.utcnow().isoformat() + "Z"

        prev_pids = set(previous.keys())
        curr_pids = set(current.keys())

        new_pids = curr_pids - prev_pids
        terminated_pids = prev_pids - curr_pids
        common_pids = prev_pids & curr_pids

        if new_pids or terminated_pids:
            logger.info(
                f"[ProcessCollector] Diff detected: new={len(new_pids)}, terminated={len(terminated_pids)}"
            )

        for pid in new_pids:
            events.append({"type": "PROCESS_NEW", "timestamp": now_iso, **current[pid]})

        for pid in terminated_pids:
            p_prev = previous.get(pid, {})
            create_time = p_prev.get("create_time")
            try:
                run_time = time.time() - float(create_time) if create_time else None
            except Exception:
                run_time = None

            events.append(
                {
                    "type": "PROCESS_TERMINATED",
                    "timestamp": now_iso,
                    "pid": p_prev.get("pid"),
                    "ppid": p_prev.get("ppid"),
                    "name": p_prev.get("name"),
                    "exe": p_prev.get("exe"),
                    "username": p_prev.get("username"),
                    "create_time": create_time,
                    "run_time": run_time,
                }
            )

        for pid in common_pids:
            p_prev = previous[pid]
            p_curr = current[pid]

            if p_prev.get("exe") != p_curr.get("exe"):
                events.append(
                    {
                        "type": "PROCESS_EXEC_CHANGED",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "old": p_prev.get("exe"),
                        "new": p_curr.get("exe"),
                    }
                )

            if p_prev.get("cmdline") != p_curr.get("cmdline"):
                events.append(
                    {
                        "type": "PROCESS_CMDLINE_CHANGED",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "old": p_prev.get("cmdline"),
                        "new": p_curr.get("cmdline"),
                    }
                )

            if p_prev.get("username") != p_curr.get("username"):
                events.append(
                    {
                        "type": "PROCESS_PRIV_ESCALATION",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "old": p_prev.get("username"),
                        "new": p_curr.get("username"),
                    }
                )

            if p_prev.get("status") != p_curr.get("status"):
                events.append(
                    {
                        "type": "PROCESS_STATUS_CHANGED",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "old": p_prev.get("status"),
                        "new": p_curr.get("status"),
                    }
                )

            if p_curr.get("status") == psutil.STATUS_ZOMBIE:
                events.append(
                    {
                        "type": "PROCESS_ZOMBIE_PROCESS",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "name": p_curr.get("name"),
                        "exe": p_curr.get("exe"),
                        "username": p_curr.get("username"),
                    }
                )

            if not p_prev.get("exe_deleted") and p_curr.get("exe_deleted"):
                events.append(
                    {
                        "type": "PROCESS_EXEC_DELETED",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "exe": p_curr.get("exe"),
                        "username": p_curr.get("username"),
                    }
                )

            if (
                self.include_hash
                and p_prev.get("exe_hash") is not None
                and p_curr.get("exe_hash") is not None
                and p_prev.get("exe_hash") != p_curr.get("exe_hash")
            ):
                events.append(
                    {
                        "type": "PROCESS_EXEC_HASH_CHANGED",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "exe": p_curr.get("exe"),
                        "old_hash": p_prev.get("exe_hash"),
                        "new_hash": p_curr.get("exe_hash"),
                    }
                )

        logger.debug(f"[ProcessCollector] Diff produced {len(events)} events")
        return events

    # ---------------------------------------------------
    # 6) FOR SCHEDULER ONE STEP
    # ---------------------------------------------------
    def step(self) -> List[Dict[str, Any]]:
        logger.debug("[ProcessCollector] step() invoked")
        current = self.collect_snapshot()
        events = self.diff_processes(self.previous, current)

        self.previous = current
        self.save_previous(current)

        logger.info(f"[ProcessCollector] step() returned {len(events)} events")
        return events

    # ---------------------------------------------------
    # 7) MAIN LOOP
    # ---------------------------------------------------
    def run(self, interval: int = 10):
        logger.info(f"[ProcessCollector] Run loop started interval={interval}s")
        while True:
            events = self.step()
            for event in events:
                yield event
            time.sleep(interval)

    # ---------------------------------------------------
    # 8) TEST FUNC
    # ---------------------------------------------------
    def test_once(self) -> None:
        events = self.step()

        logger.info(f"[ProcessCollector] Test produced {len(events)} events")
        print("\n===== PROCESS COLLECTOR TEST =====\n")
        if not events:
            print("Herhangi bir event yok.")
        else:
            for e in events:
                print(f"[EVENT] {e['type']}")
                print(json.dumps(e, indent=2))

        print("\nSnapshot boyutu:", len(self.previous))
        print("Cache path:", self.cache_path)
        print("===================================\n")


if __name__ == "__main__":
    collector = ProcessCollector(
        cache_path=CACHE_PATH,
        include_hash=False,
        include_details=False,
    )
    collector.test_once()
