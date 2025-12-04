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
        """
        :param cache_path: previous snapshot'ın saklanacağı JSON dosyası
        :param include_hash: exe path için SHA256 hash hesaplasın mı?
        :param include_details: cwd, open_files gibi extra detaylar
        """
        self.cache_path = cache_path
        self.include_hash = include_hash
        self.include_details = include_details

        # exe_path -> sha256 cache
        self._hash_cache: Dict[str, Optional[str]] = {}

        # PID -> process snapshot
        self.previous: Dict[str, Dict[str, Any]] = self.load_previous()

    # ---------------------------------------------------
    # 1) PREVIOUS SNAPSHOT YÜKLE
    # ---------------------------------------------------
    def load_previous(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(self.cache_path):
            return {}

        try:
            with open(self.cache_path, "r") as f:
                data = json.load(f)

                if isinstance(data, dict):
                    return data
                return {}
        except Exception:
            return {}

    # ---------------------------------------------------
    # 2) CACHE’E YAZ
    # ---------------------------------------------------
    def save_previous(self, snapshot: Dict[str, Dict[str, Any]]) -> None:

        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, "w") as f:
            json.dump(snapshot, f)

    # ---------------------------------------------------
    # 3) EXE HASH YARDIMCI FONKSİYONU
    # ---------------------------------------------------
    def _hash_executable(self, path: Optional[str]) -> Optional[str]:
        if not path:
            return None

        # cache
        if path in self._hash_cache:
            return self._hash_cache[path]

        try:
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
                self._hash_cache[path] = digest
                return digest
        except Exception:
            # erişilemiyorsa None
            self._hash_cache[path] = None
            return None

    # ---------------------------------------------------
    # 4) CURRENT SNAPSHOT TOPLA
    # ---------------------------------------------------
    def collect_snapshot(self) -> Dict[str, Dict[str, Any]]:
        """
        Sistemdeki tüm process'lerin anlık durumunu toplar.
        PID key'leri string olarak tutulur (JSON için uygun).
        """
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

                # CPU yüzde (önceki ölçümlerle delta alır; ilk seferde 0 olabilir)
                cpu_percent = p.cpu_percent(interval=None)

                # memory info
                try:
                    mem = p.memory_info()
                    rss = mem.rss
                    vms = mem.vms
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    rss = None
                    vms = None

                exe = info.get("exe")
                cmdline = info.get("cmdline")
                username = info.get("username")
                status = info.get("status")
                create_time = info.get("create_time")
                ppid = info.get("ppid")
                name = info.get("name")

                # Deleted binary tespiti
                exe_deleted = False
                if exe:
                    # Bazı sistemlerde "(deleted)" suffix'i kullanılıyor
                    if "(deleted)" in exe or not os.path.exists(exe):
                        exe_deleted = True

                # optional
                cwd = None
                open_files = None
                if self.include_details:
                    try:
                        cwd = p.cwd()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        cwd = None
                    try:
                        of = p.open_files()
                        open_files = [f.path for f in of]
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        open_files = None

                # optional
                exe_hash = None
                if self.include_hash and exe and not exe_deleted:
                    exe_hash = self._hash_executable(exe)

                snapshot[pid_str] = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "exe": exe,
                    "cmdline": cmdline,
                    "username": username,
                    "status": status,
                    "create_time": create_time,
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
            except Exception:
                # hata olursa da devam
                continue

        return snapshot

    # ---------------------------------------------------
    # 5) DIFF AL — EVENT ÜRET
    # ---------------------------------------------------
    def diff_processes(
        self,
        previous: Dict[str, Dict[str, Any]],
        current: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        previous vs current snapshot karşılaştırıp event listesi üretir.
        """
        prev_pids = set(previous.keys())
        curr_pids = set(current.keys())

        new_pids = curr_pids - prev_pids          # NEW_PROCESS
        terminated_pids = prev_pids - curr_pids   # TERMINATED_PROCESS
        common_pids = prev_pids & curr_pids       # CHANGES

        events: List[Dict[str, Any]] = []
        now_iso = datetime.utcnow().isoformat() + "Z"

        # NEW_PROCESS
        for pid in new_pids:
            p_curr = current[pid]
            events.append(
                {
                    "type": "NEW_PROCESS",
                    "timestamp": now_iso,
                    **p_curr,
                }
            )

        # TERMINATED_PROCESS
        for pid in terminated_pids:
            p_prev = previous[pid]
            create_time = p_prev.get("create_time")
            run_time = None
            if create_time is not None:
                try:
                    run_time = time.time() - float(create_time)
                except Exception:
                    run_time = None

            events.append(
                {
                    "type": "TERMINATED_PROCESS",
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

        # CHANGES
        for pid in common_pids:
            p_prev = previous[pid]
            p_curr = current[pid]

            # EXE değişimi
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

            # CMDLINE değişimi
            if p_prev.get("cmdline") != p_curr.get("cmdline"):
                events.append(
                    {
                        "type": "CMDLINE_CHANGED",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "old": p_prev.get("cmdline"),
                        "new": p_curr.get("cmdline"),
                    }
                )

            # USERNAME değişimi (privilege escalation)
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

            # STATUS değişimi (özellikle ZOMBIE)
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

            # ZOMBIE process 
            if p_curr.get("status") == psutil.STATUS_ZOMBIE:
                events.append(
                    {
                        "type": "ZOMBIE_PROCESS",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "name": p_curr.get("name"),
                        "exe": p_curr.get("exe"),
                        "username": p_curr.get("username"),
                    }
                )

            # Deleted executable
            if not p_prev.get("exe_deleted") and p_curr.get("exe_deleted"):
                events.append(
                    {
                        "type": "EXEC_DELETED",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "exe": p_curr.get("exe"),
                        "username": p_curr.get("username"),
                    }
                )

            # Binary hash değişimi (opsiyonel, include_hash=True ise)
            if (
                self.include_hash
                and p_prev.get("exe_hash") is not None
                and p_curr.get("exe_hash") is not None
                and p_prev.get("exe_hash") != p_curr.get("exe_hash")
            ):
                events.append(
                    {
                        "type": "EXEC_HASH_CHANGED",
                        "timestamp": now_iso,
                        "pid": p_curr.get("pid"),
                        "exe": p_curr.get("exe"),
                        "old_hash": p_prev.get("exe_hash"),
                        "new_hash": p_curr.get("exe_hash"),
                    }
                )

        return events

    # ---------------------------------------------------
    # 6) TEK ADIM — SCHEDULER İÇİN KULLANILACAK FONKSİYON
    # ---------------------------------------------------
    def step(self) -> List[Dict[str, Any]]:
        """
        Tek bir ölçüm + diff + cache güncelleme.
        Dışarıya sadece event listesi döner.
        """
        current = self.collect_snapshot()
        events = self.diff_processes(self.previous, current)

        # previous snapshot güncelle
        self.previous = current
        self.save_previous(current)

        return events

    # ---------------------------------------------------
    # 7) ANA ÇALIŞMA LOOP'U (GENERATOR)
    # ---------------------------------------------------
    def run(self, interval: int = 10):
        """
        Sürekli çalışmak için generator.
        Scheduler veya main loop buradan event okuyabilir.
        """
        while True:
            events = self.step()
            for event in events:
                yield event
            time.sleep(interval)

    # ---------------------------------------------------
    # 8) TEST FUNKSIYONU — TEK SEFERLİK
    # ---------------------------------------------------
    def test_once(self) -> None:
        """
        ProcessCollector'ı tek seferlik test etmek için.
        """
        print("\n===== PROCESS COLLECTOR TEST =====\n")
        events = self.step()

        if not events:
            print("Herhangi bir event yok (normal olabilir).")
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
        include_hash=False,     # optional, simdilik false
        include_details=False,  # optional, simdilik false
    )
    collector.test_once()
