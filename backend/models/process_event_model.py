from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from backend.models.base import Base, current_time


class ProcessEventModel(Base):
    """
    Process Event Model
    -------------------
    Collector tarafından üretilen TÜM process event’leri (STATE + EVENT)
    bu tabloda saklanır.

    Neden tek tablo?
    - NEW_PROCESS, CMDLINE_CHANGED, PRIV_ESCALATION vb. onlarca event türünü
      ayrı tablolarla yönetmek karmaşık olur.
    - Wazuh, OSSEC, CrowdStrike gibi EDR ürünlerinde de tek tablo yapılır.
    """

    __tablename__ = "process_events"

    id = Column(Integer, primary_key=True)

    # Event timestamp
    timestamp = Column(DateTime, default=current_time, index=True)

    # Event tipi: NEW_PROCESS, TERMINATED_PROCESS, CMDLINE_CHANGED vb.
    event_type = Column(String(100), nullable=False, index=True)

    # Process PID & PPID
    pid = Column(Integer, nullable=True, index=True)
    ppid = Column(Integer, nullable=True)

    # Process adı (kısa adı)
    process_name = Column(String(200), nullable=True)

    # Çalıştırılan binary
    exe = Column(Text, nullable=True)

    # Command line args (string olarak)
    cmdline = Column(Text, nullable=True)

    # Process'in user'ı (root mu, www-data mı vs.)
    username = Column(String(100), nullable=True)

    # Process create_time (epoch)
    create_time = Column(String(50), nullable=True)

    # CPU & RAM usage (STATE bilgilerinden)
    cpu_percent = Column(String(50), nullable=True)
    memory_rss = Column(String(50), nullable=True)
    memory_vms = Column(String(50), nullable=True)

    # “Önceki” alanlar → değişim tespit edilen event'lerde doldurulur
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)

    # Deleted executable flag
    exe_deleted = Column(String(10), nullable=True)  # "true" / "false"

    # Extra JSON data (open_files, cwd, hashes, status vs.)
    snapshot_data = Column(JSON, nullable=True)

    # Rule Engine’in bağladığı alert (opsiyonel)
    alert_id = Column(Integer, nullable=True)

    # Raw event full JSON
    raw_event = Column(JSON, nullable=True)

    # ---------------------------------------------------
    #            STATIC CREATE METHOD
    # ---------------------------------------------------
    @staticmethod
    def create(event: dict, session):
        obj = ProcessEventModel(
            event_type=event.get("type"),
            pid=event.get("pid"),
            ppid=event.get("ppid"),
            process_name=event.get("name") or event.get("process_name"),
            exe=event.get("exe"),
            cmdline=" ".join(event.get("cmdline", []))
                if isinstance(event.get("cmdline"), list)
                else event.get("cmdline"),
            username=event.get("username"),
            create_time=str(event.get("create_time")),
            cpu_percent=str(event.get("cpu_percent")),
            memory_rss=str(event.get("memory_rss")),
            memory_vms=str(event.get("memory_vms")),
            old_value=str(event.get("old")),
            new_value=str(event.get("new")),
            exe_deleted=str(event.get("exe_deleted")).lower()
                if event.get("exe_deleted") is not None else None,
            snapshot_data=event,
            raw_event=event
        )

        session.add(obj)
        return obj


    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "pid": self.pid,
            "ppid": self.ppid,
            "process_name": self.process_name,
            "exe": self.exe,
            "cmdline": self.cmdline,
            "username": self.username,
            "create_time": self.create_time,
            "cpu_percent": self.cpu_percent,
            "memory_rss": self.memory_rss,
            "memory_vms": self.memory_vms,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "exe_deleted": self.exe_deleted,
            "snapshot_data": self.snapshot_data,
            "alert_id": self.alert_id,
            "raw_event": self.raw_event,
        }
