# TO:DO network event model which will data provided from the network collector
# network collector (events will be created in here) -> event_dispatcher (in the event_dispatcher events will ve wrote to the db)
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from backend.models.base import Base, current_time


class NetworkEventModel(Base):
    """
    Network Event Model
    -------------------
    Collector tarafından üretilen TÜM network event’leri
    (STATE + EVENT + ALERT tetikleyen eventler) tek tabloda tutulur.

    Neden tek tablo?
    - NET_NEW_CONNECTION, NET_CLOSED_LISTEN_PORT, CONNECTION_SUSPICIOUS_REMOTE
      gibi çok sayıda event türü üretildiği için.
    - ProcessEventModel mimarisi ile birebir uyumlu.
    """

    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True)

    # Event timestamp
    timestamp = Column(DateTime, default=current_time, index=True)

    # Event tipi (NET_NEW_CONNECTION, CONNECTION_PORT_SCAN_OUTBOUND, NET_SNAPSHOT...)
    event_type = Column(String(100), nullable=False, index=True)

    # Process bilgileri (opsiyonel olabilir)
    pid = Column(Integer, nullable=True, index=True)
    process_name = Column(String(200), nullable=True)

    # Protokol: tcp / udp
    protocol = Column(String(20), nullable=True)

    # Local Addr
    laddr_ip = Column(String(100), nullable=True)
    laddr_port = Column(Integer, nullable=True)

    # Remote Addr
    raddr_ip = Column(String(100), nullable=True)
    raddr_port = Column(Integer, nullable=True)

    # Connection status (ESTABLISHED, LISTEN, SYN_SENT, CLOSED...)
    status = Column(String(50), nullable=True)

    # Suspicious / unusual detection alanları
    reason = Column(String(200), nullable=True)
    description = Column(Text, nullable=True)

    # Port scan esetleri için
    ports_tried = Column(JSON, nullable=True)

    # Snapshot / diff eventleri için ham JSON veri
    snapshot_data = Column(JSON, nullable=True)

    # Rule Engine tarafından bağlanan alert_id (opsiyonel)
    alert_id = Column(Integer, nullable=True)

    # Raw event
    raw_event = Column(JSON, nullable=True)

    # ---------------------------------------------------
    #            STATIC CREATE METHOD
    # ---------------------------------------------------
    @staticmethod
    def create(event: dict, session):
        obj = NetworkEventModel(
            event_type=event.get("type"),
            pid=event.get("pid"),
            process_name=event.get("process_name"),
            protocol=event.get("protocol"),
            laddr_ip=event.get("laddr_ip"),
            laddr_port=event.get("laddr_port"),
            raddr_ip=event.get("raddr_ip"),
            raddr_port=event.get("raddr_port"),
            status=event.get("status"),
            reason=event.get("reason"),
            description=event.get("description"),
            ports_tried=event.get("ports_tried"),
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
            "process_name": self.process_name,
            "protocol": self.protocol,
            "laddr_ip": self.laddr_ip,
            "laddr_port": self.laddr_port,
            "raddr_ip": self.raddr_ip,
            "raddr_port": self.raddr_port,
            "status": self.status,
            "reason": self.reason,
            "description": self.description,
            "ports_tried": self.ports_tried,
            "snapshot_data": self.snapshot_data,
            "alert_id": self.alert_id,
            "raw_event": self.raw_event,
        }
