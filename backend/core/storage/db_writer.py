# backend/core/storage/db_writer.py

import threading
import queue
import time
from typing import Dict, Any

from sqlalchemy.exc import OperationalError

from backend.database import SessionLocal
from backend.logger import logger

from backend.models.process_event_model import ProcessEventModel
from backend.models.network_event_model import NetworkEventModel
from backend.models.metric_model import MetricModel
from backend.models.log_model import LogEventModel
from backend.models.alert_model import AlertModel
from backend.models.alert_evidence_model import AlertEvidenceModel


class DBWriter:
    """
    Sistemdeki TEK DB write noktası.

    Sorumluluk:
    - Gelen payload'ı doğru tabloya yazmak
    - Transaction / retry yönetmek
    - Alert oluşturulduktan sonra evidence'ı DB'ye bağlamak

    Yapmaz:
    - Kural çalıştırmak
    - Correlation yapmak
    """

    def __init__(self):
        self.queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self._stop_event = threading.Event()

        self.worker = threading.Thread(
            target=self._run,
            name="DBWriter",
            daemon=True,
        )

    # -------------------------------------------------
    # LIFECYCLE
    # -------------------------------------------------
    def start(self):
        logger.info("[DBWriter] Starting DB writer thread")
        self.worker.start()

    def stop(self):
        self._stop_event.set()
        self.worker.join(timeout=5)

    def enqueue(self, payload: Dict[str, Any]):
        if payload:
            self.queue.put(payload)

    # -------------------------------------------------
    # WORKER LOOP
    # -------------------------------------------------
    def _run(self):
        logger.info("[DBWriter] Worker running")

        while not self._stop_event.is_set():
            try:
                payload = self.queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                self._handle_payload(payload)
            except Exception:
                logger.exception("[DBWriter] Payload processing failed")
            finally:
                self.queue.task_done()

    # -------------------------------------------------
    # PAYLOAD ROUTER
    # -------------------------------------------------
    def _handle_payload(self, payload: Dict[str, Any]):
        etype = payload.get("type")

        if not etype:
            return

        if etype.startswith("PROCESS_"):
            self._with_retry(
                lambda s: ProcessEventModel.create(payload, session=s),
                event_type=etype,
            )

        elif etype == "LOG_EVENT":
            self._with_retry(
                lambda s: LogEventModel.create(payload, session=s),
                event_type="LOG_EVENT",
            )

        elif etype.startswith("NET_") or etype.startswith("CONNECTION_"):
            self._with_retry(
                lambda s: NetworkEventModel.create(payload, session=s),
                event_type=etype,
            )

        elif etype == "METRIC_SNAPSHOT":
            self._with_retry(
                lambda s: MetricModel.create(payload, session=s),
                event_type="METRIC_SNAPSHOT",
            )

        elif etype == "ALERT":
            self._save_alert(payload)

        else:
            logger.debug(f"[DBWriter] Ignored payload type={etype}")

    # -------------------------------------------------
    # RETRY WRAPPER
    # -------------------------------------------------
    def _with_retry(self, fn, *, event_type: str, retries: int = 3):
        for attempt in range(1, retries + 1):
            session = SessionLocal()
            try:
                fn(session)
                session.commit()
                return
            except OperationalError as e:
                session.rollback()
                if "locked" in str(e):
                    time.sleep(0.1 * attempt)
                else:
                    raise
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    # -------------------------------------------------
    # ALERT + EVIDENCE
    # -------------------------------------------------
    def _save_alert(self, payload: Dict[str, Any]):
        alert_data = payload.get("alert")
        evidence_list = payload.get("evidence", [])

        if not alert_data:
            return

        def op(session):
            alert_obj = AlertModel.create(alert_data, session=session)
            session.flush() 

            for ev in evidence_list:
                if not ev.get("event_id") or not ev.get("event_type") or not ev.get("role"):
                    continue

                session.add(
                    AlertEvidenceModel.create(
                        alert_id=alert_obj.id,
                        event_type=ev["event_type"],
                        event_id=ev["event_id"],
                        role=ev["role"],
                        sequence=ev.get("sequence"),
                    )
                )

            self._resolve_evidence(
                session=session,
                alert_id=alert_obj.id,
                alert_data=alert_data,
            )

        self._with_retry(op, event_type="ALERT")

    # -------------------------------------------------
    # GENERIC EVIDENCE RESOLVER
    # -------------------------------------------------
    def _resolve_evidence(self, *, session, alert_id: int, alert_data: Dict[str, Any]):
        """
        alert.extra["evidence_resolve"] üzerinden
        ilgili event'leri DB'den bulup alert_evidence'a bağlar
        """

        extra = alert_data.get("extra") or {}
        spec = extra.get("evidence_resolve")

        if not spec:
            return

        source = spec.get("source")
        category = spec.get("category")
        event_types = spec.get("event_types", [])

        # Şimdilik sadece LOG_EVENT destekleniyor
        if source != "log_events":
            logger.warning(f"[DBWriter] Unsupported evidence source: {source}")
            return

        q = session.query(LogEventModel.id)

        if category:
            q = q.filter(LogEventModel.category == category)

        if event_types:
            q = q.filter(LogEventModel.event_type.in_(event_types))

        q = q.order_by(LogEventModel.timestamp.desc()).limit(100)

        rows = q.all()

        for idx, (event_id,) in enumerate(rows, start=1):
            session.add(
                AlertEvidenceModel.create(
                    alert_id=alert_id,
                    event_type="LOG_EVENT",
                    event_id=event_id,
                    role="SUPPORT",
                    sequence=idx,
                )
            )
