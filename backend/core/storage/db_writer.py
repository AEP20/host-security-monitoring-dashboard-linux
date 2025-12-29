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
    - Event'leri DB'ye yazmak
    - Alert + Evidence ilişkilendirmesini yapmak
    - Transaction / retry yönetmek

    Yapmaz:
    - Rule çalıştırmak
    - Correlation mantığı kurmak
    """

    # -------------------------------------------------
    # INIT
    # -------------------------------------------------
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
            self._write(ProcessEventModel, payload, etype)

        elif etype == "LOG_EVENT":
            self._write(LogEventModel, payload, etype)

        elif etype.startswith("NET_") or etype.startswith("CONNECTION_"):
            self._write(NetworkEventModel, payload, etype)

        elif etype == "METRIC_SNAPSHOT":
            self._write(MetricModel, payload, etype)

        elif etype == "ALERT":
            self._save_alert(payload)

        else:
            logger.debug(f"[DBWriter] Ignored payload type={etype}")

    # -------------------------------------------------
    # GENERIC WRITE WITH RETRY
    # -------------------------------------------------
    def _write(self, model, payload: Dict[str, Any], event_type: str):
        def op(session):
            model.create(payload, session=session)

        self._with_retry(op, event_type=event_type)

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
        explicit_evidence = payload.get("evidence", [])

        if not alert_data:
            logger.warning("[DBWriter] ALERT payload without alert_data")
            return

        logger.info(
            f"[DBWriter][ALERT] rule={alert_data.get('rule_name')} "
            f"type={alert_data.get('type')}"
        )

        def op(session):
            alert_obj = AlertModel.create(alert_data, session=session)
            session.flush()

            logger.debug(
                f"[DBWriter][ALERT_CREATED] id={alert_obj.id}"
            )

            # explicit evidence
            for ev in explicit_evidence:
                if not self._valid_evidence(ev):
                    logger.debug(
                        f"[DBWriter][EVIDENCE_SKIP] invalid={ev}"
                    )
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

                logger.debug(
                    f"[DBWriter][EVIDENCE_EXPLICIT] "
                    f"event_id={ev['event_id']} role={ev['role']}"
                )

            self._resolve_evidence(
                session=session,
                alert_id=alert_obj.id,
                alert_data=alert_data,
            )

        self._with_retry(op, event_type="ALERT")


    # -------------------------------------------------
    # EVIDENCE VALIDATION
    # -------------------------------------------------
    @staticmethod
    def _valid_evidence(ev: Dict[str, Any]) -> bool:
        return (
            ev.get("event_id")
            and ev.get("event_type")
            and ev.get("role")
        )

    # -------------------------------------------------
    # GENERIC EVIDENCE RESOLVER
    # -------------------------------------------------
    def _resolve_evidence(self, *, session, alert_id: int, alert_data: Dict[str, Any]):
        spec = (alert_data.get("extra") or {}).get("evidence_resolve")
        if not spec:
            logger.debug(
                f"[DBWriter][RESOLVE] alert_id={alert_id} no spec"
            )
            return

        logger.debug(
            f"[DBWriter][RESOLVE] alert_id={alert_id} spec={spec}"
        )

        source = spec.get("source")
        filters = spec.get("filters", {})
        time_range = spec.get("time_range", {})
        limit = spec.get("limit", 20)
        order = spec.get("order", "desc")

        model, event_type = self._resolve_source(source)
        if not model:
            return

        q = session.query(model.id, model.timestamp)

        for field, value in filters.items():
            if value is None:
                continue
            if hasattr(model, field):
                logger.debug(
                    f"[DBWriter][FILTER] {field}={value}"
                )
                q = q.filter(getattr(model, field) == value)

        if time_range.get("from"):
            q = q.filter(model.timestamp >= time_range["from"])
        if time_range.get("to"):
            q = q.filter(model.timestamp <= time_range["to"])

        q = q.order_by(
            model.timestamp.asc() if order == "asc" else model.timestamp.desc()
        )

        rows = q.limit(limit).all()

        logger.info(
            f"[DBWriter][RESOLVE] alert_id={alert_id} "
            f"matched_events={len(rows)}"
        )

        for seq, (event_id, _) in enumerate(rows, start=1):
            session.add(
                AlertEvidenceModel.create(
                    alert_id=alert_id,
                    event_type=event_type,
                    event_id=event_id,
                    role="SUPPORT",
                    sequence=seq,
                )
            )

    # -------------------------------------------------
    # SOURCE → MODEL MAP
    # -------------------------------------------------
    @staticmethod
    def _resolve_source(source: str):
        if source == "log_events":
            return LogEventModel, "LOG_EVENT"
        if source == "process_events":
            return ProcessEventModel, "PROCESS_EVENT"
        if source == "network_events":
            return NetworkEventModel, "NETWORK_EVENT"
        if source == "metric_events":
            return MetricModel, "METRIC_SNAPSHOT"

        logger.warning(f"[DBWriter] Unsupported evidence source: {source}")
        return None, None
