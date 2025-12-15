import threading
import queue
import time
from typing import Dict, Any, List
from datetime import timedelta

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
    ============================================================
                        DB WRITER SERVICE
    ============================================================
    - Sistemdeki TEK DB write noktası
    - Thread-safe Queue
    - Tek worker thread
    - Retry & commit logic
    - Alert + Evidence atomik yazım
    - Evidence resolve (DB-based) desteği
    ============================================================
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
    # PUBLIC API
    # -------------------------------------------------
    def start(self):
        logger.info("[DBWriter] Starting DB writer thread")
        self.worker.start()

    def stop(self):
        logger.info("[DBWriter] Stopping DB writer thread")
        self._stop_event.set()
        self.worker.join(timeout=5)

    def enqueue(self, payload: Dict[str, Any]):
        if payload:
            self.queue.put(payload)

    # -------------------------------------------------
    # WORKER LOOP
    # -------------------------------------------------
    def _run(self):
        logger.info("[DBWriter] Worker thread running")

        while not self._stop_event.is_set():
            try:
                payload = self.queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                self._handle_payload(payload)
            except Exception:
                logger.exception("[DBWriter] Unhandled exception while processing payload")
            finally:
                self.queue.task_done()

    # -------------------------------------------------
    # PAYLOAD ROUTER
    # -------------------------------------------------
    def _handle_payload(self, payload: Dict[str, Any]):
        etype = payload.get("type")
        logger.debug(f"[DBWriter] Handling payload type={etype}")

        if not etype:
            return

        # ---------- RAW EVENTS ----------
        if etype.startswith("PROCESS_"):
            self._save_process_event(payload)

        elif etype == "LOG_EVENT":
            self._save_log_event(payload)

        elif etype.startswith("NET_") or etype.startswith("CONNECTION_"):
            self._save_network_event(payload)

        elif etype == "METRIC_SNAPSHOT":
            self._save_metric_snapshot(payload)

        # ---------- ALERT ----------
        elif etype == "ALERT":
            self._save_alert_with_evidence(payload)

        else:
            logger.debug(f"[DBWriter] Ignored unknown payload type={etype}")

    # -------------------------------------------------
    # CORE DB OPERATION WITH RETRY
    # -------------------------------------------------
    def _with_retry(self, fn, *, event_type: str, retries: int = 3):
        for attempt in range(1, retries + 1):
            session = SessionLocal()
            try:
                fn(session)
                session.commit()
                logger.debug(f"[DBWriter] Write OK type={event_type} (attempt {attempt})")
                return

            except OperationalError as e:
                session.rollback()
                if "database is locked" in str(e):
                    logger.warning(
                        f"[DBWriter] DB locked type={event_type} "
                        f"(retry {attempt}/{retries})"
                    )
                    time.sleep(0.1 * attempt)
                else:
                    raise

            except Exception:
                session.rollback()
                logger.exception(f"[DBWriter] Unexpected error type={event_type}")
                raise

            finally:
                session.close()

        logger.error(f"[DBWriter] Max retry exceeded type={event_type}")

    # -------------------------------------------------
    # SAVE METHODS (RAW EVENTS)
    # -------------------------------------------------
    def _save_process_event(self, event: Dict[str, Any]):
        self._with_retry(
            lambda session: ProcessEventModel.create(event, session=session),
            event_type=event.get("type", "PROCESS"),
        )

    def _save_network_event(self, event: Dict[str, Any]):
        self._with_retry(
            lambda session: NetworkEventModel.create(event, session=session),
            event_type=event.get("type", "NETWORK"),
        )

    def _save_metric_snapshot(self, event: Dict[str, Any]):
        self._with_retry(
            lambda session: MetricModel.create(event, session=session),
            event_type="METRIC_SNAPSHOT",
        )

    def _save_log_event(self, event: Dict[str, Any]):
        self._with_retry(
            lambda session: LogEventModel.create(event, session=session),
            event_type="LOG_EVENT",
        )

    # -------------------------------------------------
    # ALERT + EVIDENCE (DOĞRU & GÜVENLİ)
    # -------------------------------------------------
    def _save_alert_with_evidence(self, payload: Dict[str, Any]):
        alert_data = payload.get("alert")
        evidence_list: List[Dict[str, Any]] = payload.get("evidence", [])

        if not alert_data:
            logger.warning("[DBWriter] ALERT payload missing alert data")
            return

        def _resolve_evidence_from_db(session, alert_obj) -> List[Dict[str, Any]]:
            """
            Evidence listesi boşsa:
            - alert.extra içinden resolve parametrelerini al
            - log_events tablosundan event_id'leri BUL
            """
            extra = alert_data.get("extra") or {}
            resolve_cfg = extra.get("evidence_resolve") or {}

            if resolve_cfg.get("source") != "log_events":
                return []

            ip = extra.get("ip")
            user = extra.get("user")
            window_seconds = extra.get("window_seconds")

            if not ip or not user or not window_seconds:
                return []

            end_ts = alert_obj.timestamp
            start_ts = end_ts - timedelta(seconds=int(window_seconds))

            q = session.query(LogEventModel.id).filter(
                LogEventModel.timestamp >= start_ts,
                LogEventModel.timestamp <= end_ts,
                LogEventModel.ip_address == ip,
                LogEventModel.user == user,
            )

            if resolve_cfg.get("event_type"):
                q = q.filter(LogEventModel.event_type == resolve_cfg["event_type"])

            if resolve_cfg.get("category"):
                q = q.filter(LogEventModel.category == resolve_cfg["category"])

            rows = q.order_by(LogEventModel.timestamp.asc()).all()
            if not rows:
                return []

            resolved = []
            for idx, (event_id,) in enumerate(rows):
                resolved.append({
                    "event_type": "LOG_EVENT",
                    "event_id": event_id,
                    "role": "SUPPORT",
                    "sequence": idx + 1,
                })

            resolved[-1]["role"] = "TRIGGER"
            return resolved

        def _op(session):
            alert_obj = AlertModel.create(alert_data, session=session)
            session.flush()  

            if not evidence_list:
                evs = _resolve_evidence_from_db(session, alert_obj)
            else:
                evs = evidence_list

            written = 0
            for ev in evs:
                event_id = ev.get("event_id")

                if event_id is None:
                    logger.warning(
                        f"[DBWriter] Skipping evidence with missing event_id "
                        f"(rule={alert_data.get('rule_name')})"
                    )
                    continue

                session.add(
                    AlertEvidenceModel.create(
                        alert_id=alert_obj.id,
                        event_type=ev.get("event_type"),
                        event_id=event_id,
                        role=ev.get("role"),
                        sequence=ev.get("sequence"),
                    )
                )
                written += 1

            logger.debug(
                f"[DBWriter] Alert saved id={alert_obj.id} evidence_written={written}"
            )

        self._with_retry(_op, event_type="ALERT")
