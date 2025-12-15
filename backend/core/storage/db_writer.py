# backend/core/storage/db_writer.py

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
    Sistemdeki TEK DB write noktası
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
            self._save_alert_with_evidence(payload)

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
    def _save_alert_with_evidence(self, payload: Dict[str, Any]):
        alert_data = payload.get("alert")
        evidence_list = payload.get("evidence", [])

        if not alert_data:
            return

        def resolve_evidence(session, alert_obj):
            extra = alert_data.get("extra") or {}
            cfg = extra.get("evidence_resolve") or {}

            if cfg.get("source") != "log_events":
                return []

            ip = extra.get("ip")
            user = extra.get("user")
            window = extra.get("window_seconds")

            if not ip or not window:
                return []

            end_ts = alert_obj.timestamp
            start_ts = end_ts - timedelta(seconds=int(window))

            q = session.query(LogEventModel.id).filter(
                LogEventModel.timestamp >= start_ts,
                LogEventModel.timestamp <= end_ts,
                LogEventModel.ip_address == ip,
            )

            if user:
                q = q.filter(LogEventModel.user == user)

            rows = q.order_by(LogEventModel.timestamp.asc()).all()
            if not rows:
                return []

            out = []
            for i, (eid,) in enumerate(rows):
                out.append({
                    "event_type": "LOG_EVENT",
                    "event_id": eid,
                    "role": "SUPPORT",
                    "sequence": i + 1,
                })

            out[-1]["role"] = "TRIGGER"
            return out

        def op(session):
            alert_obj = AlertModel.create(alert_data, session=session)
            session.flush()

            evs = evidence_list or resolve_evidence(session, alert_obj)

            for ev in evs:
                if not ev.get("event_id"):
                    continue

                session.add(
                    AlertEvidenceModel.create(
                        alert_id=alert_obj.id,
                        event_type=ev["event_type"],
                        event_id=ev["event_id"],
                        role=ev["role"],
                        sequence=ev["sequence"],
                    )
                )

        self._with_retry(op, event_type="ALERT")
