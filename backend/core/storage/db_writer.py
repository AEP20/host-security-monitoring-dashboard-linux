# DBWriter
# ├── Queue (thread-safe)
# ├── Worker Thread (daemon)
# ├── SessionLocal (tek session per işlem)
# ├── Event → Model routing
# ├── Retry & commit logic

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


class DBWriter:
    """
    ============================================================
                        DB WRITER SERVICE
    ============================================================
    - Sistemdeki TEK DB write noktası
    - Thread-safe Queue üzerinden event alır
    - Tek worker thread DB'ye yazar
    - SQLite / PostgreSQL uyumlu
    """

    def __init__(self):
        self.queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self._stop_event = threading.Event()

        self.worker = threading.Thread(
            target=self._run,
            name="DBWriter",
            daemon=True
        )

    # -------------------------
    # PUBLIC API
    # -------------------------
    def start(self):
        logger.info("[DBWriter] Starting DB writer thread")
        self.worker.start()

    def stop(self):
        logger.info("[DBWriter] Stopping DB writer thread")
        self._stop_event.set()
        self.worker.join(timeout=5)

    def enqueue(self, event: Dict[str, Any]):
        """
        EventDispatcher burayı çağırır
        """
        if not event:
            return

        self.queue.put(event)

    # -------------------------
    # WORKER LOOP
    # -------------------------
    def _run(self):
        logger.info("[DBWriter] Worker thread running")

        while not self._stop_event.is_set():
            try:
                event = self.queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                self._handle_event(event)
            except Exception as e:
                logger.exception("[DBWriter] Failed to handle event")
            finally:
                self.queue.task_done()

    # -------------------------
    # EVENT ROUTER
    # -------------------------
    def _handle_event(self, event: Dict[str, Any]):
        etype = event.get("type", "")

        if etype.startswith("PROCESS_"):
            self._save_process_event(event)
        elif etype == "LOG_EVENT":
            self._save_log_event(event)
        elif etype.startswith("NET_") or etype.startswith("CONNECTION_"):
            self._save_network_event(event)
        elif etype == "METRIC_SNAPSHOT":
            self._save_metric_snapshot(event)
        elif etype.startswith("ALERT_"):
            self._save_alert_event(event)
        else:
            logger.debug(f"[DBWriter] Ignored unknown event type={etype}")

    # -------------------------
    # SAVE METHODS
    # -------------------------
    def _with_retry(self, fn, retries=3):
        for attempt in range(retries):
            session = SessionLocal()
            try:
                fn(session)
                session.commit()
                return
            except OperationalError as e:
                session.rollback()
                if "database is locked" in str(e):
                    time.sleep(0.1 * (attempt + 1))
                else:
                    raise
            finally:
                session.close()

        logger.error("[DBWriter] Max retry exceeded")

    def _save_process_event(self, event):
        def op(session):
            ProcessEventModel.create(event, session=session)

        self._with_retry(op)

    def _save_network_event(self, event):
        def op(session):
            NetworkEventModel.create(event, session=session)

        self._with_retry(op)

    def _save_metric_snapshot(self, event):
        def op(session):
            MetricModel.create(event, session=session)

        self._with_retry(op)

    def _save_log_event(self, event):
        def op(session):
            LogEventModel.create(event, session=session)

        self._with_retry(op)

    def _save_alert_event(self, event):
        def op(session):
            AlertModel.create(event, session=session)

        self._with_retry(op)
