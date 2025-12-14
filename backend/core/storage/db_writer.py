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


class DBWriter:
    """
    ============================================================
                        DB WRITER SERVICE
    ============================================================
    - Sistemdeki TEK DB write noktası
    - Thread-safe Queue
    - Tek worker thread
    - Retry & commit logic
    - Spam yapmayan debug logging
    """

    def __init__(self):
        self.queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self._stop_event = threading.Event()

        self.worker = threading.Thread(
            target=self._run,
            name="DBWriter",
            daemon=True
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

    def enqueue(self, event: Dict[str, Any]):
        """
        EventDispatcher / LogDispatcher burayı çağırır
        """
        if not event:
            return

        self.queue.put(event)

    # -------------------------------------------------
    # WORKER LOOP
    # -------------------------------------------------
    def _run(self):
        logger.info("[DBWriter] Worker thread running")

        while not self._stop_event.is_set():
            try:
                event = self.queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                self._handle_event(event)
            except Exception:
                logger.exception("[DBWriter] Unhandled exception while processing event")
            finally:
                self.queue.task_done()

    # -------------------------------------------------
    # EVENT ROUTER
    # -------------------------------------------------
    def _handle_event(self, event: Dict[str, Any]):
        etype = event.get("type", "")

        if not etype:
            logger.debug("[DBWriter] Dropped event with missing type")
            return

        if etype.startswith("PROCESS_"):
            self._save_process_event(event)
        elif etype == "LOG_EVENT":
            logger.debug(f"[DBWriter] Saving LOG_EVENT to database: (kritik) {event}")
            self._save_log_event(event)
        elif etype.startswith("NET_") or etype.startswith("CONNECTION_"):
            self._save_network_event(event)
        elif etype == "METRIC_SNAPSHOT":
            self._save_metric_snapshot(event)
        elif etype.startswith("ALERT_"):
            self._save_alert_event(event)
        else:
            logger.debug(f"[DBWriter] Ignored unknown event type={etype}")

    # -------------------------------------------------
    # CORE DB OPERATION WITH RETRY
    # -------------------------------------------------
    def _with_retry(self, fn, event_type: str, retries: int = 3):
        for attempt in range(1, retries + 1):
            session = SessionLocal()
            try:
                fn(session)
                session.commit()

                logger.debug(
                    f"[DBWriter] Write OK type={event_type} (attempt {attempt})"
                )
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
                    logger.exception(
                        f"[DBWriter] OperationalError type={event_type}"
                    )
                    raise

            except Exception:
                session.rollback()
                logger.exception(
                    f"[DBWriter] Unexpected error type={event_type}"
                )
                raise

            finally:
                session.close()

        logger.error(
            f"[DBWriter] Max retry exceeded type={event_type}"
        )

    # -------------------------------------------------
    # SAVE METHODS
    # -------------------------------------------------
    def _save_process_event(self, event: Dict[str, Any]):
        self._with_retry(
            lambda session: ProcessEventModel.create(event, session=session),
            event_type=event.get("type", "PROCESS")
        )

    def _save_network_event(self, event: Dict[str, Any]):
        self._with_retry(
            lambda session: NetworkEventModel.create(event, session=session),
            event_type=event.get("type", "NETWORK")
        )

    def _save_metric_snapshot(self, event: Dict[str, Any]):
        self._with_retry(
            lambda session: MetricModel.create(event, session=session),
            event_type="METRIC_SNAPSHOT"
        )

    def _save_log_event(self, event: Dict[str, Any]):
        logger.debug(f"[DBWriter] Saving LOG_EVENT to database: {event}")
        self._with_retry(
            lambda session: LogEventModel.create(event, session=session),
            event_type="LOG_EVENT"
        )

    def _save_alert_event(self, event: Dict[str, Any]):
        self._with_retry(
            lambda session: AlertModel.create(event, session=session),
            event_type=event.get("type", "ALERT")
        )
