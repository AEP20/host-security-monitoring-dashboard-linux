import threading
import time

from backend.core.collector.metrics_collector import MetricsCollector
from backend.core.collector.processes_collector import ProcessCollector
from backend.core.collector.network_collector import NetworkCollector
from backend.core.collector.logs_collector import LogsCollector

from backend.core.event_dispatcher.event_dispatcher import EventDispatcher
from backend.core.parser.LogDispatcher import LogDispatcher

from backend.logger import logger

# Global instance for API
scheduler_instance = None
scheduler_lock = threading.Lock()


class Scheduler:
    """
    ============================================================
                        CENTRAL SCHEDULER (HIDS)
    ============================================================

    • MetricsCollector → EventDispatcher
    • ProcessCollector → EventDispatcher
    • NetworkCollector → EventDispatcher

    • LogsCollector → LogDispatcher → EventDispatcher
    ============================================================
    """

    METRICS_INTERVAL = 60
    PROCESS_INTERVAL = 15
    NETWORK_INTERVAL = 15
    LOG_INTERVAL = 3

    def __init__(self):
        # COLLECTORS
        self.metrics_collector = MetricsCollector()
        self.process_collector = ProcessCollector()
        self.network_collector = NetworkCollector()
        self.log_collector = LogsCollector()

        # DISPATCHER
        self.event_dispatcher = EventDispatcher()
        self.log_dispatcher = LogDispatcher()

        self.heartbeat = {}
        self.threads = []

        logger.info("[Scheduler] Initialized")

    # ---------------------------------------------------------
    # HEALTH LOOP
    # ---------------------------------------------------------
    def _run_health_loop(self):
        while True:
            self.heartbeat["HealthThread"] = time.time()
            time.sleep(2)

    # ---------------------------------------------------------
    # METRICS LOOP
    # ---------------------------------------------------------
    def _run_metrics_loop(self):
        interval = self.METRICS_INTERVAL
        logger.info(f"[Scheduler] MetricsCollector started ({interval}s interval)")

        while True:
            self.heartbeat["MetricsThread"] = time.time()

            try:
                event = self.metrics_collector.snapshot()
                self.event_dispatcher.dispatch(event)

            except Exception:
                logger.exception("[Scheduler] MetricsCollector error")

            time.sleep(interval)

    # ---------------------------------------------------------
    # GENERIC LOOP (Process / Network)
    # ---------------------------------------------------------
    # ---------------------------------------------------------
    # GENERIC LOOP (Process / Network)
    # ---------------------------------------------------------
    def _run_collector_loop(self, collector, interval, name):
        # NOTE: 'name' here comes from the args passed in start()
        # We must ensure start() passes "ProcessThread" / "NetworkThread"
        # OR we just map it here. To be safe/simple, we will use the actual thread name.
        
        thread_name = threading.current_thread().name
        logger.info(f"[Scheduler] {thread_name} started ({interval}s interval)")

        while True:
            self.heartbeat[thread_name] = time.time()

            try:
                events = collector.step()

                for ev in events:
                    self.event_dispatcher.dispatch(ev)

            except Exception:
                logger.exception(f"[Scheduler] {thread_name} error")

            time.sleep(interval)

    # ---------------------------------------------------------
    # LOG LOOP
    # ---------------------------------------------------------
    def _run_log_collector(self):
        logger.info("[Scheduler] LogCollector started")

        while True:
            self.heartbeat["LogThread"] = time.time()

            try:
                raw_entries = self.log_collector.collect()

                for entry in raw_entries:
                    source = entry["source"]
                    line = entry["line"]

                    parsed_event = self.log_dispatcher.dispatch(source, line)

                    if not parsed_event:
                        continue 

                    parsed_event.setdefault("type", "LOG_EVENT")

                    logger.debug(
                        f"[Scheduler] Dispatching parsed log event: {parsed_event}"
                    )
                    self.event_dispatcher.dispatch(parsed_event)

            except Exception:
                logger.exception("[Scheduler] LogCollector error")

            time.sleep(self.LOG_INTERVAL)


    # ---------------------------------------------------------
    # START THREADS
    # ---------------------------------------------------------
    def start(self):
        logger.info("[Scheduler] Starting all collectors...")

        self.threads = [
            threading.Thread(target=self._run_metrics_loop, name="MetricsThread", daemon=False),

            threading.Thread(
                target=self._run_collector_loop,
                args=(self.process_collector, self.PROCESS_INTERVAL, "ProcessCollector"),
                name="ProcessThread",
                daemon=False
            ),

            threading.Thread(
                target=self._run_collector_loop,
                args=(self.network_collector, self.NETWORK_INTERVAL, "NetworkCollector"),
                name="NetworkThread",
                daemon=False
            ),

            threading.Thread(target=self._run_log_collector, name="LogThread", daemon=False),
            threading.Thread(target=self._run_health_loop, name="HealthThread", daemon=False),
        ]

        for t in self.threads:
            t.start()
            logger.info(f"[Scheduler] Started thread: {t.name}")

        logger.info("[Scheduler] All collectors running.")

        global scheduler_instance
        with scheduler_lock:
            scheduler_instance = self


# FOR TESTING 
if __name__ == "__main__":
    s = Scheduler()
    s.start()

    while True:
        time.sleep(1)
