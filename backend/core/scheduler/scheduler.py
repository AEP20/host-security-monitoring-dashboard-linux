import threading
import time

from backend.core.collector.metrics_collector import MetricsCollector
from backend.core.collector.processes_collector import ProcessCollector
from backend.core.collector.network_collector import NetworkCollector
from backend.core.collector.logs_collector import LogsCollector

from backend.core.event_dispatcher.event_dispatcher import EventDispatcher
from backend.core.parser.LogDispatcher import LogDispatcher

from backend.logger import logger


# Global instance — API'ler buradan çağıracak
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
    PROCESS_INTERVAL = 10
    NETWORK_INTERVAL = 10
    LOG_INTERVAL = 3

    def __init__(self):
        # Collectors
        self.metrics_collector = MetricsCollector()
        self.process_collector = ProcessCollector()
        self.network_collector = NetworkCollector()
        self.log_collector = LogsCollector()

        # Dispatchers
        self.event_dispatcher = EventDispatcher()
        self.log_dispatcher = LogDispatcher()

        # Threads
        self.threads = []

        logger.info("[Scheduler] Initialized")

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
    # GENERIC COLLECTOR LOOP (Process / Network)
    # ---------------------------------------------------------
    def _run_collector_loop(self, collector, interval, name):
        logger.info(f"[Scheduler] {name} started ({interval}s interval)")

        while True:
            self.heartbeat["LogThread"] = time.time()
            
            
            try:
                events = collector.step()

                for ev in events:
                    self.event_dispatcher.dispatch(ev)

            except Exception:
                logger.exception(f"[Scheduler] {name} error")

            time.sleep(interval)

    # ---------------------------------------------------------
    # LOG COLLECTOR LOOP  (Raw → Parsed → EventDispatcher)
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

                    # STEP 1 → RAW → PARSER
                    parsed_event = self.log_dispatcher.dispatch(source, line)

                    if not parsed_event:
                        continue  # parser.match() fail → skip

                    # STEP 2 → Parsed structured event → EventDispatcher
                    self.event_dispatcher.dispatch(parsed_event)

            except Exception:
                logger.exception("[Scheduler] LogCollector error")

            time.sleep(self.LOG_INTERVAL)

    # ---------------------------------------------------------
    # START ALL THREADS
    # ---------------------------------------------------------
    def start(self):
        logger.info("[Scheduler] Starting all collectors...")

        self.threads = [
            threading.Thread(target=self._run_metrics_loop, name="MetricsThread", daemon=False),

            # Enable when needed:
            # threading.Thread(target=self._run_collector_loop,
            #                  args=(self.process_collector, self.PROCESS_INTERVAL, "ProcessCollector"),
            #                  name="ProcessThread",
            #                  daemon=False),

            # threading.Thread(target=self._run_collector_loop,
            #                  args=(self.network_collector, self.NETWORK_INTERVAL, "NetworkCollector"),
            #                  name="NetworkThread",
            #                  daemon=False),

            threading.Thread(target=self._run_log_collector, name="LogThread", daemon=False),
        ]

        for t in self.threads:
            t.start()
            logger.info(f"[Scheduler] Started thread: {t.name}")

        logger.info("[Scheduler] All collectors running.")

        # Global instance
        global scheduler_instance
        with scheduler_lock:
            scheduler_instance = self


# Standalone run
if __name__ == "__main__":
    s = Scheduler()
    s.start()
    while True:
        time.sleep(1)
