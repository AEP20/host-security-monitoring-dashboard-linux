import threading
import time

from backend.core.collector.metrics_collector import MetricsCollector
from backend.core.collector.processes_collector import ProcessCollector
from backend.core.collector.network_collector import NetworkCollector
from backend.core.collector.logs_collector import LogsCollector

# from backend.core.rules.rule_engine import RuleEngine
# from backend.core.event_dispatcher.event_dispatcher import EventDispatcher

from backend.logger import logger


# Global instance — API’ler buradan erişecek
scheduler_instance = None
scheduler_lock = threading.Lock()


class Scheduler:
    """
    ============================================================
                        CENTRAL SCHEDULER
    ============================================================
    Collector → RuleEngine → EventDispatcher zincirini
    belirli aralıklarla tetikleyen ana zamanlayıcı.
    """

    METRICS_INTERVAL = 60
    PROCESS_INTERVAL = 10
    NETWORK_INTERVAL = 10
    CONFIG_CHECKER_INTERVAL = 3600

    def __init__(self):
        # Collector instances
        self.metrics_collector = MetricsCollector()
        self.process_collector = ProcessCollector()
        self.network_collector = NetworkCollector()
        self.log_collector = LogsCollector()

        # Core engines
        # self.rule_engine = RuleEngine()
        self.dispatcher = EventDispatcher()

        # Thread list
        self.threads = []

        logger.info("[Scheduler] Initialized")

    # ---------------------------------------------------------
    # METRICS loop
    # ---------------------------------------------------------
    def _run_metrics_loop(self):
        interval = self.METRICS_INTERVAL
        logger.info(f"[Scheduler] MetricsCollector started ({interval}s interval)")

        while True:
            try:
                metric_event = self.metrics_collector.snapshot()

                # alert = self.rule_engine.process(metric_event)
                self.dispatcher.dispatch(metric_event)

                # if alert:
                #     self.dispatcher.dispatch(alert)

            except Exception as e:
                logger.exception("[Scheduler] MetricsCollector error")

            time.sleep(interval)

    # ---------------------------------------------------------
    # Generic collector runner
    # ---------------------------------------------------------
    def _run_collector_loop(self, collector, interval, name):
        logger.info(f"[Scheduler] {name} started ({interval}s interval)")

        while True:
            try:
                events = collector.step()

                for ev in events:
                    # alert = self.rule_engine.process(ev)
                    self.dispatcher.dispatch(ev)

                    # if alert:
                    #     self.dispatcher.dispatch(alert)

            except Exception:
                logger.exception(f"[Scheduler] {name} error")

            time.sleep(interval)

    # ---------------------------------------------------------
    # LOG tailing loop
    # ---------------------------------------------------------
    def _run_log_collector(self):
        logger.info("[Scheduler] LogCollector started (tail mode)")

        # LogCollector'ın 'run()' fonksiyonu yoktu; bu yüzden step çağırıyoruz.
        while True:
            try:
                events = self.log_collector.collect()

                for ev in events:
                    self.dispatcher.dispatch(ev)

            except Exception:
                logger.exception("[Scheduler] LogCollector error")

            time.sleep(3)

    # ---------------------------------------------------------
    # CONFIG CHECKER loop
    # ---------------------------------------------------------
    # def _run_config_checker(self):
    #     interval = self.CONFIG_CHECKER_INTERVAL
    #     logger.info(f"[Scheduler] ConfigChecker started (interval={interval}s)")

    #     checker = FirewallCheck()

    #     while True:
    #         try:
    #             findings = checker.run()

    #             for f in findings:
    #                 self.dispatcher.dispatch(f)

    #         except Exception:
    #             logger.exception("[Scheduler] ConfigChecker error")

    #         time.sleep(interval)

    # ---------------------------------------------------------
    # Start all threads
    # ---------------------------------------------------------
    def start(self):
        logger.info("[Scheduler] Starting all collectors...")

        # THREAD DEFINITIONS
        self.threads = [
            threading.Thread(target=self._run_metrics_loop, name="MetricsThread", daemon=False),
            
            # threading.Thread(target=self._run_collector_loop,
            #                  args=(self.process_collector, self.PROCESS_INTERVAL, "ProcessCollector"),
            #                  name="ProcessThread",
            #                  daemon=False),
            
            # threading.Thread(target=self._run_collector_loop,
            #                  args=(self.network_collector, self.NETWORK_INTERVAL, "NetworkCollector"),
            #                  name="NetworkThread",
            #                  daemon=False),
            
            threading.Thread(target=self._run_log_collector, name="LogThread", daemon=False),
            
            # threading.Thread(target=self._run_config_checker, name="ConfigCheckerThread", daemon=False),
        ]

        # START THREADS
        for t in self.threads:
            t.start()
            logger.info(f"[Scheduler] Started thread: {t.name}")

        logger.info("[Scheduler] All collectors running.")

        # Thread-safe global assignment
        global scheduler_instance
        with scheduler_lock:
            scheduler_instance = self


# Standalone run
if __name__ == "__main__":
    s = Scheduler()
    s.start()
    while True:
        time.sleep(1)
