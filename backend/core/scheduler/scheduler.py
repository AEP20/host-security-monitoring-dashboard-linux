import threading
import time

from backend.core.collector.metrics_collector import MetricsCollector
from backend.core.collector.processes_collector import ProcessCollector
from backend.core.collector.network_collector import NetworkCollector
from backend.core.collector.logs_collector import LogsCollector

from backend.core.rules.rule_engine import RuleEngine
from backend.core.event_dispatcher.event_dispatcher import EventDispatcher


# Global instance — API’ler buradan erişecek
scheduler_instance = None


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
        self.rule_engine = RuleEngine()
        self.dispatcher = EventDispatcher()

        # Thread list
        self.threads = []

    # ---------------------------------------------------------
    # METRICS loop
    # ---------------------------------------------------------
    def _run_metrics_loop(self):
        interval = self.METRICS_INTERVAL
        print(f"[Scheduler] MetricsCollector started ({interval}s interval)")

        while True:
            try:
                metric_event = self.metrics_collector.snapshot()

                alert = self.rule_engine.process(metric_event)
                self.dispatcher.dispatch(metric_event)

                if alert:
                    self.dispatcher.dispatch(alert)

            except Exception as e:
                print("[Scheduler] MetricsCollector error:", e)

            time.sleep(interval)

    # ---------------------------------------------------------
    # Generic collector runner
    # ---------------------------------------------------------
    def _run_collector_loop(self, collector, interval, name):
        print(f"[Scheduler] {name} started ({interval}s interval)")

        while True:
            try:
                events = collector.step()

                for ev in events:
                    alert = self.rule_engine.process(ev)
                    self.dispatcher.dispatch(ev)

                    if alert:
                        self.dispatcher.dispatch(alert)

            except Exception as e:
                print(f"[Scheduler] {name} error:", e)

            time.sleep(interval)

    # ---------------------------------------------------------
    # LOG tailing loop
    # ---------------------------------------------------------
    def _run_log_collector(self):
        print("[Scheduler] LogCollector started (tail mode)")

        for event in self.log_collector.run():
            try:
                alert = self.rule_engine.process(event)
                self.dispatcher.dispatch(event)

                if alert:
                    self.dispatcher.dispatch(alert)

            except Exception as e:
                print("[Scheduler] LogCollector error:", e)

    # ---------------------------------------------------------
    # CONFIG CHECKER loop
    # ---------------------------------------------------------
    def _run_config_checker(self):
        interval = self.CONFIG_CHECKER_INTERVAL
        print(f"[Scheduler] ConfigChecker started (interval={interval}s)")

        from backend.core.config_checker.firewall_check import FirewallCheck
        checker = FirewallCheck()

        while True:
            try:
                findings = checker.run()

                for f in findings:
                    self.dispatcher.dispatch(f)

            except Exception as e:
                print("[Scheduler] ConfigChecker error:", e)

            time.sleep(interval)

    # ---------------------------------------------------------
    # Start all threads
    # ---------------------------------------------------------
    def start(self):
        print("[Scheduler] Starting all collectors...")

        # THREAD DEFINITIONS
        self.threads = [
            threading.Thread(target=self._run_metrics_loop, daemon=False),
            threading.Thread(target=self._run_collector_loop,
                             args=(self.process_collector, self.PROCESS_INTERVAL, "ProcessCollector"),
                             daemon=False),
            threading.Thread(target=self._run_collector_loop,
                             args=(self.network_collector, self.NETWORK_INTERVAL, "NetworkCollector"),
                             daemon=False),
            threading.Thread(target=self._run_log_collector, daemon=False),
            threading.Thread(target=self._run_config_checker, daemon=False),
        ]

        # START THREADS
        for t in self.threads:
            t.start()

        print("[Scheduler] All collectors running.")

        global scheduler_instance
        scheduler_instance = self


# Standalone run
if __name__ == "__main__":
    Scheduler().start()
    while True:
        time.sleep(1)
