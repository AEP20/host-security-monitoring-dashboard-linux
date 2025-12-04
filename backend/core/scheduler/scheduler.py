# ============================================================
#                          SCHEDULER
# ============================================================

# Amaç:
# ------
# HIDS içindeki collector, parser, rule engine ve dispatcher
# akışını doğru zamanlarda tetikleyen merkezi zamanlayıcıdır.

# Görevleri:
# ----------
# • MetricsCollector → her 60 sn snapshot üretir → dispatcher → DB
# • ProcessCollector → her 10 sn diff → event → rule engine → dispatcher
# • NetworkCollector → her 10 sn diff → event → rule engine → dispatcher
# • LogCollector → sürekli takip → satır → parser → event → rule → dispatcher
# • ConfigChecker → 30–60 dk aralıklarla → hardening bulgularını üretir

# Mimari:
# -------
# Scheduler hiçbir yerde DB işlemi yapmaz.
# Collector → RuleEngine → Dispatcher zincirini çalıştırır.

# Teknik Detay:
# -------------
# Scheduler her collector için ayrı bir thread açar (non-blocking).
# Her thread kendi loop’u içinde:
#     1) collector.step() veya collector.snapshot() çağırır
#     2) çıkan event'leri rule_engine.process(event) ile işler
#     3) rule engine’den dönen alertleri event dizisine ekler
#     4) tümünü dispatcher.dispatch(event) ile DB'ye kaydeder
#     5) interval kadar sleep atar

# Bu yapı gerçek EDR sistemlerinde (Wazuh, OSSEC, Elastic Agent)
# kullanılan yaklaşımın birebir aynısıdır.

# ============================================================


import threading
import time

from backend.core.collector.metrics_collector import MetricsCollector
from backend.core.collector.processes_collector import ProcessCollector
from backend.core.collector.network_collector import NetworkCollector
# from backend.core.collector.logs_collector import LogCollector  # varsa

from backend.core.rules.rule_engine import RuleEngine
from backend.core.event_dispatcher.event_dispatcher import EventDispatcher


class Scheduler:
    """
    ============================================================
                              SCHEDULER
    ============================================================

    Collector → RuleEngine → EventDispatcher zincirini
    belirli aralıklarla tetikleyen merkezi zamanlayıcıdır.

    Her collector kendi thread'i içinde çalışır.
    Non-blocking tasarım — biri yavaşlasa diğerlerini etkilemez.
    """

    def __init__(self):
        # Collector'lar
        self.metrics_collector = MetricsCollector()
        self.process_collector = ProcessCollector()
        self.network_collector = NetworkCollector()
        # self.log_collector = LogCollector()  # tail -f tarzı çalışır

        # Engine & Dispatcher
        self.rule_engine = RuleEngine()
        self.dispatcher = EventDispatcher()

        self.threads = []

    # ---------------------------------------------------------
    # İç fonksiyon: belirli interval ile bir collector çalıştır
    # ---------------------------------------------------------
    def _run_collector_loop(self, collector, interval, collector_name):
        """
        Generic collector worker.

        - collector.step() → event listesi döner
        - her event → rule_engine.process(event)
        - çıkan alert varsa → ayrı event olarak eklenir
        - dispatcher.dispatch(event) → DB
        """

        print(f"[Scheduler] {collector_name} started (interval={interval}s)")

        while True:
            try:
                # Process & Network collector step() kullanır
                events = collector.step()

                for ev in events:
                    # Rule engine incele
                    alert = self.rule_engine.process(ev)

                    # Event'i DB'ye gönder
                    self.dispatcher.dispatch(ev)

                    # Alert varsa onu da dispatcher'a gönder
                    if alert:
                        self.dispatcher.dispatch(alert)

            except Exception as e:
                print(f"[Scheduler] Error in {collector_name}:", str(e))

            time.sleep(interval)

    # ---------------------------------------------------------
    # LogCollector ayrı çalışır (tailing)
    # ---------------------------------------------------------
    # def _run_log_collector(self):
    #     """
    #     LogCollector sürekli çalışır. (tail -f mantığı)
    #     Log satırı → parser → event → rule → dispatcher
    #     """
    #     print("[Scheduler] LogCollector started")

    #     for event in self.log_collector.run():     # generator
    #         try:
    #             alert = self.rule_engine.process(event)
    #             self.dispatcher.dispatch(event)
    #             if alert:
    #                 self.dispatcher.dispatch(alert)
    #         except Exception as e:
    #             print("[Scheduler] LogCollector error:", e)

    # ---------------------------------------------------------
    # Config Checker (30-60 dk arası)
    # ---------------------------------------------------------
    def _run_config_checker(self):
        from backend.core.config_checker.firewall_check import FirewallCheck

        checker = FirewallCheck()  # örnek check
        interval = 3600  # 1 saat

        print("[Scheduler] ConfigChecker started (interval=1h)")

        while True:
            try:
                findings = checker.run()

                for finding in findings:
                    self.dispatcher.dispatch(finding)

            except Exception as e:
                print("[Scheduler] ConfigChecker error:", e)

            time.sleep(interval)

    # ---------------------------------------------------------
    # Threadleri başlat
    # ---------------------------------------------------------
    def start(self):
        """
        Scheduler tüm thread’leri başlatır.
        """
        print("[Scheduler] Starting all collectors...")

        self.threads = [
            threading.Thread(
                target=self._run_collector_loop,
                args=(self.metrics_collector, 60, "MetricsCollector"),
                daemon=True,
            ),
            threading.Thread(
                target=self._run_collector_loop,
                args=(self.process_collector, 10, "ProcessCollector"),
                daemon=True,
            ),
            threading.Thread(
                target=self._run_collector_loop,
                args=(self.network_collector, 10, "NetworkCollector"),
                daemon=True,
            ),
            threading.Thread(
                target=self._run_log_collector,
                daemon=True,
            ),
            threading.Thread(
                target=self._run_config_checker,
                daemon=True,
            ),
        ]

        # Thread'leri başlat
        for t in self.threads:
            t.start()

        print("[Scheduler] All collectors are running.")


# Standalone çalıştırmak için
if __name__ == "__main__":
    Scheduler().start()
    while True:
        time.sleep(1)

