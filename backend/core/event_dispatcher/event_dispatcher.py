# backend/core/event_dispatcher/event_dispatcher.py

from backend.logger import logger
from backend.core.storage import services

from backend.core.rules.rule_engine import RuleEngine
from backend.core.rules.context import CorrelationContext

from backend.core.rules.suspicious_process import SuspiciousProcessRule
from backend.core.rules.ssh_bruteforce import SSHBruteforceRule
from backend.core.rules.sensitive_file_access import SensitiveFileAccessRule
from backend.core.rules.log_deletion import LogDeletionRule
from backend.core.rules.resource_usage import HighResourceUsageRule
from backend.core.rules.user_creation import UserCreationRule
from backend.core.rules.persistence_cron import PersistenceCronRule
from backend.core.rules.suspicious_shell import SuspiciousShellRule


class EventDispatcher:

    def __init__(self):
        self.context = CorrelationContext()

        self.rule_engine = RuleEngine(
            rules=[
                SuspiciousProcessRule(),
                SSHBruteforceRule(),
                SensitiveFileAccessRule(),
                LogDeletionRule(),
                HighResourceUsageRule(),
                UserCreationRule(),
                PersistenceCronRule(),
                SuspiciousShellRule(),
            ],
            context=self.context
        )

    def dispatch(self, event: dict):
        if not event:
            return None

        etype = event.get("type", "")
        logger.debug(f"[DISPATCH] Received event type={etype}")

        # -------------------------
        # PERSIST EVENT FIRST
        # -------------------------
        if etype == "LOG_EVENT":
            self._handle_log(event)

        elif etype.startswith("PROCESS_"):
            self._handle_process(event)

        elif etype.startswith("NET_") or etype.startswith("CONNECTION_"):
            self._handle_network(event)

        elif etype == "METRIC_SNAPSHOT":
            self._handle_metric(event)

        # -------------------------
        # RULE ENGINE
        # -------------------------
        try:
            results = self.rule_engine.process(event)

            for result in results:
                alert = result.get("alert")
                evidence = result.get("evidence", [])

                if not alert:
                    continue

                payload = {
                    "type": "ALERT",
                    "alert": alert,
                    "evidence": evidence,
                }

                services.db_writer.enqueue(payload)

        except Exception:
            logger.exception("[DISPATCH][RULE_ENGINE] Failed")

        return event

    # -------------------------
    # HANDLERS
    # -------------------------

    def _handle_process(self, event):
        try:
            services.db_writer.enqueue(event)
            return event
        except Exception:
            logger.exception("[DISPATCH][PROCESS] Failed")
            return None

    def _handle_network(self, event):
        try:
            services.db_writer.enqueue(event)
            return event
        except Exception:
            logger.exception("[DISPATCH][NETWORK] Failed")
            return None

    def _handle_metric(self, event):
        try:
            services.db_writer.enqueue(event)
            return event
        except Exception:
            logger.exception("[DISPATCH][METRIC] Failed")
            return None

    def _handle_log(self, event):
        try:
            services.db_writer.enqueue(event)
            return event
        except Exception:
            logger.exception("[DISPATCH][LOG] Failed")
            return None
