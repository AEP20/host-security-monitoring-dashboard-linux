from backend.core.rules.base import StatelessRule
from backend.logger import logger
from typing import Dict, Any

class PersistenceCronRule(StatelessRule):
    rule_id = "PER_001"
    description = "Persistence attempt via Crontab (Process or Log detection)"
    severity = "HIGH"
    event_prefix = ""  

    def supports(self, event_type: str) -> bool:
        """Kuralın hangi olay tiplerini desteklediğini belirtir"""
        return event_type in ["PROCESS_NEW", "LOG_EVENT"]

    def match(self, event: Dict[str, Any]) -> bool:
        if event.get("type") == "PROCESS_NEW":
            pname = (event.get("process_name") or "").lower()
            raw_cmd = event.get("cmdline", "")
            cmdline = " ".join(raw_cmd).lower() if isinstance(raw_cmd, list) else str(raw_cmd).lower()

            targets = ["/etc/cron", "/var/spool/cron", "crontab"]
            if any(t in cmdline for t in targets) or "cron" in pname:
                logger.info(f"[{self.rule_id}] Process-based cron activity detected: {cmdline}")
                return True

        if event.get("type") == "LOG_EVENT":
            msg = event.get("message", "").lower()
            if "crontab" in msg and any(action in msg for action in ["edit", "replace", "delete", "list"]):
                logger.info(f"[{self.rule_id}] Log-based cron activity detected: {msg}")
                return True

        return False

    def build_alert(self, event: Dict[str, Any]) -> Dict[str, Any]:
        etype = event.get("type")
        user = event.get("username") or event.get("user") or "unknown"
        
        if etype == "PROCESS_NEW":
            message = f"Possible persistence attempt: User '{user}' executed a cron-related command."
            source = "process_events"
        else:
            message = f"System log alert: Manual crontab modification detected for user '{user}'."
            source = "log_events"

        return self.build_alert_base(
            alert_type="ALERT_PERSISTENCE_CRON",
            message=message,
            extra=self.build_evidence_spec(
                source=source,
                filters={"id": event.get("id")}
            )
        )