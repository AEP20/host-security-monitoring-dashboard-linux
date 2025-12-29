from backend.core.rules.base import StatelessRule
from backend.logger import logger
from typing import Dict, Any

class PersistenceCronRule(StatelessRule):
    rule_id = "PER_001"
    description = "Persistence attempt via Crontab (Process or Log detection)"
    severity = "HIGH"
    event_prefix = ""  # Hibrit yapı: Hem LOG hem PROCESS olaylarını kabul eder

    def supports(self, event_type: str) -> bool:
        """Kuralın hangi olay tiplerini desteklediğini belirtir"""
        return event_type in ["PROCESS_NEW", "LOG_EVENT"]

    def match(self, event: Dict[str, Any]) -> bool:
        # --- 1. SÜREÇ (PROCESS) ANALİZİ ---
        # Saldırgan komutu çalıştırdığı anda yakalar (Niyet Tespiti)
        if event.get("type") == "PROCESS_NEW":
            pname = (event.get("process_name") or "").lower()
            raw_cmd = event.get("cmdline", "")
            cmdline = " ".join(raw_cmd).lower() if isinstance(raw_cmd, list) else str(raw_cmd).lower()

            # Kritik dizinler veya crontab komutu geçiyor mu?
            targets = ["/etc/cron", "/var/spool/cron", "crontab"]
            if any(t in cmdline for t in targets) or "cron" in pname:
                logger.info(f"[{self.rule_id}] Process-based cron activity detected: {cmdline}")
                return True

        # --- 2. LOG ANALİZİ ---
        # Sistem dosyası gerçekten değiştiğinde yakalar (Kanıt Tespiti)
        if event.get("type") == "LOG_EVENT":
            msg = event.get("message", "").lower()
            # Loglarda 'crontab' ve 'edit/replace/delete' gibi anahtar kelimeler
            if "crontab" in msg and any(action in msg for action in ["edit", "replace", "delete", "list"]):
                logger.info(f"[{self.rule_id}] Log-based cron activity detected: {msg}")
                return True

        return False

    def build_alert(self, event: Dict[str, Any]) -> Dict[str, Any]:
        etype = event.get("type")
        user = event.get("username") or event.get("user") or "unknown"
        
        # Olay tipine göre mesajı özelleştir
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