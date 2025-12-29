from backend.core.rules.base import StatelessRule
from backend.logger import logger
from typing import Dict, Any

class UserCreationRule(StatelessRule):
    rule_id = "UUC_001"
    description = "New user creation or modification detected via system logs"
    severity = "CRITICAL"
    event_prefix = "LOG_" # Sadece log olaylarını takip edeceğiz

    def supports(self, event_type: str) -> bool:
        # Sadece log olaylarını desteklemesi yeterli
        return event_type == "LOG_EVENT"

    def match(self, event: Dict[str, Any]) -> bool:
        if event.get("type") != "LOG_EVENT":
            return False

        # Log mesajını normalize et
        msg = event.get("message", "").lower()
        
        # Kritik log desenleri:
        # "new user" -> adduser/useradd komutu sonrası oluşur
        # "new group" -> Genellikle kullanıcıyla beraber oluşur
        # "password changed" -> usermod veya passwd değişikliği
        keywords = ["new user", "new group", "useradd", "adduser"]
        
        if any(key in msg for key in keywords):
            logger.info(f"[{self.rule_id}] Pattern matched in logs: {msg}")
            return True

        return False

    def build_alert(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # Log verisinden kullanıcıyı çekmeye çalış, yoksa 'System' olarak işaretle
        user = event.get("user") or "System/Root"
        raw_msg = event.get("message", "No message content")

        return self.build_alert_base(
            alert_type="ALERT_USER_CREATION",
            message=f"Critical system change: New user/group detection pattern found in logs.",
            extra=self.build_evidence_spec(
                source="log_events",
                filters={"id": event.get("id")}
            )
        )