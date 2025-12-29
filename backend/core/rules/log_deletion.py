from backend.core.rules.base import StatelessRule

class LogDeletionRule(StatelessRule):
    rule_id = "LOG_001"
    description = "Potential log clearing or history deletion attempt"
    severity = "HIGH"
    event_prefix = "" 

    SUSPICIOUS_TARGETS = [
        "/var/log/auth", "/var/log/syslog", "/var/log/messages",
        "/var/log/hids", ".bash_history", ".zsh_history", "/var/log/hids/app.log"
    ]

    def supports(self, event_type: str) -> bool:
        # Hem süreçleri hem de auth loglarını destekle
        return event_type in ["PROCESS_NEW", "LOG_EVENT"]

    def match(self, event: dict) -> bool:
        # 1. Veriyi normalize et (Sudo logu mu yoksa süreç mi?)
        if event.get("type") == "LOG_EVENT":
            # Sudo logu içindeki 'message' alanına bakıyoruz
            content = event.get("message", "").lower()
            # Sadece 'truncate' veya 'rm' geçen sudo loglarını dikkate al
            if not any(cmd in content for cmd in ["truncate", "rm", "shred"]):
                return False
        else:
            # Normal süreç takibi
            raw_cmdline = event.get("cmdline", "")
            content = " ".join(raw_cmdline).lower() if isinstance(raw_cmdline, list) else str(raw_cmdline).lower()
            
            pname = (event.get("process_name") or "").lower()
            if pname not in ["rm", "truncate", "shred"]:
                return False

        # 2. Kritik dosyalar hedeflenmiş mi?
        for target in self.SUSPICIOUS_TARGETS:
            if target.lower() in content:
                return True

        return False

    def build_alert(self, event: dict) -> dict:
        user = event.get("username") or event.get("user", "unknown")
        # Log mu süreç mi olduğuna göre mesajı ayarla
        msg_source = "process" if event.get("type") == "PROCESS_NEW" else "sudo log"
        
        return self.build_alert_base(
            alert_type="ALERT_LOG_DELETION",
            message=f"Log clearing attempt detected via {msg_source} by user '{user}'",
            extra=self.build_evidence_spec(
                source="process_events" if event.get("type") == "PROCESS_NEW" else "log_events",
                filters={"id": event.get("id")}
            )
        )