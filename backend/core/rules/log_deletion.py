
# 📁 log_deletion.py

# Amaç: Log dosyası silinmiş mi veya truncate edilmiş mi tespit etmek.
# Dosya boyutu sıfıra düşmüşse
# inode değişmişse

from backend.core.rules.base import StatelessRule

class LogDeletionRule(StatelessRule):
    rule_id = "LOG_001"
    description = "Potential log clearing or history deletion attempt"
    severity = "HIGH"
    event_prefix = "PROCESS_"

    SUSPICIOUS_TARGETS = [
        "/var/log/auth", "/var/log/syslog", "/var/log/messages",
        "/var/log/hids", ".bash_history", ".zsh_history", "/var/log/hids/app.log"
    ]

    def match(self, event: dict) -> bool:
        if event.get("type") != "PROCESS_NEW":
            return False

        # --- GÜVENLİ VERİ DÖNÜŞTÜRME ---
        raw_cmdline = event.get("cmdline", "")
        if isinstance(raw_cmdline, list):
            cmdline_str = " ".join(raw_cmdline).lower()
        else:
            cmdline_str = str(raw_cmdline).lower()
        # ------------------------------

        process_name = (event.get("process_name") or "").lower()

        # 1. rm, truncate veya shred komutları kontrolü
        if process_name in ["rm", "truncate", "shred"]:
            for target in self.SUSPICIOUS_TARGETS:
                if target.lower() in cmdline_str: # String içinde parça araması yapar
                    return True
        
        # 2. /dev/null yönlendirmesi ile geçmiş temizleme
        if "/dev/null" in cmdline_str and "history" in cmdline_str:
            return True

        return False

    def build_alert(self, event: dict) -> dict:
        pname = event.get("process_name")
        user = event.get("username")
        pid = event.get("pid")

        return self.build_alert_base(
            alert_type="ALERT_LOG_DELETION",
            message=f"Log clearing attempt by user '{user}' using '{pname}' (PID: {pid})",
            extra=self.build_evidence_spec(
                source="process_events",
                filters={
                    "id__in": [event.get("id")] if event.get("id") else []
                }
            )
        )