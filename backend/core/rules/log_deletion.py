# 📁 log_deletion.py

# Amaç: Log dosyası silinmiş mi veya truncate edilmiş mi tespit etmek.
# Dosya boyutu sıfıra düşmüşse
# inode değişmişse

from backend.core.rules.base import StatelessRule
import re

class LogDeletionRule(StatelessRule):
    rule_id = "LOG_001"
    description = "Potential log clearing or history deletion attempt"
    severity = "HIGH"
    event_prefix = "PROCESS_"  # Log silme genellikle bir process (rm, truncate) üzerinden yapılır

    # Tespit etmek istediğimiz kritik log ve geçmiş dosyaları
    SUSPICIOUS_TARGETS = [
        "/var/log/auth", "/var/log/syslog", "/var/log/messages",
        "/var/log/hids", ".bash_history", ".zsh_history", "/var/log/hids/app.log"
    ]

    def match(self, event: dict) -> bool:
        # Sadece yeni süreçleri kontrol et
        if event.get("type") != "PROCESS_NEW":
            return False

        cmdline = event.get("cmdline", "").lower()
        process_name = (event.get("process_name") or "").lower()

        # 1. rm veya truncate gibi komutlar kullanılıyor mu?
        if process_name in ["rm", "truncate", "shred"]:
            # 2. Kritik bir log dosyası hedef alınıyor mu?
            for target in self.SUSPICIOUS_TARGETS:
                if target in cmdline:
                    return True
        
        # 3. bash/zsh history temizleme komutları (örn: ln -sf /dev/null .bash_history)
        if "/dev/null" in cmdline and ("history" in cmdline):
            return True

        return False

    def build_alert(self, event: dict) -> dict:
        pname = event.get("process_name")
        cmd = event.get("cmdline")
        user = event.get("username")
        pid = event.get("pid")

        return self.build_alert_base(
            alert_type="ALERT_LOG_DELETION",
            message=f"Log clearing attempt by user '{user}' using '{pname}' (PID: {pid})",
            # Generic Resolver için talimat:
            # id__in içine kuralı tetikleyen o anki event'in ID'sini koyuyoruz.
            extra=self.build_evidence_spec(
                source="process_events",
                filters={
                    "id__in": [event.get("id")] if event.get("id") else []
                }
            )
        )