from backend.core.rules.base import StatelessRule
from backend.core.utils.sensitive_files import SENSITIVE_FILES, SENSITIVE_ACCESS_WHITELIST

class SensitiveFileAccessRule(StatelessRule):
    rule_id = "FILE_001"
    description = "Access to sensitive system file detected"
    severity = "HIGH"
    event_prefix = "PROCESS_" # Dosya erişimi genellikle bir okuma süreciyle başlar

    def match(self, event: dict) -> bool:
        if event.get("type") != "PROCESS_NEW":
            return False

        cmdline = (event.get("cmdline") or "").lower()
        pname = (event.get("process_name") or "").lower()

        # 1. Beyaz listedeki güvenilir süreçleri atla (False Positive önleme)
        if pname in SENSITIVE_ACCESS_WHITELIST:
            return False

        # 2. Komut satırında hassas dosyalardan biri geçiyor mu kontrol et
        for s_file in SENSITIVE_FILES:
            # Wildcard (*) desteği için basit bir kontrol (basitlik adına 'in' kullanıyoruz)
            clean_path = s_file.replace("*", "")
            if clean_path in cmdline:
                return True

        return False

    def build_alert(self, event: dict) -> dict:
        pname = event.get("process_name")
        cmd = event.get("cmdline")
        user = event.get("username")
        pid = event.get("pid")

        return self.build_alert_base(
            alert_type="ALERT_SENSITIVE_FILE_ACCESS",
            message=f"Sensitive file access by user '{user}' using '{pname}' (PID: {pid})",
            # Generic Resolver: Sadece bu süreci kanıt olarak bağla
            extra=self.build_evidence_spec(
                source="process_events",
                filters={
                    "id__in": [event.get("id")] if event.get("id") else []
                }
            )
        )