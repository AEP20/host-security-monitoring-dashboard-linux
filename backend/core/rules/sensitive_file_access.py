from backend.core.rules.base import StatelessRule
from backend.core.utils.sensitive_files import SENSITIVE_FILES, SENSITIVE_ACCESS_WHITELIST
from backend.logger import logger

class SensitiveFileAccessRule(StatelessRule):
    rule_id = "FILE_001"
    description = "Access to sensitive system file detected"
    severity = "HIGH"
    event_prefix = "PROCESS_"

    def match(self, event: dict) -> bool:
        if event.get("type") != "PROCESS_NEW":
            return False

        # --- 🛠️ VERİ DÖNÜŞTÜRME ---
        raw_cmdline = event.get("cmdline") or ""
        
        # Liste ise stringe çeviriyoruz ki .lower() ve 'in' operatörü hata vermesin
        if isinstance(raw_cmdline, list):
            cmdline_str = " ".join(raw_cmdline).lower()
        else:
            cmdline_str = str(raw_cmdline).lower()

        pname = (event.get("process_name") or "").lower()

        logger.debug(f"[{self.rule_id}] Checking: {pname} | Cmd: {cmdline_str}")

        # 1. Beyaz Liste Kontrolü
        if pname in SENSITIVE_ACCESS_WHITELIST:
            return False

        # 2. Hassas Dosya Kontrolü
        for s_file in SENSITIVE_FILES:
            clean_path = s_file.replace("*", "").lower()
            if clean_path in cmdline_str:
                logger.info(f"[{self.rule_id}] MATCH! Target: {clean_path} in {cmdline_str}")
                return True

        return False

    def build_alert(self, event: dict) -> dict:
        pname = event.get("process_name")
        user = event.get("username")
        pid = event.get("pid")
        
        # --- CMD_DISPLAY KULLANIMI ---
        raw_cmdline = event.get("cmdline")
        # Listeyi güzelce okunabilir bir stringe çeviriyoruz
        cmd_display = " ".join(raw_cmdline) if isinstance(raw_cmdline, list) else str(raw_cmdline)

        return self.build_alert_base(
            alert_type="ALERT_SENSITIVE_FILE_ACCESS",
            # Artık mesajın içinde tam komutu görebileceksin:
            message=f"Sensitive file access by user '{user}' | Command: {cmd_display} (PID: {pid})",
            extra=self.build_evidence_spec(
                source="process_events",
                filters={
                    "id__in": [event.get("id")] if event.get("id") else []
                }
            )
        )