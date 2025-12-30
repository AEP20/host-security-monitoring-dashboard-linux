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

        raw_cmdline = event.get("cmdline") or ""
        
        if isinstance(raw_cmdline, list):
            cmdline_str = " ".join(raw_cmdline).lower()
        else:
            cmdline_str = str(raw_cmdline).lower()

        pname = (event.get("process_name") or "").lower()

        logger.debug(f"[{self.rule_id}] Checking: {pname} | Cmd: {cmdline_str}")

        # WHITELIST CHECK
        if pname in SENSITIVE_ACCESS_WHITELIST:
            return False

        # SENSETIVE FILE CHECK
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
        
        raw_cmdline = event.get("cmdline")
        cmd_display = " ".join(raw_cmdline) if isinstance(raw_cmdline, list) else str(raw_cmdline)

        return self.build_alert_base(
            alert_type="ALERT_SENSITIVE_FILE_ACCESS",
            message=f"Sensitive file access by user '{user}' | Command: {cmd_display} (PID: {pid})",
            extra=self.build_evidence_spec(
                source="process_events",
                filters={
                    "id__in": [event.get("id")] if event.get("id") else []
                }
            )
        )