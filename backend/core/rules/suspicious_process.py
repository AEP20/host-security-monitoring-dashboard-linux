# core/rules/suspicious_process.py

from backend.core.rules.base import BaseRule

class SuspiciousProcessRule(BaseRule):
    """
    PROC_001 – Suspicious process execution

    Detects execution of well-known offensive tools
    such as nc, nmap, hydra etc.
    """

    rule_id = "PROC_001"
    description = "Suspicious process execution"
    severity = "HIGH"
    event_prefix = "PROCESS_"

    SUSPICIOUS_NAMES = {"nc", "nmap", "hydra"}

    # -----------------------------
    # INTERNAL HELPERS
    # -----------------------------
    def _get_process_name(self, event: dict) -> str:
        """
        Normalize process name across collectors.
        PROCESS events may contain:
          - name
          - process_name
        """
        return (
            event.get("process_name")
            or event.get("name")
            or ""
        ).lower()

    # -----------------------------
    # RULE LOGIC
    # -----------------------------
    def match(self, event: dict) -> bool:
        pname = self._get_process_name(event)
        return pname in self.SUSPICIOUS_NAMES

    def build_alert(self, event: dict) -> dict:
        pname = self._get_process_name(event)

        return {
            "type": "ALERT_PROCESS_SUSPICIOUS",
            "rule_name": self.rule_id,
            "severity": self.severity,
            "message": f"Suspicious process detected: {pname}",
            "log_event_id": None,
        }
