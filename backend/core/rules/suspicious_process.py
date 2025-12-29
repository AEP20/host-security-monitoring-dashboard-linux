# backend/core/rules/suspicious_process.py
from backend.core.rules.base import StatelessRule
from backend.core.utils.hacking_tools import HACKING_TOOLS


class SuspiciousProcessRule(StatelessRule):
    rule_id = "PROC_001"
    description = "Suspicious process execution"
    severity = "HIGH"
    event_prefix = "PROCESS_"

    def _get_process_name(self, event: dict) -> str:
        # Event içindeki process ismini normalize et
        return (event.get("process_name") or event.get("name") or "").lower()

    def match(self, event: dict) -> bool:
        # Hacking araçları listesinde var mı kontrol et
        return self._get_process_name(event) in HACKING_TOOLS

    def build_alert(self, event: dict) -> dict:
        pname = self._get_process_name(event)
        pid = event.get("pid")

        return self.build_alert_base(
            alert_type="ALERT_PROCESS_SUSPICIOUS",
            message=f"Suspicious process detected: {pname} (PID: {pid})",
            # Yeni helper ile evidence spec oluşturma:
            extra=self.build_evidence_spec(
                source="process_events",
                filters={"process_name": pname, "pid": pid},
                limit=1
            )
        )