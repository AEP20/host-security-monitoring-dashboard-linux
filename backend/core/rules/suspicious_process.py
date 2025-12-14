from backend.core.rules.base import StatelessRule
from backend.core.utils.hacking_tools import HACKING_TOOLS


class SuspiciousProcessRule(StatelessRule):
    rule_id = "PROC_001"
    description = "Suspicious process execution"
    severity = "HIGH"
    event_prefix = "PROCESS_"

    def _get_process_name(self, event: dict) -> str:
        return (event.get("process_name") or event.get("name") or "").lower()

    def match(self, event: dict) -> bool:
        pname = self._get_process_name(event)
        return pname in HACKING_TOOLS

    def build_alert(self, event: dict) -> dict:
        pname = self._get_process_name(event)
        return self.build_alert_base(
            alert_type="ALERT_PROCESS_SUSPICIOUS",
            message=f"Suspicious process detected: {pname}",
            log_event_id=None,
            related_events=self.related_events(event),
        )
