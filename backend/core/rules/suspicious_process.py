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
        return self._get_process_name(event) in HACKING_TOOLS

    def build_alert(self, event: dict) -> dict:
        ts = event.get("timestamp")
        pname = self._get_process_name(event)

        return self.build_alert_base(
            alert_type="ALERT_PROCESS_SUSPICIOUS",
            message=f"Suspicious process detected: {pname}",
            extra={
                "evidence_resolve": {
                    "source": "process_events",
                    "filters": {
                        "process_name": pname,
                        "pid": event.get("pid"),
                    },
                    "time_range": {
                        "from": ts,
                        "to": ts,
                    },
                    "limit": 1,
                }
            },
        )
