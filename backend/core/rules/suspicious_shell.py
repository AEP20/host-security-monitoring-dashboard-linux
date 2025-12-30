from backend.core.rules.base import StatelessRule
from backend.logger import logger
from typing import Dict, Any

class SuspiciousShellRule(StatelessRule):
    rule_id = "PROC_002"
    description = "Suspicious shell execution by non-shell process"
    severity = "CRITICAL"
    event_prefix = "PROCESS_"

    SUSPICIOUS_PARENTS = ["python", "python3", "php", "node", "perl", "nc", "netcat", "socat", "lua"]
    
    SHELL_PROCESSES = ["sh", "bash", "zsh", "dash", "rbash"]

    def match(self, event: Dict[str, Any]) -> bool:
        if event.get("type") != "PROCESS_NEW":
            return False

        pname = (event.get("process_name") or "").lower()
        parent_pname = (event.get("parent_name") or "").lower()

        if pname in self.SHELL_PROCESSES:
            if any(parent in parent_pname for parent in self.SUSPICIOUS_PARENTS):
                logger.warning(f"[{self.rule_id}] Suspicious shell spawn: {parent_pname} -> {pname}")
                return True

        return False

    def build_alert(self, event: Dict[str, Any]) -> Dict[str, Any]:
        pname = event.get("process_name")
        parent = event.get("parent_name")
        cmdline = event.get("cmdline")
        user = event.get("username") or "unknown"

        return self.build_alert_base(
            alert_type="ALERT_SUSPICIOUS_SHELL",
            message=f"Critical Alert: Process '{parent}' spawned a shell '{pname}' under user '{user}'. Potential Reverse Shell!",
            extra=self.build_evidence_spec(
                source="process_events",
                filters={"id": event.get("id")}
            )
        )