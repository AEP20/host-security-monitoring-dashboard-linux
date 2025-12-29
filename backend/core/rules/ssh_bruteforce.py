# backend/core/rules/ssh_bruteforce.py
from backend.core.rules.base import ThresholdRule

class SSHBruteforceRule(ThresholdRule):
    rule_id = "AUTH_001"
    description = "SSH brute force attack detected"
    severity = "HIGH"
    event_prefix = "LOG_EVENT"
    
    threshold = 3
    window_seconds = 60

    def is_relevant(self, event):
        return (event.get("category") == "AUTH" and 
                event.get("event_type") in ("FAILED_LOGIN", "FAILED_AUTH"))

    def get_key(self, event):
        return (event.get("ip"),)

    def create_alert(self, key, events):
        ip = key[0]
        return self.build_alert_base(
            alert_type="ALERT_SSH_BRUTEFORCE",
            message=f"SSH brute force from {ip} ({len(events)} attempts)",
            extra=self.build_evidence_spec("log_events", {"ip_address": ip})
        )