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
                event.get("event_type") in ("FAILED_LOGIN", "FAILED_AUTH") and
                event.get("ip") is not None)

    def get_key(self, event):
        return (event.get("ip"),)

    def create_alert(self, key, events):
        ip = key[0]
        
        # Yarış durumu için ID'leri topla (ID'ler None olabilir)
        event_ids = [e.get("event_id") for e in events if e.get("event_id")]
        
        # ID'ler boş olsa bile resolver'ın bulabilmesi için zaman aralığını al
        timestamps = [e.get("ts") for e in events if e.get("ts")]
        
        return self.build_alert_base(
            alert_type="ALERT_SSH_BRUTEFORCE",
            message=f"SSH brute force from {ip} ({len(events)} attempts)",
            extra={
                "evidence_resolve": {
                    "source": "log_events", 
                    "filters": {
                        "ip_address": ip, 
                        "category": "AUTH",
                        "id__in": event_ids # Varsa ID ile, yoksa IP+Time ile bağlanacak
                    },
                    "time_range": {
                        "from": min(timestamps) if timestamps else None,
                        "to": max(timestamps) if timestamps else None
                    },
                    "limit": 10
                }
            }
        )