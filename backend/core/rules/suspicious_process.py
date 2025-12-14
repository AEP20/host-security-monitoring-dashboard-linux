# 📁 suspicious_process.py

# Amaç: Şüpheli process pattern’lerini yakalamak.
# /tmp altından çalışan binary
# adı nc, ncat, masscan vs. olan process’ler

# core/rules/suspicious_process.py
from backend.core.rules.base import BaseRule
from datetime import datetime

class SuspiciousProcessRule(BaseRule):
    rule_id = "PROC_001"
    description = "Suspicious process execution"
    severity = "HIGH"
    event_prefix = "PROCESS_"

    SUSPICIOUS_NAMES = {"nc", "nmap", "hydra"}

    def match(self, event: dict) -> bool:
        name = event.get("process_name", "").lower()
        return name in self.SUSPICIOUS_NAMES

    def build_alert(self, event: dict) -> dict:
        return {
            "type": "ALERT_PROCESS_SUSPICIOUS",
            "rule_name": self.rule_id,         
            "severity": self.severity,
            "message": f"Suspicious process detected: {event.get('process_name')}",
            "log_event_id": None,             
        }
