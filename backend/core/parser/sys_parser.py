# 📁 sys_parser.py

# Girdi: syslog satırları
# Çıktı: “SERVICE_FAILED”, “SYSTEM_WARNING” gibi event’ler.

# Ör:

# {
#   "timestamp": ...,
#   "event_type": "SERVICE_FAILED",
#   "service": "nginx",
#   "message": "failed to start"
# }


import re
from datetime import datetime

from backend.core.utils.regex_patterns import (
    SYS_TIMESTAMP,
    SYS_SYSTEMD,
    SYS_SERVICE_NAME,
    SYS_FAILED_START,
    SYS_STARTED,
    SYS_STOPPED,
    SYS_WARNING,
    SYS_ERROR
)
from backend.core.utils.timestamp import parse_timestamp

class SysParser:
    """
    - SERVICE_FAILED
    - SERVICE_STARTED
    - SERVICE_STOPPED
    - SYSTEM_WARNING
    - SYSTEM_ERROR
    - SYS_EVENT (generic)
    """

    # ---------------------------
    # PUBLIC API
    # ---------------------------

    def match(self, line: str) -> bool:
        """syslog formatına uyuyor mu?"""
        if not line:
            return False
        return bool(SYS_TIMESTAMP.match(line))

    def parse(self, line: str) -> dict:

        ts = self.extract_timestamp(line)
        service = self.extract_service_name(line)
        event_type = self.detect_event_type(line)
        severity = self.estimate_severity(event_type)

        return {
            "event_type": event_type,
            "log_source": "syslog",
            "category": "SYSTEM",
            "severity": severity,

            "timestamp": ts,
            "raw": line.strip(),
            "message": line.strip(),

            "service": service,
            "user": None,
            "ip": None,
        }

    # ---------------------------
    # HELPERS
    # ---------------------------

    def extract_timestamp(self, line: str): 
        return parse_timestamp(line)

    def extract_service_name(self, line: str):
        """systemd veya service restart satırlarında service adını yakala."""
        m = SYS_SERVICE_NAME.search(line)
        return m.group(1) if m else None

    # ---------------------------
    # EVENT TYPE DETECTION
    # ---------------------------

    def detect_event_type(self, line: str):

        lower = line.lower()

        # High-level failures
        if SYS_FAILED_START.search(line):
            return "SERVICE_FAILED"

        if SYS_STARTED.search(line):
            return "SERVICE_STARTED"

        if SYS_STOPPED.search(line):
            return "SERVICE_STOPPED"

        if SYS_ERROR.search(lower):
            return "SYSTEM_ERROR"

        if SYS_WARNING.search(lower):
            return "SYSTEM_WARNING"

        return "SYS_EVENT"

    # ---------------------------
    # SEVERITY MAPPING
    # ---------------------------

    def estimate_severity(self, event_type):

        if event_type == "SERVICE_FAILED":
            return "HIGH"

        if event_type == "SYSTEM_ERROR":
            return "HIGH"

        if event_type == "SERVICE_STOPPED":
            return "MEDIUM"

        if event_type == "SYSTEM_WARNING":
            return "LOW"

        return "LOW"
