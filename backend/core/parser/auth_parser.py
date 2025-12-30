# 6.2 core/parser/auth_parser.py

# Bu dosyaların amacı:
# Ham log satırlarını parse edip “event” nesneleri haline getirmek.

# 📁 auth_parser.py

# Girdi: auth.log satırları
# Çıktı: Örn:

# {
#   "timestamp": ...,
#   "event_type": "FAILED_LOGIN" veya "SUCCESS_LOGIN",
#   "user": "ahmet",
#   "ip": "10.0.0.1",
#   "method": "password" vs.
# }

from datetime import datetime
from backend.core.utils.timestamp import parse_timestamp

from backend.core.utils.regex_patterns import (
    AUTH_PID,
    AUTH_IP,
    AUTH_USER,
    AUTH_TIMESTAMP,
)

class AuthParser:
    """
    /var/log/auth.log satırlarını structured event haline getirir.
    SSH login, sudo, PAM olaylarını işler.
    """

    MONTHS = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
        "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
        "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    # ---------------------------
    # Public API
    # ---------------------------

    def match(self, line: str) -> bool:
        """Bu satır auth.log formatına uyuyor mu?"""

        if not line:
            return False

        # SSH veya sudo contains -> auth satir
        keywords = [
            "sshd", "sudo", "authentication failure",
            "Failed password", "Accepted password",
            "session opened", "session closed"
        ]

        return any(k in line for k in keywords)

    def parse(self, line: str) -> dict:
        ts = self.extract_timestamp(line)
        event_type = self.detect_event_type(line)
        user = self.extract_user(line)
        ip = self.extract_ip(line)
        method = self.extract_method(line)
        pid = self.extract_pid(line)

        severity = self.estimate_severity(event_type, user)

        return {
            "event_type": event_type,
            "log_source": "auth",
            "category": "AUTH",
            "severity": severity,
            "timestamp": ts,
            "raw": line.strip(),

            "user": user,
            "ip": ip,
            "method": method,
            "pid": pid,
            "message": line.strip(),
        }

    # ---------------------------
    # INTERNAL HELPERS
    # ---------------------------

    def extract_timestamp(self, line):
        return parse_timestamp(line)

    def extract_pid(self, line: str):
        m = AUTH_PID.search(line)
        return int(m.group(1)) if m else None

    def extract_ip(self, line: str):
        m = AUTH_IP.search(line)
        return m.group(1) if m else None

    def extract_user(self, line: str):
        m = AUTH_USER.search(line)
        if not m:
            return None

        user = m.group(1)

        if user in ["invalid", "user"]:
            return None

        return user

    def extract_method(self, line: str):
        line_lower = line.lower()

        if "password" in line_lower:
            return "password"
        if "publickey" in line_lower:
            return "publickey"
        if "keyboard-interactive" in line_lower:
            return "keyboard-interactive"
        return None

    # ---------------------------
    # EVENT TYPE DETECTION
    # ---------------------------

    def detect_event_type(self, line: str):
        l = line.lower()

        if "failed password" in l:
            return "FAILED_LOGIN"

        if "accepted password" in l or "accepted publickey" in l:
            return "SUCCESS_LOGIN"

        if "authentication failure" in l:
            return "FAILED_AUTH"

        if "sudo:" in l and "authentication failure" in l:
            return "SUDO_FAILED"

        if "sudo:" in l and "session opened" in l:
            return "SUDO_SESSION_OPEN"

        if "sudo:" in l and "session closed" in l:
            return "SUDO_SESSION_CLOSE"

        if "session opened" in l:
            return "SESSION_OPEN"

        if "session closed" in l:
            return "SESSION_CLOSE"

        return "AUTH_EVENT"

    # ---------------------------
    # SEVERITY CALCULATOR
    # ---------------------------

    def estimate_severity(self, event_type, user):
        if event_type in ["FAILED_LOGIN", "FAILED_AUTH"]:
            return "MEDIUM"

        if event_type == "SUCCESS_LOGIN" and user == "root":
            return "HIGH"

        if event_type.startswith("SUDO"):
            return "HIGH"

        return "LOW"