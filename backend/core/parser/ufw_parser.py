import re
from datetime import datetime

from backend.core.utils.regex_patterns import (
    AUTH_TIMESTAMP,   
    UFW_ACTION,
    UFW_SRC_IP,
    UFW_DST_IP,
    UFW_PROTOCOL,
    UFW_SRC_PORT,
    UFW_DST_PORT,
    UFW_IN_IF,
    UFW_OUT_IF,
)
from backend.core.utils.timestamp import parse_timestamp


class UfwParser:
    """
        - UFW_BLOCK
        - UFW_ALLOW
    Ek bilgiler:
        - src_ip, dst_ip
        - spt, dpt
        - protocol
        - interface bilgisi (IN/OUT)
    """

    # ---------------------------
    # PUBLIC API
    # ---------------------------

    def match(self, line: str) -> bool:
        """Bu satır UFW log formatına uyuyor mu?"""
        if not line:
            return False

        return "UFW " in line

    def parse(self, line: str) -> dict:

        ts = self.extract_timestamp(line)
        event_type = self.extract_event_type(line)
        src_ip = self.extract_src_ip(line)
        dst_ip = self.extract_dst_ip(line)
        protocol = self.extract_protocol(line)
        src_port = self.extract_src_port(line)
        dst_port = self.extract_dst_port(line)
        in_if = self.extract_in_interface(line)
        out_if = self.extract_out_interface(line)

        severity = self.estimate_severity(event_type)

        return {
            "event_type": event_type,
            "log_source": "ufw",
            "category": "FIREWALL",
            "severity": severity,

            "timestamp": ts,
            "raw": line.strip(),
            "message": line.strip(),

            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "in_interface": in_if,
            "out_interface": out_if,
        }

    # ---------------------------
    # HELPERS
    # ---------------------------

    def extract_timestamp(self, line: str):
        return parse_timestamp(line)

    def extract_event_type(self, line: str):
        m = UFW_ACTION.search(line)
        if not m:
            return "UFW_EVENT"
        action = m.group(1).upper()
        return f"UFW_{action}"

    def extract_src_ip(self, line: str):
        m = UFW_SRC_IP.search(line)
        return m.group(1) if m else None

    def extract_dst_ip(self, line: str):
        m = UFW_DST_IP.search(line)
        return m.group(1) if m else None

    def extract_protocol(self, line: str):
        m = UFW_PROTOCOL.search(line)
        return m.group(1) if m else None

    def extract_src_port(self, line: str):
        m = UFW_SRC_PORT.search(line)
        return int(m.group(1)) if m else None

    def extract_dst_port(self, line: str):
        m = UFW_DST_PORT.search(line)
        return int(m.group(1)) if m else None

    def extract_in_interface(self, line: str):
        m = UFW_IN_IF.search(line)
        return m.group(1) if m else None

    def extract_out_interface(self, line: str):
        m = UFW_OUT_IF.search(line)
        return m.group(1) if m else None

    # ---------------------------
    # SEVERITY MAPPING
    # ---------------------------

    def estimate_severity(self, event_type: str):

        if event_type == "UFW_BLOCK":
            return "MEDIUM"  # block önemli

        if event_type == "UFW_ALLOW":
            return "LOW"     

        return "LOW"
