# 📁 kernel_parser.py

# Kernel loglarını “critical errors” için parse eder.

# Event’ler:

# KERNEL_PANIC

# SEGFAULT

# OOM killer

from datetime import datetime

from backend.core.utils.regex_patterns import (
    AUTH_TIMESTAMP,
    KERNEL_PANIC,
    KERNEL_SEGFAULT,
    KERNEL_OOM,
    KERNEL_USB_ERROR,
    KERNEL_DRIVER_FAIL,
    KERNEL_PID,
    KERNEL_PROCESS
)

class KernelParser:
    """
    Kernel loglarını parse ederek structured event üretir.
    Yakalanan kritik olaylar:
    - Kernel Panic
    - Segfault
    - OOM Killer
    """

    def match(self, line: str) -> bool:
        """Kernel check"""
        if not line:
            return False

        keywords = [
            "kernel", "panic", "segfault", "Out of memory",
            "OOM", "driver", "usb", "segmentation fault"
        ]

        return any(k.lower() in line.lower() for k in keywords)

    def parse(self, line: str) -> dict:

        ts = self.extract_timestamp(line)
        event_type = self.detect_event_type(line)
        severity = self.estimate_severity(event_type)

        return {
            "event_type": event_type,
            "log_source": "kernel",
            "category": "KERNEL",
            "severity": severity,

            "timestamp": ts,
            "raw": line.strip(),
            "message": line.strip(),

            "user": None,
            "ip": None,
            "method": None,

            "pid": self.extract_pid(line),
            "process": self.extract_process_name(line),
        }

    # ---------------------------
    # HELPERS
    # ---------------------------

    def extract_timestamp(self, line: str):
        if not AUTH_TIMESTAMP.match(line):
            return None

        try:
            month_str = line[0:3]
            day = int(line[4:6])
            time_str = line[7:15]

            MONTHS = {
                "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
                "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
                "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
            }

            month = MONTHS.get(month_str)
            year = datetime.now().year

            return datetime.strptime(
                f"{year}-{month}-{day} {time_str}",
                "%Y-%m-%d %H:%M:%S"
            )
        except:
            return None

    def extract_pid(self, line: str):
        m = KERNEL_PID.search(line)
        return int(m.group(1)) if m else None

    def extract_process_name(self, line: str):
        m = KERNEL_PROCESS.search(line)
        return m.group(1) if m else None

    # ---------------------------
    # EVENT TYPE LOGIC
    # ---------------------------

    def detect_event_type(self, line: str):

        if KERNEL_PANIC.search(line):
            return "KERNEL_PANIC"

        if KERNEL_SEGFAULT.search(line):
            return "SEGFAULT"

        if KERNEL_OOM.search(line):
            return "OOM_KILLER"

        if KERNEL_USB_ERROR.search(line):
            return "USB_ERROR"

        if KERNEL_DRIVER_FAIL.search(line):
            return "DRIVER_ERROR"

        return "KERNEL_EVENT"

    # ---------------------------
    # SEVERITY
    # ---------------------------

    def estimate_severity(self, event_type: str):

        if event_type == "KERNEL_PANIC":
            return "CRITICAL"

        if event_type == "OOM_KILLER":
            return "HIGH"

        if event_type == "SEGFAULT":
            return "HIGH"

        if event_type in ["USB_ERROR", "DRIVER_ERROR"]:
            return "MEDIUM"

        return "LOW"
