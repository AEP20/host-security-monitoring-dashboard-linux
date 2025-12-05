# 📁 regex_patterns.py

# Log parse ederken kullanılan regex’ler burada toplanır

import re

# Global Timestamp
TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
)

# Package 
PACKAGE = re.compile(
    r"\s([a-zA-Z0-9.+-]+):([a-z0-9]+)\s"
)

# Version 
VERSION = re.compile(
    r"\s([0-9.a-zA-Z~:+-]+)\s([0-9.a-zA-Z~:+-]+)$"
)

# DPKG Actions
DPKG_ACTIONS = ["install", "upgrade", "remove", "purge"]


# ============================
# AUTH LOG REGEX PATTERNS
# ============================

# Example: "Dec  4 12:32:10"
AUTH_TIMESTAMP = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)

# Example: sshd[12345]
AUTH_PID = re.compile(
    r"\[(\d+)\]"
)

# Example: for root  / for ubuntu
AUTH_USER = re.compile(
    r"for\s+([A-Za-z0-9_\-]+)"
)

# Example: from 185.21.33.10
AUTH_IP = re.compile(
    r"from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
)


# ============================
# KERNEL LOG REGEX PATTERNS
# ============================

import re

# Kernel panic
KERNEL_PANIC = re.compile(
    r"kernel panic", re.IGNORECASE
)

# Segfault
KERNEL_SEGFAULT = re.compile(
    r"(segfault|segmentation fault)", re.IGNORECASE
)

# Out of memory / OOM killer
KERNEL_OOM = re.compile(
    r"(Out of memory|OOM killer)", re.IGNORECASE
)

# USB device errors
KERNEL_USB_ERROR = re.compile(
    r"usb .* error", re.IGNORECASE
)

# Driver failures
KERNEL_DRIVER_FAIL = re.compile(
    r"driver .* failed", re.IGNORECASE
)

# Extract PID → "pid 1234"
KERNEL_PID = re.compile(
    r"pid\s+(\d+)"
)

# Extract process name → "process foo"
KERNEL_PROCESS = re.compile(
    r"process\s+([A-Za-z0-9_\-./]+)"
)

# ============================
# SYS LOG REGEX PATTERNS
# ============================

# Example timestamp: "Dec  4 13:20:44"
SYS_TIMESTAMP = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)

# systemd-unit: something happened
SYS_SYSTEMD = re.compile(
    r"systemd\[(\d+)\]:\s*(.*)"
)

# service name: foo.service
SYS_SERVICE_NAME = re.compile(
    r"([a-zA-Z0-9_.-]+)\.service"
)

# Failed to start xyz
SYS_FAILED_START = re.compile(
    r"Failed to start\s+(.+)"
)

# Started xyz
SYS_STARTED = re.compile(
    r"Started\s+(.+)"
)

# Stopped xyz
SYS_STOPPED = re.compile(
    r"Stopped\s+(.+)"
)

# Warning or error lines
SYS_WARNING = re.compile(
    r"warning", re.IGNORECASE
)
SYS_ERROR = re.compile(
    r"error|failed|critical", re.IGNORECASE
)


# ============================
# UFW LOG REGEX PATTERNS
# ============================

UFW_ACTION = re.compile(r"UFW (BLOCK|ALLOW)", re.IGNORECASE)

UFW_SRC_IP = re.compile(r"SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
UFW_DST_IP = re.compile(r"DST=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")

UFW_PROTOCOL = re.compile(r"PROTO=([A-Z]+)")

UFW_SRC_PORT = re.compile(r"SPT=(\d+)")
UFW_DST_PORT = re.compile(r"DPT=(\d+)")

UFW_IN_IF = re.compile(r"IN=([a-zA-Z0-9]+)")
UFW_OUT_IF = re.compile(r"OUT=([a-zA-Z0-9]+)")
