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
