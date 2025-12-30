import re
from datetime import datetime

from backend.core.utils.regex_patterns import (
    TIMESTAMP,
    PACKAGE,
    VERSION,
    DPKG_ACTIONS
)
from backend.core.utils.hacking_tools import HACKING_TOOLS
from backend.core.utils.timestamp import parse_timestamp

class DpkgParser:

    VALID_ACTIONS = DPKG_ACTIONS

    # Public API

    def match(self, line: str) -> bool:
        """Bu satır DPKG formatına uyuyor mu?"""
        if not line:
            return False

        # TIMESTAMPT CHECK
        if not TIMESTAMP.match(line):
            return False

        return any(f" {action} " in line for action in self.VALID_ACTIONS)

    def parse(self, line: str) -> dict:
        """Ham satırdan structured event çıkarır."""
        ts = self.extract_timestamp(line)
        action = self.extract_action(line)
        package, arch = self.extract_package(line)
        old_ver, new_ver = self.extract_versions(line)

        event_type = self.normalize_event_type(action, old_ver, new_ver)
        severity = self.estimate_severity(action, package)

        return {
            "event_type": event_type,
            "log_source": "dpkg",
            "category": "PACKAGE",
            "severity": severity,
            "timestamp": ts,
            "raw": line,
            "message": f"{action} {package} (old:{old_ver} new:{new_ver})",
            "package": package,
            "arch": arch,
            "action": action,
            "old_version": old_ver,
            "new_version": new_ver,
        }

    # Internal Helpers

    def extract_timestamp(self, line):
        return parse_timestamp(line)

    def extract_action(self, line):
        for action in self.VALID_ACTIONS:
            if f" {action} " in line:
                return action
        return "unknown"

    def extract_package(self, line):
        m = PACKAGE.search(line)
        if not m:
            return None, None
        return m.group(1), m.group(2)

    def extract_versions(self, line):
        parts = line.split()

        if len(parts) < 5:
            return "<none>", "<none>"

        # son iki kolon = old ve new version
        return parts[-2], parts[-1]

    # Event Normalization 
    def normalize_event_type(self, action, old_ver, new_ver):
        if action == "install":
            return "PACKAGE_INSTALL"

        if action == "remove":
            return "PACKAGE_REMOVE"

        if action == "purge":
            return "PACKAGE_PURGE"

        if action == "upgrade":
            if self.is_downgrade(old_ver, new_ver):
                return "PACKAGE_DOWNGRADE"
            return "PACKAGE_UPGRADE"

        return "PACKAGE_EVENT"

    def is_downgrade(self, old_ver, new_ver):
        if old_ver == "<none>" or new_ver == "<none>":
            return False
        return new_ver < old_ver

    #SEVERITY CALC
    def estimate_severity(self, action, package):
        if package in HACKING_TOOLS:
            return "HIGH"

        if action in ["install", "remove"]:
            return "MEDIUM"

        return "LOW"
