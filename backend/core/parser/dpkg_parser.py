import re
from datetime import datetime

class DpkgParser:
    VALID_ACTIONS = ["install", "upgrade", "remove", "purge"]

    # ---- Public API ---------------------------------------------------------

    def match(self, line: str) -> bool:
        """Bu satır DPKG formatına uyuyor mu?"""
        if not line:
            return False

        if not re.match(r"^\d{4}-\d{2}-\d{2}", line):
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

    # Internal Parsing Helpers
    def extract_timestamp(self, line):
        m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if not m:
            return None
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")

    def extract_action(self, line):
        for action in self.VALID_ACTIONS:
            if f" {action} " in line:
                return action
        return "unknown"

    def extract_package(self, line):
        """
        nmap:arm64 → ("nmap", "arm64")
        """
        m = re.search(r"\s([a-zA-Z0-9.+-]+):([a-z0-9]+)\s", line)
        if not m:
            return None, None
        return m.group(1), m.group(2)

    def extract_versions(self, line):
        """
        Basit yaklaşım:
            <old> <new>
        Upgrade/downgrade ayrımı normalize_event_type içinde yapılır.
        """
        parts = line.split()
        # timestamp + action + package, 3 kolon
        if len(parts) < 5:
            return "<none>", "<none>"

        old_ver = parts[-2]
        new_ver = parts[-1]

        return old_ver, new_ver

    # Event type normalization 
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
        """
        Çok basit downgrade kontrolü:
        - Version string alphabetically greater ise downgrade sayılır
        """
        if old_ver == "<none>" or new_ver == "<none>":
            return False
        return new_ver < old_ver

    # Severity Estimation 
    def estimate_severity(self, action, package):
        """
        - install veya remove → MEDIUM
        - purge → LOW
        - upgrade → LOW
        - hacking tool→ HIGH
        """

        # geliştirilecek
        hacking_tools = [
            "nmap", "netcat", "nc", "hydra", "medusa", "john", "sqlmap",
            "aircrack-ng", "kismet", "metasploit", "msfconsole"
        ]

        if package in hacking_tools:
            return "HIGH"

        if action in ["install", "remove"]:
            return "MEDIUM"

        return "LOW"
