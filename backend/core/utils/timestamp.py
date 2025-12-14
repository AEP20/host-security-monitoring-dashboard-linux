from datetime import datetime

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_timestamp(line: str):
    if not line:
        return None

    try:
        # ISO-8601 (journald)
        if line[0].isdigit():
            parts = line.split()
            if "T" in parts[0]:
                return datetime.fromisoformat(parts[0])
            if len(parts) >= 2:
                return datetime.fromisoformat(f"{parts[0]} {parts[1]}")

        # Klasik syslog
        month_str = line[0:3]
        if month_str not in MONTHS:
            return None

        day = int(line[4:6])
        time_str = line[7:15]
        year = datetime.now().year

        return datetime.strptime(
            f"{year}-{MONTHS[month_str]}-{day} {time_str}",
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:
        return None
