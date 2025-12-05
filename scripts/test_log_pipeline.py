#!/usr/bin/env python3

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from backend.core.collector.logs_collector import LogsCollector
from backend.core.parser.LogDispatcher import LogDispatcher

def main():
    print("\n===== HIDS LOG PARSER PIPELINE TEST =====\n")

    collector = LogsCollector()
    dispatcher = LogDispatcher()

    logs = collector.collect()

    print(f"Toplam yeni log satırı: {len(logs)}\n")

    for entry in logs:
        source = entry["source"]
        line = entry["line"]

        event = dispatcher.dispatch(source, line)

        print(f"[{source.upper()}] RAW: {line}")

        if event:
            print("  → PARSED EVENT:", event)
        else:
            print("  → NO MATCH / SKIPPED")

        print("-" * 60)

if __name__ == "__main__":
    main()
