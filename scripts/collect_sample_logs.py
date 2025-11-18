#!/usr/bin/env python3

import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.core.collector.logs_collector import LogsCollector


def main():
    print("Running LogsCollector test...\n")

    collector = LogsCollector()
    raw_logs = collector.collect()

    print(f"Toplam yeni satır: {len(raw_logs)}\n")

    for entry in raw_logs:
        src = entry["source"]
        line = entry["line"]
        print(f"[{src}] {line}")

    print("\nTest tamamlandı! (Yeni satır yoksa collector doğru çalışıyor demektir.)")


if __name__ == "__main__":
    main()
