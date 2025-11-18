#!/usr/bin/env python3

import sys
import os

# --- Path ayarı (backend importları için) ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.core.collector.logs_collector import LogsCollector
from backend.core.parser.dispatcher import LogDispatcher
from backend.database import SessionLocal
from backend.models.log_model import LogEventModel


def main():
    print("\n===== HIDS Log Pipeline Test (Collector → Parser → DB) =====\n")

    collector = LogsCollector()
    dispatcher = LogDispatcher()

    raw_logs = collector.collect()

    print(f"Toplam yeni satır bulundu: {len(raw_logs)}\n")

    for entry in raw_logs:
        src = entry["source"]
        line = entry["line"]

        print(f"[RAW] ({src}) {line}")

        event = dispatcher.dispatch(src, line)

        if event:
            print(f"  → [PARSED] {event['event_type']} | {event['message']}")
        else:
            print("  → [SKIPPED] Parser bu satırı işlemedi.")

    # --- DB kontrol ---
    session = SessionLocal()
    total = session.query(LogEventModel).count()
    session.close()

    print("\n-------------------------------------------")
    print(f"DB kontrol: log_events tablosunda toplam {total} kayıt var.")
    print("-------------------------------------------\n")

    print("Test tamamlandı!\n")


if __name__ == "__main__":
    main()
