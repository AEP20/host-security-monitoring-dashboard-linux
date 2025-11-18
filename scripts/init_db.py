#!/usr/bin/env python3

import sys
import os

# --- Import path ayarı ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.database import init_db

def main():
    print("== HIDS DB INIT ==")
    print("veritabanı oluşturuluyor...")

    init_db()

    print("Tablolar hazır.\n")

if __name__ == "__main__":
    main()
