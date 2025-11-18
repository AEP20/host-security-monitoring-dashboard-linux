#!/usr/bin/env python3
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.database import engine
from backend.models.base import Base

def main():
    print("== HIDS DB INIT ==")
    print("Veritabanı oluşturuluyor...")

    Base.metadata.create_all(bind=engine)

    print("Tablolar hazır.")

if __name__ == "__main__":
    main()
