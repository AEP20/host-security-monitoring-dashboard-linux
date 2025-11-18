    # """
    # Her log dosyası için son okunan byte offset'ini saklayan sınıf.
    # offsetler JSON dosyasında tutulur (ör: /var/lib/hids/log_offsets.json)
    # """

import os
import json
from threading import Lock


class OffsetManager:
    def __init__(self, state_file):
        self.state_file = state_file
        self._lock = Lock()  

        self._ensure_file_exists()

        self.offsets = self._load()

    # Internal helpers

    def _ensure_file_exists(self):
        """Dosya yoksa klasörü ve boş JSON dosyasını oluşturur."""
        directory = os.path.dirname(self.state_file)
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        if not os.path.exists(self.state_file):
            with open(self.state_file, "w") as f:
                json.dump({}, f)

    def _load(self):
        """JSON dosyasını okuyup dict olarak döner."""
        try:
            with open(self.state_file, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            # Dosya bozulmuşsa sıfırla
            return {}

    def _save(self):
        """Güncel offsetleri dosyaya atomic şekilde yazar."""
        with open(self.state_file, "w") as f:
            json.dump(self.offsets, f, indent=4)

    # Public API

    def get(self, key):
        """Bir log dosyası için offset’i döner. Yoksa 0 döner."""
        return self.offsets.get(key, 0)

    def set(self, key, value):
        """Offset günceller (ancak kaydetmez)."""
        with self._lock:
            self.offsets[key] = int(value)

    def save(self):
        """Offsetleri disk’e yazar (atomic)."""
        with self._lock:
            self._save()

    def reset(self, key):
        """Bir dosya için offset’i sıfırlar."""
        with self._lock:
            self.offsets[key] = 0
            self._save()

    def reset_all(self):
        """Tüm offsetleri sıfırlar."""
        with self._lock:
            self.offsets = {}
            self._save()
