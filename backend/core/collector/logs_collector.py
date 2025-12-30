# Amaç: Linux log dosyalarından ham satırları çekmek.
# Bunlar henüz parse edilmemiş ham text.

# Her çalıştırmada:
# log dosyasının son okunan byte'ını saklarız.
# Son okunan offset’ten sonraki satırları çekeriz.
# Böylece:
# eski satırlar tekrar okunmaz
# yeni satırlar kaçmaz


# 🟩 1) /var/log/auth.log — EN ÖNEMLİ DOSYA

# Bu dosya olmazsa HIDS olmaz.
# Buradan yakalayabileceğin olaylar:
# failed SSH attempt
# successful SSH login
# sudo kullanımı
# root login
# PAM/U2F doğrulama olayları
# ssh-key based login
# brute-force tespiti (rule engine ile)
# Kesin okunacak.
# Bu senin HIDS’in kalbi.

# 🟩 2) /var/log/syslog — Genel sistem olayları

# Bu log:
# servis restartları
# daemon hataları
# network interface değişiklikleri
# hostname değişimleri
# disk/network hata mesajları
# gibi çok geniş kapsamlı olayları içerir.
# Kesin okunacak.

# 🟩 3) /var/log/kern.log — Kernel seviyesinde şüpheli aktiviteler

# Buradan:
# kernel errors
# segmentation faults
# driver hataları
# network stack uyarıları
# firewall iptables/out-of-memory killer
# çıkar.
# Bu dosya olmazsa olmaz değil,
# ama eğer okursan:
# → “kernel panic / kernel exploit attempt” gibi sorunlara karşı görünürlük artar.
# Önerilir, düşük maliyetli, değerli.

# 🟩 4) /var/log/dpkg.log — Paket kurulum/değişiklik logları

# Gerçekten değerli.
# Çünkü:
# Yeni paket yüklenmesi = compromise ihtimali.
# Yakalanabilir olaylar:
# “unexpected package installation”
# “package removed”
# “package version change”
# “suspicious tool installation (nmap, netcat, hydra, john, metasploit…)”
# Bu sayede
# sistemde yetkisiz paket yüklemesi olursa anında alert verebilirsin.
# Kesin önerilir.

# 🟧 5) BONUS: /var/log/ufw.log — Firewall events

# Eğer makinede UFW kullanıyorsa (Ubuntu default olarak disabled gelir fakat kolayca açılır):
# bloklanan ip
# bloklanan bağlantı denemesi
# kabul edilen TCP/UDP trafik
# → çok güzel security sinyalleri çıkar.
# Ama her kullanıcıda UFW açık olmayabilir, yani parser yazıp hiçbir veri alamama durumu olabilir.
# O yüzden:
# Optional ama güzel bir katkı.


# 🟩 7) OPTIONAL: /var/log/apt/history.log
# dpkg’ye benzer ama özellikle:
# hangi user patch yükledi
# hangi paket hangi tarihte güncellendi
# upgrade/ downgrade geçmişi
# gibi daha “audit-friendly” bilgiler içerir.


import os
from backend.core.collector.offsets_manager import OffsetManager
from backend.logger import logger


class LogsCollector:
    LOG_FILES = {
        "auth": "/var/log/auth.log",
        "syslog": "/var/log/syslog",
        "kernel": "/var/log/kern.log",
        "dpkg": "/var/log/dpkg.log",
        "ufw": "/var/log/ufw.log",
    }

    def __init__(self, state_file="/var/lib/hids/log_offsets.json"):
        self.offset_manager = OffsetManager(state_file)
        logger.info(f"[LogsCollector] Initialized with state file: {state_file}")

    def collect(self):
        logger.debug("[LogsCollector] collect() invoked")
        results = []

        for source, path in self.LOG_FILES.items():
            lines = self._read_file(source, path)
            if lines:
                logger.info(f"[LogsCollector] {source}: collected {len(lines)} new lines")
            results.extend({"source": source, "line": line} for line in lines)

        self.offset_manager.save()
        logger.debug("[LogsCollector] Offsets saved after collection")

        return results

    # INTERNAL HELPERS
    def _read_file(self, source, filepath):
        if not os.path.exists(filepath):
            logger.warning(f"[LogsCollector] Log file not found: {filepath}")
            return []

        last_offset = self.offset_manager.get(source)
        file_size = os.path.getsize(filepath)

        if last_offset > file_size:
            logger.warning(f"[LogsCollector] Offset reset for {source} (file truncated or rotated)")
            last_offset = 0
            self.offset_manager.set(source, 0)

        new_lines = []

        try:
            with open(filepath, "r", errors="ignore") as f:
                f.seek(last_offset)
                for line in f:
                    new_lines.append(line.rstrip("\n"))

                new_offset = f.tell()
                self.offset_manager.set(source, new_offset)

        except Exception as e:
            logger.error(f"[LogsCollector] Failed reading {source}: {e}")
            return []

        if new_lines:
            logger.debug(f"[LogsCollector] {source}: read {len(new_lines)} new lines")

        return new_lines
