#process_collector

# Çalışan process’leri toplamak.
# psutil ile process listesi
# CPU / RAM tüketimi
# process path’i (binary nerede)
# user (root mu vs.)

# 🟦 📌 PROCESS COLLECTOR — (Snapshot)
# Nasıl çalışmalı?
# Her X saniyede psutil.process_iter() ile tüm process listesi alınır.
# Bu, sistemin o anki process inventory’sidir.
# Eski process'ler tekrar gelmez çünkü:
# Process ID (PID) değişir.
# Collector sadece o an var olan process’leri üretir.
# Rule engine geçmişi kendisi tutabilir (mesela bir process kayboldu mu diye).
# Biriktirme mantığı yok.
# Her çalışmada: “şu an çalışanların tablosu”.