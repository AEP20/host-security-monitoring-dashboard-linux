# Açık portlar ve network bağlantılarını keşfetmek.
# ss -tulnp veya benzeri komutlarla open port’ları çıkarır
# port → process mapping (mümkünse)
# network bağlantı sayısı
# Bu veri, port_exposure kuralında kullanılır.

# 🟦 📌 NETWORK COLLECTOR — (Snapshot)
# Nasıl çalışmalı?
# 2 seçenek:
# A) psutil.net_connections()
# en temiz yöntem:
# port
# pid
# ip, local addr, remote addr
# Ne tutacağız?
# 5 saniyede bir sistemin anlık network durumunu göreceğiz.
# Değişimleri algılamayı rule engine yapar:
# yeni port açıld
# process yeni bir dış IP’ye bağlandı