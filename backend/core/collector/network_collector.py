#network_collector

# 🟦 📌 NETWORK COLLECTOR — (Snapshot)
# Nasıl çalışmalı?
# A) psutil

# | Görev                         | Tür   | Açıklama                                                                |
# | ----------------------------- | ----- | ----------------------------------------------------------------------- |
# | *Interface I/O ölçümü*      | STATE | Her interface için trafik istatistikleri (bytes/packets, errors, drops) |
# | *Aktif bağlantı listesi*    | STATE | Sistemdeki tüm TCP/UDP bağlantılarının snapshot’ı                       |
# | *Yeni bağlantı tespiti*     | EVENT | Snapshot diff ile tespit edilen yeni remote IP/port bağlantıları        |
# | *Bağlantı kapanması*        | EVENT | Önceki snapshot’ta olup şu anda olmayan bağlantılar                     |
# | *Yeni listening port*       | EVENT | Bir process’in yeni bir LISTEN port açması (server davranışı)           |
# | *Process–connection eşleme* | STATE | Her bağlantının hangi PID/process tarafından açıldığının belirlenmesi   |

# Çalışma Mantığı (Özet)
# -Local JSON cache → previous snapshot olarak yüklenir
# •⁠  ⁠psutil ile current snapshot toplanır
# •⁠  ⁠previous vs current → diff yapılır
# •⁠  ⁠NEW_CONNECTION, CLOSED_CONNECTION, NEW_LISTEN_PORT gibi event’ler oluşturulur
# •⁠  ⁠Event’ler DB’ye veya mesaj kuyruğuna gönderilir
# •⁠  ⁠current snapshot → RAM’de previous olarak overwrite edilir
# •⁠  ⁠current snapshot → local cache’e overwrite edilerek kaydedilir

# oluşturulan eventler event_dispatchera gidip orada dbye kaydolacağı için eventlerin başında  NET_ veya CONNECTION_ olarak başlamalıdır.
# event_dispatcher icindeki kısım aşağıdaki gibidir,

        # # NETWORK
        # if etype.startswith("NET_") or etype.startswith("CONNECTION_"):
        #     return self._handle_network(event)


