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
        
#### tüm event tipleri,

# -----------------------------------------
# NET_NEW_CONNECTION
# -----------------------------------------
# Bir process, yeni bir remote bağlantı açtı.

# Alanlar:
# - type: "NET_NEW_CONNECTION"
# - timestamp
# - pid
# - process_name
# - laddr_ip
# - laddr_port
# - raddr_ip
# - raddr_port
# - status  (ESTABLISHED / SYN_SENT / SYN_RECV)


# -----------------------------------------
# NET_CLOSED_CONNECTION
# -----------------------------------------
# Önceden var olan bir bağlantı artık yok.

# Alanlar:
# - type: "NET_CLOSED_CONNECTION"
# - timestamp
# - pid
# - process_name
# - laddr_ip
# - laddr_port
# - raddr_ip
# - raddr_port


# -----------------------------------------
# NET_CLOSED_LISTEN_PORT
# -----------------------------------------
# Daha önce açık olan bir LISTEN port artık kapalı.

# Alanlar:
# - type: "NET_CLOSED_LISTEN_PORT"
# - timestamp
# - pid
# - process_name
# - laddr_ip
# - laddr_port
# - protocol


# -----------------------------------------
# CONNECTION_SUSPICIOUS_REMOTE
# -----------------------------------------
# Şüpheli bir uzak IP’ye bağlantı tespit edildi.

# Alanlar:
# - type: "CONNECTION_SUSPICIOUS_REMOTE"
# - timestamp
# - pid
# - process_name
# - raddr_ip
# - raddr_port
# - reason  (ör: "blacklisted_ip", "malware_c2", "unknown_country")


# -----------------------------------------
# NET_INTERFACE_STATS
# -----------------------------------------
# Per-interface trafik snapshot’ı.
# Bu bir "EVENT" değil, STATE snapshot’tır (Metrics gibi).

# Alanlar:
# - type: "NET_INTERFACE_STATS"
# - timestamp
# - iface
# - bytes_sent
# - bytes_recv
# - packets_sent
# - packets_recv
# - errin
# - errout
# - dropin
# - dropout


# -----------------------------------------
# NET_SNAPSHOT
# -----------------------------------------
# Collector’ın periyodik tam snapshot’ı.
# This is STATE, event değil.

# Alanlar:
# - type: "NET_SNAPSHOT"
# - timestamp
# - interfaces:   {...}
# - connections:  [...]


# -----------------------------------------
# CONNECTION_UNUSUAL_PORT
# -----------------------------------------
# İlginç/alışılmadık bir porta outbound bağlantı oluştu (ör: 6667 IRC, 23 Telnet)

# Alanlar:
# - type: "CONNECTION_UNUSUAL_PORT"
# - timestamp
# - pid
# - process_name
# - raddr_ip
# - raddr_port
# - description  ("rare outbound port")


# -----------------------------------------
# CONNECTION_PORT_SCAN_OUTBOUND
# -----------------------------------------
# Aynı hedef IP’ye çok sayıda kısa ömürlü port denemesi yapıldı (port scan belirtisi)

# Alanlar:
# - type: "CONNECTION_PORT_SCAN_OUTBOUND"
# - timestamp
# - pid
# - process_name
# - target_ip
# - ports_tried  (list)


# -----------------------------------------
# CONNECTION_PORT_SCAN_INBOUND
# -----------------------------------------
# Sisteme inbound port scan geldi (bir IP çok fazla port denemiş)

# Alanlar:
# - type: "CONNECTION_PORT_SCAN_INBOUND"
# - timestamp
# - source_ip
# - ports_tried (list)

# ########################## tüm event tipleri,

# ✔ Event-Based

# NET_NEW_CONNECTION
# NET_CLOSED_CONNECTION
# NET_NEW_LISTEN_PORT
# NET_CLOSED_LISTEN_PORT
# CONNECTION_SUSPICIOUS_REMOTE
# CONNECTION_UNUSUAL_PORT
# CONNECTION_PORT_SCAN_OUTBOUND
# CONNECTION_PORT_SCAN_INBOUND

# ✔ State-Based

# NET_SNAPSHOT
# NET_INTERFACE_STATS
