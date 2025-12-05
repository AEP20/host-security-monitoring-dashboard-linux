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
# backend/core/collector/network_collector.py

import json
import os
import time
import socket
import psutil


class NetworkCollector:
    """
    Network snapshot + diff → event üretir.
    - Interface I/O (STATE)
    - Connection listesi (STATE)
    - Yeni bağlantı, kapanan bağlantı (EVENT)
    - Yeni/kapalı LISTEN port (EVENT)
    """
    def __init__(self, state_file="/var/lib/hids/network_state.json"):
        self.state_file = state_file

    # Scheduler bu fonksiyonu çağırır
    def step(self):
        prev = self._load_previous_state()
        curr = self._build_snapshot()

        events = []

        # STATE: tüm snapshot
        events.append({
            "type": "NET_SNAPSHOT",
            "timestamp": curr["timestamp"],
            "interfaces": curr["interfaces"],
            "connections": curr["connections"],
        })

        # STATE: interface I/O per interface
        for iface, stats in curr["interfaces"].items():
            events.append({
                "type": "NET_INTERFACE_STATS",
                "timestamp": curr["timestamp"],
                "iface": iface,
                **stats
            })

        # EVENT: diff
        events.extend(
            self._diff_connection_events(
                prev.get("connections", []),
                curr.get("connections", []),
                curr["timestamp"]
            )
        )

        self._save_state(curr)
        return events

    # ==============================
    # SNAPSHOT TOPLAYICILAR
    # ==============================
    def _build_snapshot(self):
        return {
            "timestamp": time.time(),
            "interfaces": self._collect_interface_io(),
            "connections": self._collect_connections(),
        }

    def _collect_interface_io(self):
        counters = psutil.net_io_counters(pernic=True)
        out = {}
        for iface, c in counters.items():
            out[iface] = {
                "bytes_sent": c.bytes_sent,
                "bytes_recv": c.bytes_recv,
                "packets_sent": c.packets_sent,
                "packets_recv": c.packets_recv,
                "errin": c.errin,
                "errout": c.errout,
                "dropin": c.dropin,
                "dropout": c.dropout,
            }
        return out

    def _collect_connections(self):
        conns = psutil.net_connections(kind="inet")
        out = []

        for c in conns:
            l_ip = getattr(c.laddr, "ip", None) if c.laddr else None
            l_port = getattr(c.laddr, "port", None) if c.laddr else None
            r_ip = getattr(c.raddr, "ip", None) if c.raddr else None
            r_port = getattr(c.raddr, "port", None) if c.raddr else None

            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"

            try:
                pname = psutil.Process(c.pid).name() if c.pid else None
            except Exception:
                pname = None

            out.append({
                "pid": c.pid,
                "process_name": pname,
                "protocol": proto,
                "laddr_ip": l_ip,
                "laddr_port": l_port,
                "raddr_ip": r_ip,
                "raddr_port": r_port,
                "status": c.status,
                "is_listen": (c.status == psutil.CONN_LISTEN),
            })

        return out

    # ==============================
    # DIFF → NET_* EVENT ÜRETİCİ
    # ==============================
    def _diff_connection_events(self, prev, curr, ts):
        events = []

        def key(c):
            return (
                c.get("pid"),
                c.get("laddr_ip"),
                c.get("laddr_port"),
                c.get("raddr_ip"),
                c.get("raddr_port"),
                c.get("status"),
                c.get("protocol"),
            )

        prev_map = {key(c): c for c in prev}
        curr_map = {key(c): c for c in curr}

        prev_keys = set(prev_map.keys())
        curr_keys = set(curr_map.keys())

        # Yeni gelen connections
        for k in curr_keys - prev_keys:
            c = curr_map[k]

            if c["is_listen"]:
                events.append({
                    "type": "NET_NEW_LISTEN_PORT",
                    "timestamp": ts,
                    "pid": c["pid"],
                    "process_name": c["process_name"],
                    "laddr_ip": c["laddr_ip"],
                    "laddr_port": c["laddr_port"],
                    "protocol": c["protocol"],
                })
            elif c["raddr_ip"]:
                events.append({
                    "type": "NET_NEW_CONNECTION",
                    "timestamp": ts,
                    **c
                })

        # Kapanan connections
        for k in prev_keys - curr_keys:
            c = prev_map[k]

            if c["is_listen"]:
                events.append({
                    "type": "NET_CLOSED_LISTEN_PORT",
                    "timestamp": ts,
                    "pid": c["pid"],
                    "process_name": c["process_name"],
                    "laddr_ip": c["laddr_ip"],
                    "laddr_port": c["laddr_port"],
                    "protocol": c["protocol"],
                })
            elif c["raddr_ip"]:
                events.append({
                    "type": "NET_CLOSED_CONNECTION",
                    "timestamp": ts,
                    **c
                })

        return events

    # ==============================
    # STATE CACHE
    # ==============================
    def _load_previous_state(self):
        if not os.path.exists(self.state_file):
            return {"connections": []}

        try:
            with open(self.state_file, "r") as f:
                return json.load(f)
        except:
            return {"connections": []}

    def _save_state(self, snap):
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        try:
            with open(self.state_file, "w") as f:
                json.dump(snap, f)
        except:
            pass


# Test
if __name__ == "__main__":
    nc = NetworkCollector()
    ev = nc.step()
    for e in ev:
        print(e)
