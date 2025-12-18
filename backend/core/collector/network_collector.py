# backend/core/collector/network_collector.py

import json
import os
import time
import socket
import psutil
from backend.logger import logger


class NetworkCollector:

    def __init__(self, state_file="/var/lib/hids/network_state.json"):
        self.state_file = state_file
        logger.info(f"[NetworkCollector] Initialized with state file: {state_file}")

    def step(self):
        logger.debug("[NetworkCollector] step() invoked — loading previous state")
        prev = self._load_previous_state()

        curr = self._build_snapshot()
        ts = curr["timestamp"]

        # 🔍 DEBUG: snapshot boyutu
        logger.debug(
            f"[NETDEBUG] prev_connections={len(prev.get('connections', []))}, "
            f"curr_connections={len(curr.get('connections', []))}"
        )

        events = []

        # logger.debug("[NetworkCollector] Building NET_SNAPSHOT event")
        # events.append({
        #     "type": "NET_SNAPSHOT",
        #     "timestamp": ts,
        #     "interfaces": curr["interfaces"],
        #     "connections": curr["connections"]
        # })

        # for iface, stats in curr["interfaces"].items():
        #     events.append({
        #         "type": "NET_INTERFACE_STATS",
        #         "timestamp": ts,
        #         "iface": iface,
        #         **stats
        #     })

        logger.debug("[NetworkCollector] Performing diff for connection events")
        diff_events = self._diff_connection_events(
            prev.get("connections", []),
            curr.get("connections", []),
            ts
        )
        events.extend(diff_events)

        logger.info(
            f"[NetworkCollector] step() produced {len(events)} events "
            f"({len(diff_events)} diff-events)"
        )

        self._save_state(curr)
        return events

    # ============================================================
    # SNAPSHOT BUILD
    # ============================================================
    def _build_snapshot(self):
        ts = time.time()
        logger.debug("[NetworkCollector] Collecting snapshot: interfaces + connections")

        return {
            "timestamp": ts,
            "interfaces": self._collect_interface_io(),
            "connections": self._collect_connections()
        }

    def _collect_interface_io(self):
        logger.debug("[NetworkCollector] Collecting per-interface IO stats")
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
                "dropout": c.dropout
            }

        logger.debug(f"[NetworkCollector] IO snapshot collected for {len(out)} interfaces")
        return out

    def _collect_connections(self):
        logger.debug("[NetworkCollector] Collecting active inet connections")
        conns = psutil.net_connections(kind="inet")
        out = []

        for c in conns:
            l_ip = getattr(c.laddr, "ip", None) if c.laddr else None
            l_port = getattr(c.laddr, "port", None) if c.laddr else None
            r_ip = getattr(c.raddr, "ip", None) if c.raddr else None
            r_port = getattr(c.raddr, "port", None) if c.raddr else None

            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"

            try:
                pname = psutil.Process(c.pid).name() if c.pid else "unknown"
            except Exception:
                pname = "unknown"

            is_listen = (
                (c.status == psutil.CONN_LISTEN) or
                (c.type == socket.SOCK_DGRAM and not r_ip)
            )

            out.append({
                "pid": c.pid,
                "process_name": pname,
                "protocol": proto,
                "laddr_ip": l_ip,
                "laddr_port": l_port,
                "raddr_ip": r_ip,
                "raddr_port": r_port,
                "status": c.status,
                "is_listen": is_listen,
            })

        logger.debug(f"[NetworkCollector] Detected {len(out)} inet connections")
        return out

    # ============================================================
    # DIFF ENGINE
    # ============================================================
    def _diff_connection_events(self, prev, curr, ts):
        logger.debug("[NetworkCollector] Starting diff-engine")

        events = []

        def key(c):
            return (
                c.get("pid"),
                c.get("laddr_ip"),
                c.get("laddr_port"),
                c.get("raddr_ip"),
                c.get("raddr_port"),
                c.get("protocol"),
            )

        prev_map = {key(c): c for c in prev}
        curr_map = {key(c): c for c in curr}

        prev_keys = set(prev_map.keys())
        curr_keys = set(curr_map.keys())

        # 🔍 DEBUG: diff summary
        logger.debug(
            f"[NETDEBUG][DIFF] prev={len(prev)}, curr={len(curr)} | "
            f"prev_keys={len(prev_keys)}, curr_keys={len(curr_keys)}"
        )

        # ================================
        # NEW CONNECTIONS
        # ================================
        for k in curr_keys - prev_keys:
            c = curr_map[k]

            # IGNORE TIME_WAIT
            if c.get("status") == "TIME_WAIT":
                # logger.debug(f"[NETIGNORE] Ignoring TIME_WAIT connection: {c}")
                continue

            # IGNORE 127.0.0.1 to 127.0.0.1:5000 (internal agent traffic)
            if c.get("laddr_port") == 5000 and c.get("laddr_ip") in {"127.0.0.1", "0.0.0.0"}:
                # logger.debug(f"[NETIGNORE] Ignoring internal agent traffic: {c}")
                continue

            if c["is_listen"]:
                events.append({
                    "type": "NET_NEW_LISTEN_PORT",
                    "timestamp": ts,
                    **c
                })
                logger.info(f"[NetworkCollector] New LISTEN port opened: {c.get('laddr_port')}")

            elif c["raddr_ip"]:
                logger.debug(
                    f"[NETDEBUG][NEW] pid={c.get('pid')} "
                    f"{c.get('laddr_ip')}:{c.get('laddr_port')} -> "
                    f"{c.get('raddr_ip')}:{c.get('raddr_port')}"
                )

                events.append({
                    "type": "NET_NEW_CONNECTION",
                    "timestamp": ts,
                    **c
                })

        # ================================
        # CLOSED CONNECTIONS
        # ================================
        for k in prev_keys - curr_keys:
            c = prev_map[k]

            # IGNORE TIME_WAIT
            if c.get("status") == "TIME_WAIT":
                # logger.debug(f"[NETIGNORE] Ignoring TIME_WAIT connection: {c}")
                continue

            # IGNORE AGENT LOOPBACK TRAFFIC ON PORT 5000
            if c.get("laddr_port") == 5000 and c.get("laddr_ip") in {"127.0.0.1", "0.0.0.0"}:
                # logger.debug(f"[NETIGNORE] Ignoring internal agent traffic: {c}")
                continue

            if c["is_listen"]:
                events.append({
                    "type": "NET_CLOSED_LISTEN_PORT",
                    "timestamp": ts,
                    **c
                })
                logger.info(f"[NetworkCollector] LISTEN port closed: {c.get('laddr_port')}")

            elif c["raddr_ip"]:
                logger.debug(
                    f"[NETDEBUG][CLOSED] pid={c.get('pid')} "
                    f"{c.get('laddr_ip')}:{c.get('laddr_port')} -> "
                    f"{c.get('raddr_ip')}:{c.get('raddr_port')}"
                )

                events.append({
                    "type": "NET_CLOSED_CONNECTION",
                    "timestamp": ts,
                    **c
                })

        logger.debug(
            f"[NETDEBUG][DIFF] produced={len(events)} | "
            f"new={len([e for e in events if e['type']=='NET_NEW_CONNECTION'])}, "
            f"closed={len([e for e in events if e['type']=='NET_CLOSED_CONNECTION'])}, "
            f"listen_new={len([e for e in events if e['type']=='NET_NEW_LISTEN_PORT'])}, "
            f"listen_closed={len([e for e in events if e['type']=='NET_CLOSED_LISTEN_PORT'])}"
        )

        return events

    # ============================================================
    # STATE PERSISTENCE
    # ============================================================
    def _load_previous_state(self):
        if not os.path.exists(self.state_file):
            logger.warning("[NetworkCollector] No state file found; starting fresh")
            return {"connections": []}
        try:
            with open(self.state_file, "r") as f:
                state = json.load(f)
                logger.debug("[NetworkCollector] Loaded previous state")
                return state
        except Exception as e:
            logger.error(f"[NetworkCollector] Failed to load previous state: {e}")
            return {"connections": []}

    def _save_state(self, snap):
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, "w") as f:
                json.dump(snap, f)

            logger.debug(
                f"[NETDEBUG] State saved: {self.state_file} | "
                f"connections={len(snap.get('connections', []))}"
            )

        except Exception as e:
            logger.error(f"[NetworkCollector] Failed to save state: {e}")
            pass
        
    # TEST
    if __name__ == "__main__":
        nc = NetworkCollector()
        events = nc.step()

        print("\n===== NETWORK COLLECTOR TEST OUTPUT =====\n")
        for e in events:
            print(json.dumps(e, indent=2))
            print("-" * 60)
