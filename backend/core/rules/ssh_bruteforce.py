from typing import Dict, Any, List
from backend.core.rules.base import StatefulRule
from backend.logger import logger


class SSHBruteforceRule(StatefulRule):
    rule_id = "AUTH_001"
    description = "SSH brute force attack detected"
    severity = "HIGH"
    event_prefix = "LOG_"

    window_seconds = 60
    threshold = 5

    # --------------------------------------------------
    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        return (
            event.get("type") == "LOG_EVENT"
            and event.get("category") == "AUTH"
            and event.get("event_type") in ("FAILED_LOGIN", "FAILED_AUTH")
            and event.get("ip")            # saldırgan tanımı
            and event.get("timestamp")
        )

    def _build_key(self, event: Dict[str, Any]) -> str:
        # brute force IP bazlıdır
        return event["ip"]

    def _build_event_ref(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": event["timestamp"],
            "count": 1,  # parser'a dokunmadan minimum anlam
            "user": event.get("user"),
        }

    # --------------------------------------------------
    def consume(self, event: Dict[str, Any], context) -> None:
        if not self._is_relevant(event):
            return

        key = self._build_key(event)

        context.add(
            rule_id=self.rule_id,
            key=key,
            event=self._build_event_ref(event),
            window_seconds=self.window_seconds,
        )

        logger.debug(f"[SSH_BRUTE][CONSUME] ip={key}")

    # --------------------------------------------------
    def evaluate(self, context) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        bucket = context._store.get(self.rule_id)

        if not bucket:
            return results

        for ip, events in list(bucket.items()):
            total_failures = sum(e.get("count", 1) for e in events)

            if total_failures < self.threshold:
                continue

            timestamps = [e["timestamp"] for e in events]
            users = {e.get("user") for e in events if e.get("user")}

            time_from = min(timestamps)
            time_to = max(timestamps)

            user_info = ", ".join(users) if users else "multiple/unknown users"

            alert = self.build_alert_base(
                alert_type="ALERT_SSH_BRUTEFORCE",
                message=(
                    f"SSH brute force detected from {ip} "
                    f"targeting {user_info} "
                    f"({total_failures} failed attempts in {self.window_seconds}s)"
                ),
                extra={
                    "evidence_resolve": {
                        "source": "log_events",
                        "filters": {
                            "category": "AUTH",
                            "event_types": ["FAILED_LOGIN", "FAILED_AUTH"],
                            "ip": ip,
                        },
                        "time_range": {
                            "from": time_from,
                            "to": time_to,
                        },
                        "limit": 20,
                        "order": "asc",
                    }
                },
            )

            results.append({"alert": alert, "evidence": []})
            context.clear_key(self.rule_id, ip)

        return results
