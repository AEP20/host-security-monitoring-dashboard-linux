from typing import Dict, Any, List
from backend.core.rules.base import StatefulRule
from backend.logger import logger


class SSHBruteforceRule(StatefulRule):
    rule_id = "AUTH_001"
    description = "SSH brute force attack detected"
    severity = "HIGH"

    window_seconds = 60
    threshold = 3

    # --------------------------------------------------
    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        return (
            event.get("type") == "LOG_EVENT"
            and event.get("category") == "AUTH"
            and event.get("event_type") in ("FAILED_LOGIN", "FAILED_AUTH")
            and event.get("ip")
            and event.get("timestamp")
        )

    def _build_key(self, event: Dict[str, Any]) -> tuple:
        return (event["ip"],)

    # --------------------------------------------------
    def consume(self, event: Dict[str, Any], context) -> None:
        if not self._is_relevant(event):
            return

        key = self._build_key(event)

        context.add(
            rule_id=self.rule_id,
            key=key,
            event=event,
            window_seconds=self.window_seconds,
        )

        logger.debug(f"[SSH_BRUTE][CONSUME] ip={key[0]}")

    # --------------------------------------------------
    def evaluate(self, context) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        rule_bucket = context._store.get(self.rule_id)
        if not rule_bucket:
            return results

        for key in list(rule_bucket.keys()):
            events = context.get(
                rule_id=self.rule_id,
                key=key,
                window_seconds=self.window_seconds,
            )

            if len(events) < self.threshold:
                continue

            ip = key[0]
            timestamps = [e["ts"] for e in events]

            alert = self.build_alert_base(
                alert_type="ALERT_SSH_BRUTEFORCE",
                message=(
                    f"SSH brute force detected from {ip} "
                    f"({len(events)} failed attempts in {self.window_seconds}s)"
                ),
                extra={
                    "evidence_resolve": {
                        "source": "log_events",
                        "filters": {
                            "category": "AUTH",
                            "event_type__in": ["FAILED_LOGIN", "FAILED_AUTH"],
                            "ip_address": ip,
                        },
                        "time_range": {
                            "from": min(timestamps),
                            "to": max(timestamps),
                        },
                        "limit": 20,
                        "order": "asc",
                    }
                },
            )

            results.append({
                "alert": alert,
                "evidence": [],
            })

            context.clear_key(rule_id=self.rule_id, key=key)

        return results
