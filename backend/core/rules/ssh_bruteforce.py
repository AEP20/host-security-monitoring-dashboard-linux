from typing import Dict, Any, List, Tuple
from backend.core.rules.base import StatefulRule
from backend.logger import logger


class SSHBruteforceRule(StatefulRule):
    """
    AUTH_001 – SSH Bruteforce Detection (Stateful)

    Evidence RULE içinde üretilir.
    DBWriter resolve yapmaz.
    """

    rule_id = "AUTH_001"
    description = "SSH brute force attack detected"
    severity = "HIGH"

    window_seconds = 60
    threshold = 5

    event_prefix = "LOG_"

    # --------------------------------------------------
    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        return (
            event.get("type") == "LOG_EVENT"
            and event.get("category") == "AUTH"
            and event.get("event_type") in ("FAILED_LOGIN", "FAILED_AUTH")
            and event.get("ip")
            and event.get("timestamp")
        )

    def _build_key(self, event: Dict[str, Any]) -> Tuple[str, str]:
        return event["ip"], event.get("user") or "UNKNOWN"

    def _build_event_ref(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Context’e koyacağımız event snapshot.
        DB id yok → problem değil.
        """
        return {
            "event_type": "LOG_EVENT",
            "timestamp": event.get("timestamp"),
            "ip": event.get("ip"),
            "user": event.get("user"),
            "message": event.get("message"),
            "log_source": event.get("log_source"),
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

        logger.debug(f"[SSH_BRUTE][CONSUME] ip={key[0]} user={key[1]}")

    def evaluate(self, context) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        bucket = context._store.get(self.rule_id)
        if not bucket:
            return results

        for (ip, user), events in list(bucket.items()):
            count = len(events)
            if count < self.threshold:
                continue

            logger.info(f"[SSH_BRUTE][TRIGGER] ip={ip} user={user} count={count}")

            # -------------------------------
            # EVIDENCE BURADA ÜRETİLİR
            # -------------------------------
            related_events: List[Dict[str, Any]] = []

            for idx, ev in enumerate(events):
                related_events.append({
                    "event_type": "LOG_EVENT",
                    "role": "SUPPORT",
                    "sequence": idx + 1,
                    "timestamp": ev.get("timestamp"),
                    "ip": ev.get("ip"),
                    "user": ev.get("user"),
                    "message": ev.get("message"),
                    "log_source": ev.get("log_source"),
                })

            # Son event TRIGGER
            if related_events:
                related_events[-1]["role"] = "TRIGGER"

            # -------------------------------
            # ALERT
            # -------------------------------
            alert = self.build_alert_base(
                alert_type="ALERT_SSH_BRUTEFORCE",
                message=(
                    f"SSH brute force detected from {ip} "
                    f"against user '{user}' "
                    f"({count} failed attempts in {self.window_seconds}s)"
                ),
                related_events=related_events, 
                extra={
                    "ip": ip,
                    "user": user if user != "UNKNOWN" else None,
                    "attempts": count,
                    "window_seconds": self.window_seconds,
                },
            )

            results.append({
                "alert": alert,
                "evidence": [],
            })

            context.clear_key(rule_id=self.rule_id, key=(ip, user))
            logger.debug(f"[SSH_BRUTE][STATE_CLEARED] ip={ip} user={user}")

        return results
