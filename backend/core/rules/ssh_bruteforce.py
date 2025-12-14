from typing import Dict, Any, List, Tuple

from backend.core.rules.base import StatefulRule
from backend.logger import logger


class SSHBruteforceRule(StatefulRule):
    """
    AUTH_001 – SSH Bruteforce Detection

    Detects multiple FAILED_LOGIN events
    from the same IP against the same user
    within a short time window.
    """

    rule_id = "AUTH_001"
    description = "SSH brute force attack detected"
    severity = "HIGH"

    event_prefix = "FAILED_LOGIN"

    window_seconds = 60
    threshold = 5

    # --------------------------------------------------
    # HELPERS
    # --------------------------------------------------
    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        return (
            event.get("type") == "LOG_EVENT"
            and event.get("category") == "AUTH"
            and event.get("event_type") == "FAILED_LOGIN"
            and event.get("ip")
            and event.get("user")
        )

    def _build_key(self, event: Dict[str, Any]) -> Tuple[str, str]:
        return event["ip"], event["user"]

    def _build_event_ref(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "ip": event["ip"],
            "user": event["user"],
        }

    # --------------------------------------------------
    # STATEFUL API
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

        logger.debug(
            f"[SSH_BRUTE][CONSUME] ip={key[0]} user={key[1]}"
        )

    def evaluate(self, context) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []

        bucket = context._store.get(self.rule_id)
        if not bucket:
            return alerts

        for (ip, user), events in list(bucket.items()):
            count = len(events)

            if count == self.threshold - 1:
                logger.debug(
                    f"[SSH_BRUTE][NEAR_THRESHOLD] ip={ip} user={user} "
                    f"{count}/{self.threshold}"
                )

            if count < self.threshold:
                continue

            logger.info(
                f"[SSH_BRUTE][TRIGGER] ip={ip} user={user} count={count}"
            )

            alerts.append(
                self.build_alert_base(
                    alert_type="ALERT_SSH_BRUTEFORCE",
                    message=(
                        f"SSH brute force detected from {ip} "
                        f"against user '{user}' "
                        f"({count} failed attempts in {self.window_seconds}s)"
                    ),
                    related_events=list(events),
                    extra={
                        "ip": ip,
                        "user": user,
                        "attempts": count,
                    },
                )
            )

            context.clear_key(rule_id=self.rule_id, key=(ip, user))
            logger.debug(
                f"[SSH_BRUTE][STATE_CLEARED] ip={ip} user={user}"
            )

        return alerts
