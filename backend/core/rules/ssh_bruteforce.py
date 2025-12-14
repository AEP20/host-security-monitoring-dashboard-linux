from typing import Dict, Any, List, Tuple

from backend.core.rules.base import StatefulRule
from backend.logger import logger


class SSHBruteforceRule(StatefulRule):
    """
    AUTH_001 – SSH Bruteforce Detection

    Detects multiple FAILED_LOGIN auth log events
    from the same IP against the same user
    within a short time window.
    """

    rule_id = "AUTH_001"
    description = "SSH brute force attack detected"
    severity = "HIGH"

    # RuleEngine supports() için:
    # event_type üzerinden çalışıyoruz
    event_prefix = "FAILED_"

    # correlation config
    window_seconds = 60
    threshold = 5

    # --------------------------------------------------
    # HELPERS
    # --------------------------------------------------
    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        """
        Bu rule SADECE:
        - LOG_EVENT
        - AUTH kategorisi
        - FAILED_LOGIN event_type
        için çalışır
        """
        return (
            event.get("type") == "LOG_EVENT"
            and event.get("category") == "AUTH"
            and event.get("event_type") == "FAILED_LOGIN"
            and event.get("ip") is not None
            and event.get("user") is not None
        )

    def _build_key(self, event: Dict[str, Any]) -> Tuple[str, str]:
        """
        Korelasyon anahtarı:
        aynı IP + aynı user
        """
        return (
            event.get("ip"),
            event.get("user"),
        )

    def _build_event_ref(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        RAM'de tutulacak minimal event referansı
        """
        return {
            "event_type": event.get("event_type"),
            "timestamp": event.get("timestamp"),
            "ip": event.get("ip"),
            "user": event.get("user"),
        }

    # --------------------------------------------------
    # STATEFUL API
    # --------------------------------------------------
    def consume(self, event: Dict[str, Any], context) -> None:
        if not self._is_relevant(event):
            return

        key = self._build_key(event)
        event_ref = self._build_event_ref(event)

        context.add(
            rule_id=self.rule_id,
            key=key,
            event=event_ref,
            window_seconds=self.window_seconds,
        )

        logger.debug(
            f"[SSH_BRUTE] Consumed FAILED_LOGIN ip={key[0]} user={key[1]}"
        )

    def evaluate(self, context) -> List[Dict[str, Any]]:
        """
        Her consume sonrası çağrılır.
        Threshold aşılırsa alert üretir.
        """
        alerts: List[Dict[str, Any]] = []

        rule_bucket = context._store.get(self.rule_id, {})
        if not rule_bucket:
            return alerts

        for key, events in list(rule_bucket.items()):
            count = len(events)

            if count < self.threshold:
                continue

            ip, user = key

            alert = self.build_alert_base(
                alert_type="ALERT_SSH_BRUTEFORCE",
                message=(
                    f"SSH brute force detected from {ip} "
                    f"against user '{user}' "
                    f"({count} failed login attempts in {self.window_seconds}s)"
                ),
                related_events=list(events),
                extra={
                    "ip": ip,
                    "user": user,
                    "attempts": count,
                },
            )

            alerts.append(alert)

            # Alert üretildikten sonra state temizlenir
            # (alert spam ve RAM şişmesini önler)
            context.clear_key(rule_id=self.rule_id, key=key)

            logger.info(
                f"[SSH_BRUTE] Alert generated ip={ip} user={user}"
            )

        return alerts
