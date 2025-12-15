from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone

from backend.core.rules.base import StatefulRule
from backend.logger import logger


class SSHBruteforceRule(StatefulRule):
    """
    AUTH_001 – SSH Bruteforce Detection (Stateful)

    - Context'e event_id değil, sadece timestamp (window hesabı için) koyuyoruz.
    - Alert üretildiğinde evidence listesini boş bırakıyoruz.
    - Evidence'ı DBWriter, alert.extra içindeki ip/user/window_seconds bilgisiyle
      log_events tablosundan resolve edip yazacak.
    """

    rule_id = "AUTH_001"
    description = "SSH brute force attack detected"
    severity = "HIGH"

    event_prefix = "FAILED_LOGIN"

    window_seconds = 60
    threshold = 5

    # --------------------------------------------------
    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        return (
            event.get("type") == "LOG_EVENT"
            and event.get("category") == "AUTH"
            and event.get("event_type") == "FAILED_LOGIN"
            and event.get("ip")
            and event.get("user")
            and event.get("timestamp")
        )

    def _build_key(self, event: Dict[str, Any]) -> Tuple[str, str]:
        return event["ip"], event["user"]

    def _build_event_ref(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Context'e koyduğumuz minimal ref:
        - id yok (çünkü daha DB’ye yazılmadı)
        - sadece timestamp: window pruning için yeterli
        """
        return {
            "id": None,  # intentionally None
            "event_type": "LOG_EVENT",
            "timestamp": event.get("timestamp"),
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

            # Alert timestamp'ı DB tarafında default current_time ile set ediliyor.
            # DBWriter evidence resolve ederken: [alert_timestamp - window_seconds, alert_timestamp]
            # aralığından ip+user için FAILED_LOGIN arayacak.
            alert = self.build_alert_base(
                alert_type="ALERT_SSH_BRUTEFORCE",
                message=(
                    f"SSH brute force detected from {ip} "
                    f"against user '{user}' "
                    f"({count} failed attempts in {self.window_seconds}s)"
                ),
                extra={
                    "ip": ip,
                    "user": user,
                    "attempts": count,
                    "window_seconds": self.window_seconds,
                    "evidence_resolve": {
                        "source": "log_events",
                        "event_type": "FAILED_LOGIN",
                        "category": "AUTH",
                    },
                },
            )

            # Evidence'ı burada üretmiyoruz.
            # DBWriter alert'i yazdıktan sonra log_events'den event_id'leri resolve edecek.
            results.append({"alert": alert, "evidence": []})

            context.clear_key(rule_id=self.rule_id, key=(ip, user))
            logger.debug(f"[SSH_BRUTE][STATE_CLEARED] ip={ip} user={user}")

        return results
