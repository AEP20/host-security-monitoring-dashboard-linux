from typing import Dict, Any, List, Tuple

from backend.core.rules.base import StatefulRule
from backend.logger import logger


class SSHBruteforceRule(StatefulRule):
    """
    AUTH_001 – SSH Bruteforce Detection

    Stateful rule örneği:
    - Birden fazla FAILED_LOGIN event'i toplar
    - Eşik aşılınca TEK bir alert üretir
    - Alert'i besleyen event'leri EVIDENCE olarak döner
    """

    rule_id = "AUTH_001"
    description = "SSH brute force attack detected"
    severity = "HIGH"

    # RuleEngine.supports() bu prefix ile filtreler
    event_prefix = "FAILED_LOGIN"

    window_seconds = 60
    threshold = 5

    # --------------------------------------------------
    # HELPERS
    # --------------------------------------------------
    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        """
        Bu rule için hangi event'ler anlamlı?
        → Sadece AUTH / FAILED_LOGIN
        """
        return (
            event.get("type") == "LOG_EVENT"
            and event.get("category") == "AUTH"
            and event.get("event_type") == "FAILED_LOGIN"
            and event.get("ip")
            and event.get("user")
        )

    def _build_key(self, event: Dict[str, Any]) -> Tuple[str, str]:
        """
        Correlation scope:
        - Aynı IP
        - Aynı user
        """
        return event["ip"], event["user"]

    def _build_event_ref(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Context'e koyacağımız MINIMAL event referansı.

        ⚠️ DİKKAT:
        - Burada event'in TAM HALİ yok
        - Sadece alert üretmek için gereken bilgiler var
        - DB'ye yazılan şey bu DEĞİL
        """
        return {
            "event_id": event.get("id"),          # DB’deki log_event id
            "event_type": "LOG_EVENT",            # Evidence için generic type
            "timestamp": event.get("timestamp"),  # window hesabı için
        }

    # --------------------------------------------------
    # STATEFUL API
    # --------------------------------------------------
    def consume(self, event: Dict[str, Any], context) -> None:
        """
        Her event geldiğinde çalışır.

        Görevi:
        - Event'i context içine eklemek
        - Henüz alert üretmemek
        """
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
        """
        Context'e bakarak:
        - Alert üretilecek mi?
        - Üretilecekse hangi event'ler evidence olacak?
        """
        results: List[Dict[str, Any]] = []

        bucket = context._store.get(self.rule_id)
        if not bucket:
            return results

        for (ip, user), events in list(bucket.items()):
            count = len(events)

            if count < self.threshold:
                continue

            logger.info(
                f"[SSH_BRUTE][TRIGGER] ip={ip} user={user} count={count}"
            )

            # -------------------------------
            # 1️⃣ ALERT PAYLOAD
            # -------------------------------
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
                },
            )

            # -------------------------------
            # 2️⃣ EVIDENCE OLUŞTURMA
            # -------------------------------
            # Buradaki event'ler:
            # - context'te toplanmış FAILED_LOGIN'lar
            # - Alert'i BESLEYEN kanıtlar
            evidence: List[Dict[str, Any]] = []

            for idx, ev in enumerate(events):
                evidence.append({
                    "event_type": ev["event_type"],   # LOG_EVENT
                    "event_id": ev["event_id"],       # log_events.id
                    "role": "SUPPORT",                # brute force'i destekleyen denemeler
                    "sequence": idx + 1,              # alert içi sıralama
                })

            # İstersen:
            # - son event'i TRIGGER yapabilirsin
            if evidence:
                evidence[-1]["role"] = "TRIGGER"

            results.append({
                "alert": alert,
                "evidence": evidence,
            })

            # -------------------------------
            # 3️⃣ STATE TEMİZLE
            # -------------------------------
            # Aynı IP+user için tekrar tekrar alert üretmemek için
            context.clear_key(rule_id=self.rule_id, key=(ip, user))

            logger.debug(
                f"[SSH_BRUTE][STATE_CLEARED] ip={ip} user={user}"
            )

        return results
