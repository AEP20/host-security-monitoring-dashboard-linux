from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseRule(ABC):
    """
    Ortak metadata + yardımcı fonksiyonlar.
    """
    rule_id: str
    description: str
    severity: str
    event_prefix: str  # PROCESS_, NET_, LOG_, etc.
    enabled: bool = True

    def supports(self, event_type: str) -> bool:
        if not self.enabled:
            return False
        if not event_type:
            return False
        return event_type.startswith(self.event_prefix)

    def build_alert_base(
        self,
        *,
        alert_type: str,
        message: str,
        log_event_id: Optional[int] = None,
        related_events: Optional[List[Dict[str, Any]]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        alert = {
            "type": alert_type,
            "rule_name": self.rule_id,
            "severity": self.severity,
            "message": message,
            "log_event_id": log_event_id,
        }
        if related_events:
            alert["related_events"] = related_events
        if extra:
            alert["extra"] = extra
        return alert

    # --- YENİ HELPER ---
    def build_evidence_spec(self, source: str, filters: Dict[str, Any], limit: int = 20):
        """
        Boilerplate JSON yazımını engeller. 
        DBWriter'daki buffer mantığı sayesinde time_range eklemeye gerek kalmaz.
        """
        return {
            "evidence_resolve": {
                "source": source,
                "filters": filters,
                "limit": limit
            }
        }


# =========================================================
# STATELESS RULE (Basitleştirilmiş)
# =========================================================
class StatelessRule(BaseRule, ABC):
    @abstractmethod
    def match(self, event: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def build_alert(self, event: Dict[str, Any]) -> Dict[str, Any]:
        pass

    def build_evidence(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [{
            "event_type": event.get("type"),
            "event_id": event.get("id"),
            "role": "TRIGGER",
            "sequence": 1,
        }]


# =========================================================
# STATEFUL RULE (Ham/Generic)
# =========================================================
class StatefulRule(BaseRule, ABC):
    window_seconds: int = 300

    @abstractmethod
    def consume(self, event: Dict[str, Any], context: Any) -> None:
        pass

    @abstractmethod
    def evaluate(self, context: Any) -> List[Dict[str, Any]]:
        pass


# =========================================================
# PATTERN: THRESHOLD RULE (Yeni Akıllı Sınıf)
# =========================================================
class ThresholdRule(StatefulRule, ABC):
    """
    'X olayı Y sürede Z kadar olursa' mantığını tamamen encapsulate eder.
    """
    threshold: int = 3
    window_seconds: int = 60

    @abstractmethod
    def is_relevant(self, event: Dict[str, Any]) -> bool:
        """Olay bu kuralı ilgilendiriyor mu? (Örn: FAILED_LOGIN mi?)"""
        pass

    @abstractmethod
    def get_key(self, event: Dict[str, Any]) -> tuple:
        """Gruplama anahtarı ne? (Örn: IP adresi mi?)"""
        pass

    @abstractmethod
    def create_alert(self, key: tuple, events: List[Any]) -> Dict[str, Any]:
        """Eşik aşıldığında üretilecek alert payload'u."""
        pass

    def consume(self, event: Dict[str, Any], context: Any) -> None:
        if not self.is_relevant(event):
            return

        key = self.get_key(event)
        context.add(
            rule_id=self.rule_id,
            key=key,
            event=event,
            window_seconds=self.window_seconds,
        )

    def evaluate(self, context: Any) -> List[Dict[str, Any]]:
        results = []
        rule_bucket = context._store.get(self.rule_id)
        if not rule_bucket:
            return results

        for key in list(rule_bucket.keys()):
            events = context.get(
                rule_id=self.rule_id,
                key=key,
                window_seconds=self.window_seconds,
            )

            if len(events) >= self.threshold:
                alert = self.create_alert(key, events)
                results.append({"alert": alert, "evidence": []})
                context.clear_key(rule_id=self.rule_id, key=key)

        return results