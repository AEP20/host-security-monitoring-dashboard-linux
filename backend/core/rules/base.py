# backend/core/rules/base.py
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
        """
        Alert payload standardı (tüm rule'lar buradan üretir)
        """
        alert = {
            "type": alert_type,
            "rule_name": self.rule_id,
            "severity": self.severity,
            "message": message,
            "log_event_id": log_event_id,
        }

        # Şimdilik DB'ye yazılmıyor ama mimaride var
        if related_events:
            alert["related_events"] = related_events

        if extra:
            alert["extra"] = extra

        return alert


# =========================================================
# STATELESS RULE
# =========================================================
class StatelessRule(BaseRule, ABC):
    """
    Tek event ile karar veren rule.
    """

    @abstractmethod
    def match(self, event: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def build_alert(self, event: Dict[str, Any]) -> Dict[str, Any]:
        pass

    def build_evidence(
        self,
        event: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Default stateless evidence:
        - current event
        - TRIGGER
        """
        return [{
            "event_type": event.get("type"),
            "event_id": event.get("id"),
            "role": "TRIGGER",
            "sequence": 1,
        }]


# =========================================================
# STATEFUL RULE
# =========================================================
class StatefulRule(BaseRule, ABC):
    """
    Birden fazla event ile karar veren rule.
    """

    window_seconds: int = 300

    @abstractmethod
    def consume(self, event: Dict[str, Any], context: Any) -> None:
        pass

    @abstractmethod
    def evaluate(self, context: Any) -> List[Dict[str, Any]]:
        """
        Alert payload üretir.
        Evidence bilgisi alert içinde taşınır.
        """
        pass

