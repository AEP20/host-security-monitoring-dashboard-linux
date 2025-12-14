# core/rules/base.py
from abc import ABC, abstractmethod

class BaseRule(ABC):
    rule_id: str
    description: str
    severity: str
    event_prefix: str  # PROCESS_, NET_, etc.

    @abstractmethod
    def match(self, event: dict) -> bool:
        pass

    @abstractmethod
    def build_alert(self, event: dict) -> dict:
        pass
