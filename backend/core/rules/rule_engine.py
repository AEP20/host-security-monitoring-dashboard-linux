# core/rules/rule_engine.py
from backend.logger import logger

class RuleEngine:
    def __init__(self, rules: list):
        self.rules = rules

    def process(self, event: dict) -> list:
        alerts = []

        etype = event.get("type", "")
        logger.debug(f"[RULE_ENGINE] Processing event {etype}")

        for rule in self.rules:
            if not etype.startswith(rule.event_prefix):
                continue

            try:
                if rule.match(event):
                    alert = rule.build_alert(event)
                    alerts.append(alert)
                    logger.info(f"[RULE_ENGINE] Rule matched: {rule.rule_id}")
            except Exception as e:
                logger.error(f"[RULE_ENGINE] Rule {rule.rule_id} failed: {e}")

        return alerts
