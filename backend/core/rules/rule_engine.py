# backend/core/rules/rule_engine.py
from typing import Dict, List, Any

from backend.logger import logger
from backend.core.rules.base import BaseRule, StatelessRule, StatefulRule


class RuleEngine:
    def __init__(self, rules: List[BaseRule], context: Any = None):
        self.context = context
        self.stateless_rules: List[StatelessRule] = []
        self.stateful_rules: List[StatefulRule] = []

        for rule in rules:
            if isinstance(rule, StatelessRule):
                self.stateless_rules.append(rule)
            elif isinstance(rule, StatefulRule):
                self.stateful_rules.append(rule)
            else:
                logger.warning(
                    f"[RULE_ENGINE] Rule {getattr(rule, 'rule_id', '?')} has unknown base class"
                )

        logger.info(
            f"[RULE_ENGINE] Loaded "
            f"stateless={len(self.stateless_rules)} "
            f"stateful={len(self.stateful_rules)}"
        )

    def process(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Returns list of:
        {
            "alert": alert_payload,
            "evidence": [evidence_dicts]
        }
        """
        results: List[Dict[str, Any]] = []

        raw_type = event.get("type", "")

        # ---------------------------
        # STATELESS
        # ---------------------------
        for rule in self.stateless_rules:
            if not rule.supports(raw_type):
                continue

            try:
                if rule.match(event):
                    alert = rule.build_alert(event)
                    evidence = rule.build_evidence(event)

                    results.append({
                        "alert": alert,
                        "evidence": evidence,
                    })

                    logger.info(f"[RULE_ENGINE] Stateless matched: {rule.rule_id}")

            except Exception as e:
                logger.exception(
                    f"[RULE_ENGINE] Stateless rule failed {rule.rule_id}: {e}"
                )

        # ---------------------------
        # STATEFUL
        # ---------------------------
        for rule in self.stateful_rules:
            # Rule prefix kontrolü orijinal tip üzerinden yapılır
            if not rule.supports(raw_type):
                continue

            try:
                # Event'i kuralın hafızasına (Context) ekle
                rule.consume(event, context=self.context)

                # Eşik değerlerin aşılıp aşılmadığını kontrol et
                produced = rule.evaluate(self.context)
                
                if produced:
                    for item in produced:
                        alert = item.get("alert")
                        evidence = item.get("evidence", [])

                        results.append({
                            "alert": alert,
                            "evidence": evidence,
                        })
                        logger.info(f"[RULE_ENGINE] Stateful matched: {rule.rule_id}")

            except Exception as e:
                logger.exception(
                    f"[RULE_ENGINE] Stateful rule failed {rule.rule_id}: {e}"
                )

        return results