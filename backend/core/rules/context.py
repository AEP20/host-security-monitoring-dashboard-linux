# backend/core/rules/context.py
import time
from collections import defaultdict, deque
from typing import Any, Dict, Deque, Tuple, List


EventRef = Dict[str, Any]
ContextKey = Tuple[Any, ...]


class CorrelationContext:
    """
    In-memory, rule-scoped correlation store.

    - TTL based (window_seconds)
    - Rule isolation (no cross-rule leakage)
    - Key + per-key event limits
    - Lazy cleanup (no background thread)
    """

    def __init__(
        self,
        *,
        default_window: int = 300,
        max_keys_per_rule: int = 500,
        max_events_per_key: int = 50,
    ):
        self.default_window = default_window
        self.max_keys_per_rule = max_keys_per_rule
        self.max_events_per_key = max_events_per_key

        # structure:
        # rule_id -> key -> deque[event_ref]
        self._store: Dict[str, Dict[ContextKey, Deque[EventRef]]] = defaultdict(dict)

    # --------------------------------------------------
    # INTERNAL HELPERS
    # --------------------------------------------------
    def _now(self) -> float:
        return time.time()

    def _prune_deque(self, dq: Deque[EventRef], window: int):
        """
        Drop expired events from left side (oldest first).
        """
        cutoff = self._now() - window
        while dq and dq[0]["ts"] < cutoff:
            dq.popleft()

    def _ensure_limits(self, rule_id: str):
        """
        Enforce max_keys_per_rule.
        Oldest key is dropped (FIFO on dict order).
        """
        rule_bucket = self._store[rule_id]
        if len(rule_bucket) <= self.max_keys_per_rule:
            return

        # drop oldest key (dict preserves insertion order in py3.7+)
        oldest_key = next(iter(rule_bucket))
        del rule_bucket[oldest_key]

    # --------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------
    def add(
        self,
        *,
        rule_id: str,
        key: ContextKey,
        event: Dict[str, Any],
        window_seconds: int | None = None,
    ):
        """
        Add event reference to context.

        key: tuple that defines correlation scope
        """
        window = window_seconds or self.default_window
        rule_bucket = self._store[rule_id]

        # enforce key count limit
        self._ensure_limits(rule_id)

        if key not in rule_bucket:
            rule_bucket[key] = deque(maxlen=self.max_events_per_key)

        dq = rule_bucket[key]

        # prune before insert
        self._prune_deque(dq, window)

        # minimal event reference
        event_ref: EventRef = {
            "event_id": event.get("id"),
            "event_type": event.get("type"),
            "ts": event.get("timestamp") or self._now(),
        }

        dq.append(event_ref)

    def get(
        self,
        *,
        rule_id: str,
        key: ContextKey,
        window_seconds: int | None = None,
    ) -> List[EventRef]:
        """
        Get active event refs for a given rule + key.
        """
        window = window_seconds or self.default_window
        rule_bucket = self._store.get(rule_id)
        if not rule_bucket:
            return []

        dq = rule_bucket.get(key)
        if not dq:
            return []

        self._prune_deque(dq, window)
        return list(dq)

    def clear_key(self, *, rule_id: str, key: ContextKey):
        """
        Clear correlation state for a specific key (e.g. after alert).
        """
        rule_bucket = self._store.get(rule_id)
        if not rule_bucket:
            return
        rule_bucket.pop(key, None)

    def clear_rule(self, *, rule_id: str):
        """
        Clear all state for a rule.
        """
        self._store.pop(rule_id, None)

    def stats(self) -> Dict[str, Any]:
        """
        Lightweight introspection (debug / health).
        """
        out = {}
        for rule_id, bucket in self._store.items():
            out[rule_id] = {
                "keys": len(bucket),
                "events": sum(len(dq) for dq in bucket.values()),
            }
        return out
