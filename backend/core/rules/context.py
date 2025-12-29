import time
from collections import defaultdict, deque
from typing import Any, Dict, Deque, Tuple, List


EventRef = Dict[str, Any]
ContextKey = Tuple[Any, ...]


class CorrelationContext:
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
        self._store: Dict[str, Dict[ContextKey, Deque[EventRef]]] = defaultdict(dict)

    def _now(self) -> float:
        return time.time()

    def _prune_deque(self, dq: Deque[EventRef], window: int):
        cutoff = self._now() - window
        while dq and dq[0]["ts"] < cutoff:
            dq.popleft()

    def _ensure_limits(self, rule_id: str):
        rule_bucket = self._store[rule_id]
        if len(rule_bucket) <= self.max_keys_per_rule:
            return
        oldest_key = next(iter(rule_bucket))
        del rule_bucket[oldest_key]

    # --------------------------------------------------
    def add(
        self,
        *,
        rule_id: str,
        key: ContextKey,
        event: Dict[str, Any],
        window_seconds: int | None = None,
    ):
        window = window_seconds or self.default_window
        rule_bucket = self._store[rule_id]

        self._ensure_limits(rule_id)

        if key not in rule_bucket:
            rule_bucket[key] = deque(maxlen=self.max_events_per_key)

        dq = rule_bucket[key]
        self._prune_deque(dq, window)

        ts = event.get("timestamp")
        if hasattr(ts, "timestamp"):
            ts = ts.timestamp()

        dq.append({
            "event_id": event.get("id"),
            "event_type": event.get("event_type"),
            "ts": ts if ts is not None else self._now(),
        })

    def get(
        self,
        *,
        rule_id: str,
        key: ContextKey,
        window_seconds: int | None = None,
    ) -> List[EventRef]:
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
        rule_bucket = self._store.get(rule_id)
        if not rule_bucket:
            return
        rule_bucket.pop(key, None)
