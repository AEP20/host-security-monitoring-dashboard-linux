import time
from collections import defaultdict, deque
from typing import Any, Dict, Deque, Tuple, List

from backend.logger import logger

EventRef = Dict[str, Any]
ContextKey = Tuple[Any, ...]


class CorrelationContext:
    """
    Generic, rule-agnostic in-memory correlation store.

    Responsibilities:
    - Maintain per-rule, per-key sliding time windows
    - Enforce size limits (keys / events)
    - Store minimal event references (NOT full events)
    - Provide deterministic, debuggable behavior
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

        # rule_id -> key -> deque[event_ref]
        self._store: Dict[str, Dict[ContextKey, Deque[EventRef]]] = defaultdict(dict)

    # --------------------------------------------------
    # INTERNAL HELPERS
    # --------------------------------------------------
    def _now(self) -> float:
        return time.time()

    def _normalize_ts(self, ts: Any) -> float:
        """
        Normalize timestamp to epoch seconds.
        """
        if ts is None:
            return self._now()
        if hasattr(ts, "timestamp"):
            return ts.timestamp()
        return float(ts)

    def _prune_deque(self, dq: Deque[EventRef], window: int):
        """
        Remove expired events from the left (oldest first).
        """
        cutoff = self._now() - window
        before = len(dq)

        while dq and dq[0]["ts"] < cutoff:
            dq.popleft()

        removed = before - len(dq)
        if removed > 0:
            logger.debug(
                f"[CTX][PRUNE] removed={removed} remaining={len(dq)}"
            )

    def _ensure_key_limit(self, rule_id: str):
        """
        Enforce max_keys_per_rule using FIFO eviction.
        """
        rule_bucket = self._store[rule_id]
        if len(rule_bucket) <= self.max_keys_per_rule:
            return

        oldest_key = next(iter(rule_bucket))
        logger.warning(
            f"[CTX][LIMIT] rule={rule_id} dropping oldest key={oldest_key}"
        )
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
        Add a minimal event reference to the correlation store.

        Stored data is intentionally minimal:
        - event_id
        - event_type
        - ts (epoch seconds)
        """
        window = window_seconds or self.default_window
        rule_bucket = self._store[rule_id]

        self._ensure_key_limit(rule_id)

        if key not in rule_bucket:
            logger.debug(f"[CTX][NEW_KEY] rule={rule_id} key={key}")
            rule_bucket[key] = deque(maxlen=self.max_events_per_key)

        dq = rule_bucket[key]

        # prune expired before insert
        self._prune_deque(dq, window)

        event_ref: EventRef = {
            "event_id": event.get("id"),
            "event_type": event.get("event_type"),
            "ts": self._normalize_ts(event.get("timestamp")),
        }

        dq.append(event_ref)

        logger.debug(
            f"[CTX][ADD] rule={rule_id} key={key} "
            f"count={len(dq)} ts={event_ref['ts']}"
        )

    def get(
        self,
        *,
        rule_id: str,
        key: ContextKey,
        window_seconds: int | None = None,
    ) -> List[EventRef]:
        """
        Retrieve active event references for rule + key.
        """
        window = window_seconds or self.default_window
        rule_bucket = self._store.get(rule_id)

        if not rule_bucket:
            logger.debug(f"[CTX][GET] rule={rule_id} no bucket")
            return []

        dq = rule_bucket.get(key)
        if not dq:
            logger.debug(f"[CTX][GET] rule={rule_id} key={key} not found")
            return []

        self._prune_deque(dq, window)

        logger.debug(
            f"[CTX][GET] rule={rule_id} key={key} count={len(dq)}"
        )
        return list(dq)

    def clear_key(self, *, rule_id: str, key: ContextKey):
        """
        Clear correlation state for a specific key.
        """
        rule_bucket = self._store.get(rule_id)
        if not rule_bucket:
            return

        if key in rule_bucket:
            logger.debug(f"[CTX][CLEAR_KEY] rule={rule_id} key={key}")

        rule_bucket.pop(key, None)

    def clear_rule(self, *, rule_id: str):
        """
        Clear all state for a rule.
        """
        if rule_id in self._store:
            logger.debug(f"[CTX][CLEAR_RULE] rule={rule_id}")
        self._store.pop(rule_id, None)

    def stats(self) -> Dict[str, Any]:
        """
        Lightweight introspection for debugging / health checks.
        """
        return {
            rule_id: {
                "keys": len(bucket),
                "events": sum(len(dq) for dq in bucket.values()),
            }
            for rule_id, bucket in self._store.items()
        }
