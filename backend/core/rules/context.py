import time
from collections import defaultdict, deque
from typing import Any, Dict, Deque, Tuple, List

from backend.logger import logger 

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
        before = len(dq)
        while dq and dq[0]["ts"] < cutoff:
            dq.popleft()
        after = len(dq)

        if before != after:
            logger.debug(
                f"[CTX][PRUNE] removed={before-after} remaining={after}"
            )

    def _ensure_limits(self, rule_id: str):
        rule_bucket = self._store[rule_id]
        if len(rule_bucket) <= self.max_keys_per_rule:
            return

        oldest_key = next(iter(rule_bucket))
        logger.warning(
            f"[CTX][LIMIT] rule={rule_id} dropping key={oldest_key}"
        )
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
            logger.debug(
                f"[CTX][NEW_KEY] rule={rule_id} key={key}"
            )
            rule_bucket[key] = deque(maxlen=self.max_events_per_key)

        dq = rule_bucket[key]

        self._prune_deque(dq, window)

        ts = event.get("timestamp")
        if hasattr(ts, "timestamp"):
            ts = ts.timestamp()

        event_ref = {
            "event_id": event.get("id"),
            "event_type": event.get("event_type"),
            "ts": ts if ts is not None else self._now(),
        }

        dq.append(event_ref)

        logger.debug(
            f"[CTX][ADD] rule={rule_id} key={key} "
            f"events={len(dq)} ts={event_ref['ts']}"
        )

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
            logger.debug(f"[CTX][GET] rule={rule_id} empty bucket")
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
        rule_bucket = self._store.get(rule_id)
        if not rule_bucket:
            return

        if key in rule_bucket:
            logger.debug(
                f"[CTX][CLEAR_KEY] rule={rule_id} key={key}"
            )

        rule_bucket.pop(key, None)
