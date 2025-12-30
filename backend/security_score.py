import time
import math
from datetime import datetime, timedelta
from backend.database import SessionLocal
from backend.models.alert_model import AlertModel
from backend.logger import logger


class SecurityScore:
    _cached_score = 100
    _last_calc_time = 0
    CACHE_DURATION = 60 

    @classmethod
    def calculate_score(cls):
        now = time.time()

        # Cache kontrolü
        if now - cls._last_calc_time < cls.CACHE_DURATION:
            return cls._cached_score

        score = 100
        session = SessionLocal()

        try:
            # Son 24 saatteki alarmları çek
            one_day_ago = datetime.now() - timedelta(days=1)
            alerts = session.query(AlertModel).filter(
                AlertModel.timestamp >= one_day_ago
            ).all()

            rule_counts = {}

            for alert in alerts:
                sev = (alert.severity or "LOW").upper()
                penalty = {
                    "CRITICAL": 20,
                    "HIGH": 10,
                    "MEDIUM": 5,
                    "LOW": 2
                }.get(sev, 2)

                hours_old = (
                    datetime.now() - alert.timestamp
                ).total_seconds() / 3600

                time_decay = max(0.2, math.exp(-0.1 * hours_old))

                rule_key = alert.rule_name or "UNKNOWN"
                rule_counts[rule_key] = rule_counts.get(rule_key, 0) + 1
                frequency_factor = 1 + math.log(1 + rule_counts[rule_key])

                score -= penalty * time_decay * frequency_factor

            # Skoru 0–100 aralığında tuatar
            cls._cached_score = max(0, min(100, int(score)))
            cls._last_calc_time = now

            logger.info(f"[SecurityScore] New score calculated: {cls._cached_score}")
            return cls._cached_score

        except Exception as e:
            logger.error(f"[SecurityScore] Calculation error: {e}")
            return cls._cached_score

        finally:
            session.close()
