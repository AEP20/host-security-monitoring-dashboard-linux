import time
from datetime import datetime, timedelta
from backend.database import SessionLocal
from backend.models.alert_model import AlertModel
from backend.logger import logger

class SecurityScore:
    _cached_score = 100
    _last_calc_time = 0
    CACHE_DURATION = 60  # 60 saniyede bir güncelle

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
            alerts = session.query(AlertModel).filter(AlertModel.timestamp >= one_day_ago).all()

            for alert in alerts:
                # Severity bazlı puan kırma
                penalty = 0
                sev = (alert.severity or "LOW").upper()
                
                if sev == "CRITICAL": penalty = 20
                elif sev == "HIGH": penalty = 10
                elif sev == "MEDIUM": penalty = 5
                elif sev == "LOW": penalty = 2

                # Zaman aşımı (Time Decay): 
                # Alarm ne kadar yeniyse o kadar çok puan kırar.
                # 24 saatlik bir alarmın etkisi %20'ye kadar düşer.
                hours_old = (datetime.now() - alert.timestamp).total_seconds() / 3600
                time_multiplier = max(0.2, 1 - (hours_old / 24))
                
                score -= (penalty * time_multiplier)

            # Sınırları belirle
            cls._cached_score = max(0, min(100, int(score)))
            cls._last_calc_time = now
            
            logger.info(f"[SecurityScore] New score calculated: {cls._cached_score}")
            return cls._cached_score

        except Exception as e:
            logger.error(f"[SecurityScore] Calculation error: {e}")
            return cls._cached_score
        finally:
            session.close()