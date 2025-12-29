from backend.core.rules.base import ThresholdRule
from backend.logger import logger
from typing import Any, List, Dict

class HighResourceUsageRule(ThresholdRule):
    rule_id = "RES_001"
    description = "Continuous high CPU or Memory usage detected"
    severity = "MEDIUM"
    event_prefix = "METRIC_"  # MetricsCollector METRIC_SNAPSHOT üretir
    
    # Eşik Ayarları
    threshold = 3          # Pencere içinde 3 defa eşik aşılırsa tetikle
    window_seconds = 60    # 1 dakikalık pencere (WINDOW_SIZE)
    
    CPU_THRESHOLD = 70.0
    MEM_THRESHOLD = 10.0

    def is_relevant(self, event: Dict[str, Any]) -> bool:
        """Sadece metrik snapshotlarını kontrol et"""
        return event.get("type") == "METRIC_SNAPSHOT"

    def get_key(self, event: Dict[str, Any]) -> tuple:
        """Tüm sistem kaynaklarını tek bir anahtar altında izle"""
        return ("system_resources",)

    def match_condition(self, event: Dict[str, Any]) -> bool:
        """CPU veya RAM eşiği aşıldı mı?"""
        cpu = event.get("cpu_percent", 0)
        mem = event.get("ram_percent", 0)
        return cpu > self.CPU_THRESHOLD or mem > self.MEM_THRESHOLD

    def consume(self, event: Dict[str, Any], context: Any) -> None:
        """Olayı değerlendir ve eşik aşılıyorsa context'e ekle"""
        if not self.is_relevant(event):
            return
            
        if self.match_condition(event):
            logger.debug(f"[{self.rule_id}] High usage: CPU %{event.get('cpu_percent')}, MEM %{event.get('ram_percent')}")
            context.add(
                rule_id=self.rule_id,
                key=self.get_key(event),
                event=event,
                window_seconds=self.window_seconds,
            )

    def create_alert(self, key: tuple, events: List[Any]) -> Dict[str, Any]:
        """Eşik aşıldığında alarmı oluştur"""
        last_event = events[-1]
        cpu = last_event.get("cpu_percent")
        mem = last_event.get("ram_percent")

        # Kanıt olarak kuralı tetikleyen tüm snapshot ID'lerini gönder
        event_ids = [e.get("id") for e in events if e.get("id")]

        return self.build_alert_base(
            alert_type="ALERT_HIGH_RESOURCE_USAGE",
            message=f"Critical resource usage: CPU %{cpu}, RAM %{mem} exceeded thresholds for 1 minute.",
            extra=self.build_evidence_spec(
                source="metric_events", # DBWriter'daki doğru tablo ismi
                filters={"id__in": event_ids}
            )
        )