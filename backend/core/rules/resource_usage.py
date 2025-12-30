from backend.core.rules.base import ThresholdRule
from backend.logger import logger
from typing import Any, List, Dict

class HighResourceUsageRule(ThresholdRule):
    rule_id = "RES_001"
    description = "Continuous high CPU or Memory usage detected"
    severity = "MEDIUM"
    event_prefix = "METRIC_"  
    
    threshold = 2         
    window_seconds = 180  
    
    CPU_THRESHOLD = 70.0   # %70 üzeri CPU 
    MEM_THRESHOLD = 80.0   # %80 üzeri RAM

    def is_relevant(self, event: Dict[str, Any]) -> bool:
        """Sadece metrik snapshotlarını kontrol et"""
        return event.get("type") == "METRIC_SNAPSHOT"

    def get_key(self, event: Dict[str, Any]) -> tuple:
        """Sistemi tek bir anahtar altında izle"""
        return ("system_resources",)

    def match_condition(self, event: Dict[str, Any]) -> bool:
        """Eşik değerleri aşıldı mı?"""
        cpu = event.get("cpu_percent", 0)
        mem = event.get("ram_percent", 0)
        return cpu > self.CPU_THRESHOLD or mem > self.MEM_THRESHOLD

    def consume(self, event: Dict[str, Any], context: Any) -> None:
        """Eşik aşılıyorsa olayı CorrelationContext hafızasına ekle"""
        if not self.is_relevant(event):
            return
            
        if self.match_condition(event):
            logger.debug(f"[{self.rule_id}] High usage detected: CPU %{event.get('cpu_percent')}")
            context.add(
                rule_id=self.rule_id,
                key=self.get_key(event),
                event=event,
                window_seconds=self.window_seconds,
            )

    def create_alert(self, key: tuple, events: List[Any]) -> Dict[str, Any]:
        """Eşik aşıldığında asıl alarm payload'unu oluştur"""
        last_event = events[-1]
        cpu = last_event.get("cpu_percent")
        mem = last_event.get("ram_percent")

        event_ids = [e.get("id") for e in events if e.get("id")]

        logger.info(f"[{self.rule_id}] THRESHOLD REACHED! Generating Alert.")

        return self.build_alert_base(
            alert_type="ALERT_HIGH_RESOURCE_USAGE",
            message=f"Critical resource usage: CPU %{cpu}, RAM %{mem} detected over {len(events)} snapshots.",
            extra=self.build_evidence_spec(
                source="metric_events", 
                filters={"id__in": event_ids}
            )
        )