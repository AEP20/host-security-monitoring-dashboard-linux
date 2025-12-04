"""
============================================================
                    EVENT DISPATCHER
============================================================

Bu modül, HIDS mimarisindeki *tek ve merkezi* event yöneticisidir.
Collector → Rule Engine → Dispatcher → Database zincirinin
"dispatcher" ayağını temsil eder.

Collector katmanı:
    - process, network, metrics ve log collector’ları
    - snapshot toplar ve "event" üretir
    - DB’ye yazmaz, risk analizi yapmaz

Rule Engine:
    - event’i analiz eder (ör: brute force, port exposure, root login)
    - gerekiyorsa ALERT üretir
    - yine DB yazmaz

Event Dispatcher (BU DOSYA):
    - tüm eventlerin TEK giriş noktasıdır
    - event’in tipine bakarak doğru DB modeline yönlendirir
    - process event → ProcessEvent modeline
    - network event → NetworkEvent modeline
    - log event → LogEvent modeline
    - metric snapshot → Metric modeline
    - alert → Alert modeline
    - DB save işlemleri yalnızca buradan yapılır

Neden TEK DISPATCHER?
---------------------
• Collector’ların DB bağımlılığı olmamalı (performans + bağımsızlık).
• Rule Engine yalnızca karar verir; DB işlemi yapmamalı.
• Tüm event akışı için *tek merkezi kontrol noktası* gerekir.
• DB işlemleri, connection management ve hata yönetimi tek yerde toplanır.
• Gerçek HIDS/EDR mimarilerinde (Wazuh, OSSEC, Sysmon, CrowdStrike) 
  event routing her zaman tek entry-point üzerinden yapılır.

Dispatcher Flow:
----------------
1) Collector → event üretir
2) Rule Engine → event’i işler, alert gerekiyorsa alert döndürür
3) Dispatcher → tüm event’leri alır
4) Event türüne göre doğru handler’a yönlendirir
5) Handler → ilgili DB modeline kaydeder

Bu mimari sayesinde:
    - Collector hafif ve hızlı kalır
    - Rule Engine sade olur (logic-only)
    - DB işlemleri tek bir yerde toplanır
    - Yeni event türleri kolayca eklenebilir
    
    
    | Handler               | Input           | Bu event nereden gelir?               | Ne yapar?                                         |
| --------------------- | --------------- | ------------------------------------- | ------------------------------------------------- |
| **_handle_log()**     | LOG_EVENT       | LogDispatcher **kullanmaz** (şu anda) | İstersen parser DB yazımını buraya taşıyabilirsin |
| **_handle_metric()**  | METRIC_SNAPSHOT | metrics_collector                     | snapshot → MetricModel                            |
| **_handle_process()** | PROCESS_*       | process_collector                     | event → ProcessEventModel                         |
| **_handle_network()** | NET_*           | network_collector                     | event → NetworkEventModel                         |
| **_handle_alert()**   | ALERT_*         | rule_engine                           | alert → AlertModel                                |


============================================================
"""


from models.process_event_model import ProcessEventModel
from models.log_model import LogEvent
from models.metric_model import Metric
from models.alert_model import Alert
# from models.network_model import NetworkEvent

class EventDispatcher:

    def dispatch(self, event: dict):
        etype = event.get("type", "")

        # PROCESS
        if etype.startswith("PROCESS_"):
            return self._handle_process(event)

        # NETWORK
        if etype.startswith("NET_") or etype.startswith("CONNECTION_"):
            return self._handle_network(event)

        # METRIC SNAPSHOT
        if etype == "METRIC_SNAPSHOT":
            return self._handle_metric(event)

        # ALERTS
        if etype.startswith("ALERT_"):
            return self._handle_alert(event)

        # Unknown
        # print("[DISPATCHER] Unknown event:", etype)

    # -------------------------
    # HANDLERS
    # -------------------------
    def _handle_process(self, event):
        return ProcessEventModel.create(event)

    def _handle_network(self, event):
        return NetworkEvent.create(event)

    def _handle_metric(self, event):
        return Metric.create(event)

    def _handle_alert(self, event):
        return Alert.create(event)

