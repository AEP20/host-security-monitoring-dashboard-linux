# core/event_dispatcher/event_dispatcher.py
# README.md dosyasını oku

from models.process_event_model import ProcessEventModel
# from models.log_model import LogEventModel
from backend.models.metric_model import MetricModel
from models.alert_model import AlertModel
# from models.network_event_model import NetworkEvent
from backend.database import save_metric_snapshot

class EventDispatcher:

    def dispatch(self, event: dict):
        etype = event.get("type", "")

        print(f"[DEBUG][DISPATCH] Received event type={etype}")

        # PROCESS EVENTS
        if etype.startswith("PROCESS_"):
            print(f"[DEBUG][DISPATCH] → Routing PROCESS event {etype}")
            return self._handle_process(event)

        # NETWORK EVENTS
        if etype.startswith("NET_") or etype.startswith("CONNECTION_"):
            print(f"[DEBUG][DISPATCH] → Routing NETWORK event {etype}")
            return self._handle_network(event)

        # METRICS
        if etype == "METRIC_SNAPSHOT":
            print("[DEBUG][DISPATCH] → Routing METRIC_SNAPSHOT")
            return self._handle_metric(event)

        # ALERTS
        if etype.startswith("ALERT_"):
            print(f"[DEBUG][DISPATCH] → Routing ALERT event {etype}")
            return self._handle_alert(event)

        # UNKNOWN EVENT
        print(f"[WARN][DISPATCH] Unknown event type received: {etype}")
        return None


    # -------------------------
    # HANDLERS
    # -------------------------
    # def _handle_process(self, event):
    #     print(f"[DEBUG][DISPATCH][PROCESS] Saving process event")
    #     try:
    #         result = ProcessEventModel.create(event)
    #         print(f"[DEBUG][DISPATCH][PROCESS] Saved successfully")
    #         return result
    #     except Exception as e:
    #         print(f"[ERROR][DISPATCH][PROCESS] Failed: {e}")
    #         return None


    # def _handle_network(self, event):
    #     print(f"[DEBUG][DISPATCH][NETWORK] Handling network event: {event.get('type')}")
    #     try:
    #         # Şimdilik model yok → sadece debug bastık
    #         # NetworkEvent.create(event) gibi ileride eklenecek
    #         return None
    #     except Exception as e:
    #         print(f"[ERROR][DISPATCH][NETWORK] Failed: {e}")
    #         return None


    def _handle_metric(self, event):
        print(f"[DEBUG][DISPATCH][METRIC] Saving metric snapshot")
        try:
            result = save_metric_snapshot(event)
            print(f"[DEBUG][DISPATCH][METRIC] Saved successfully")
            return result
        except Exception as e:
            print(f"[ERROR][DISPATCH][METRIC] Failed: {e}")
            return None


    # def _handle_alert(self, event):
    #     print(f"[DEBUG][DISPATCH][ALERT] Saving alert event")
    #     try:
    #         result = AlertModel.create(event)
    #         print(f"[DEBUG][DISPATCH][ALERT] Saved successfully")
    #         return result
    #     except Exception as e:
    #         print(f"[ERROR][DISPATCH][ALERT] Failed: {e}")
    #         return None
