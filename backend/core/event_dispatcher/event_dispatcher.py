# core/event_dispatcher/event_dispatcher.py
# README.md dosyasını oku

from models.process_event_model import ProcessEventModel
from models.log_model import LogEventModel
from backend.models.metric_model import MetricModel
from models.alert_model import AlertModel
# from models.network_event_model import NetworkEvent

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

    # def _handle_network(self, event):
    #     return NetworkEvent.create(event)

    def _handle_metric(self, event):
        return MetricModel.create(event)

    # def _handle_alert(self, event):
    #     return AlertModel.create(event)

