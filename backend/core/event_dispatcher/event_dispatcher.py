# core/event_dispatcher/event_dispatcher.py
# README.md dosyasını oku

# from models.log_model import LogEventModel
from backend.models.metric_model import MetricModel
# from models.alert_model import AlertModel
# from models.network_event_model import NetworkEvent
from backend.database import save_metric_snapshot

from backend.models.process_event_model import ProcessEventModel
from backend.models.alert_model import AlertModel

from backend.logger import logger


class EventDispatcher:

    def dispatch(self, event: dict):
        if not event:
            return None
        
        etype = event.get("type", "")

        logger.debug(f"[DISPATCH] Received event type={etype}")

        # # PROCESS EVENTS
        # if etype.startswith("PROCESS_"):
        #     logger.debug(f"[DISPATCH] → Routing PROCESS event {etype}")
        #     return self._handle_process(event)

        # # NETWORK EVENTS
        # if etype.startswith("NET_") or etype.startswith("CONNECTION_"):
        #     logger.debug(f"[DISPATCH] → Routing NETWORK event {etype}")
        #     return self._handle_network(event)

        # METRICS
        if etype == "METRIC_SNAPSHOT":
            logger.debug("[DISPATCH] → Routing METRIC_SNAPSHOT")
            return self._handle_metric(event)

        # # ALERTS
        # if etype.startswith("ALERT_"):
        #     logger.debug(f"[DISPATCH] → Routing ALERT event {etype}")
        #     return self._handle_alert(event)

        # UNKNOWN EVENT
        # logger.warning(f"[DISPATCH] Unknown event type received: {etype}")
        return None


    # -------------------------
    # HANDLERS
    # -------------------------
    # def _handle_process(self, event):
    #     logger.debug("[DISPATCH][PROCESS] Saving process event")
    #     try:
    #         result = ProcessEventModel.create(event)
    #         logger.debug("[DISPATCH][PROCESS] Saved successfully")
    #         return result
    #     except Exception as e:
    #         logger.error(f"[DISPATCH][PROCESS] Failed: {e}")
    #         return None


    # def _handle_network(self, event):
    #     logger.debug(f"[DISPATCH][NETWORK] Handling network event: {event.get('type')}")
    #     try:
    #         # Şimdilik model yok → sadece debug bastık
    #         # NetworkEvent.create(event) gibi ileride eklenecek
    #         return None
    #     except Exception as e:
    #         logger.error(f"[DISPATCH][NETWORK] Failed: {e}")
    #         return None


    def _handle_metric(self, event):
        logger.debug("[DISPATCH][METRIC] Saving metric snapshot")
        try:
            result = save_metric_snapshot(event)
            logger.info("[DISPATCH][METRIC] Metric snapshot saved")
            return result
        except Exception as e:
            logger.error(f"[DISPATCH][METRIC] Failed: {e}")
            return None


    # def _handle_alert(self, event):
    #     logger.debug("[DISPATCH][ALERT] Saving alert event")
    #     try:
    #         result = AlertModel.create(event)
    #         logger.debug("[DISPATCH][ALERT] Saved successfully")
    #         return result
    #     except Exception as e:
    #         logger.error(f"[DISPATCH][ALERT] Failed: {e}")
    #         return None
