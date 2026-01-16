import json
import requests
from pathlib import Path
from flask import Blueprint, request, jsonify

MOCKS_DIR = Path(__file__).resolve().parent.parent / "mocks"


def load_mock(filename):
    filepath = MOCKS_DIR / filename
    if filepath.exists():
        with open(filepath, "r") as f:
            return json.load(f)
    return {}


def success_response(data, message="OK"):
    return jsonify({
        "status": "success",
        "success": True,
        "message": message,
        "data": data
    })


def error_response(message, status_code=500):
    return jsonify({
        "status": "error",
        "success": False,
        "message": message,
        "data": None
    }), status_code


mock_api = Blueprint("mock_api", __name__)


@mock_api.get("/api/system/status")
def system_status():
    data = load_mock("system.json")
    return success_response(data.get("status", {}))


@mock_api.get("/api/system/threads")
def system_threads():
    data = load_mock("system.json")
    return success_response(data.get("threads", []))


@mock_api.get("/api/metrics/latest")
def metrics_latest():
    data = load_mock("metrics.json")
    return success_response(data.get("latest", {}))


@mock_api.get("/api/metrics/timeline")
def metrics_timeline():
    data = load_mock("metrics.json")
    limit = int(request.args.get("limit", 50))
    timeline = data.get("timeline", [])
    return success_response(timeline[:limit])


@mock_api.get("/api/logs/events")
def logs_events():
    data = load_mock("logs.json")
    events = data.get("events", [])

    severity = request.args.get("severity")
    source = request.args.get("source")
    category = request.args.get("category")
    search = request.args.get("search", "").lower()
    expand = request.args.get("expand") == "true"
    limit = int(request.args.get("limit", 500))
    offset = int(request.args.get("offset", 0))

    if severity:
        events = [e for e in events if e.get("severity") == severity]
    if source:
        events = [e for e in events if e.get("log_source") == source]
    if category:
        events = [e for e in events if e.get("category") == category]
    if search:
        events = [e for e in events if search in e.get("message", "").lower()]

    paginated = events[offset:offset + limit]

    if expand:
        for ev in paginated:
            if "related_alerts" not in ev:
                ev["related_alerts"] = []

    return success_response(paginated)


@mock_api.get("/api/logs/internal")
def logs_internal():
    data = load_mock("logs.json")
    return success_response(data.get("internal", ""))


@mock_api.get("/api/alerts")
def alerts_list():
    data = load_mock("alerts.json")
    alerts = data.get("alerts", [])
    limit = int(request.args.get("limit", 100))
    return success_response(alerts[:limit])


@mock_api.get("/api/alerts/<int:alert_id>")
def alert_detail(alert_id):
    data = load_mock("alerts.json")
    details = data.get("details", {})
    detail = details.get(str(alert_id))
    if detail:
        return success_response(detail)
    return error_response("Alert not found", 404)


@mock_api.get("/api/process/events")
def process_events():
    data = load_mock("processes.json")
    return success_response(data.get("events", []))


@mock_api.get("/api/process/events/<int:event_id>")
def process_event_detail(event_id):
    data = load_mock("processes.json")
    details = data.get("event_details", {})
    detail = details.get(str(event_id))
    if detail:
        return success_response(detail)
    return error_response("Process event not found", 404)


@mock_api.get("/api/process/active")
def process_active():
    data = load_mock("processes.json")
    return success_response(data.get("active", []))


@mock_api.get("/api/network/events")
def network_events():
    data = load_mock("network.json")
    return success_response(data.get("events", []))


@mock_api.get("/api/network/events/<int:event_id>")
def network_event_detail(event_id):
    data = load_mock("network.json")
    details = data.get("event_details", {})
    detail = details.get(str(event_id))
    if detail:
        return success_response(detail)
    return error_response("Network event not found", 404)


@mock_api.get("/api/network/active")
def network_active():
    data = load_mock("network.json")
    return success_response(data.get("active", []))


unavailable_api = Blueprint("unavailable_api", __name__)


@unavailable_api.route("/api/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def api_unavailable(path):
    return error_response(
        "Backend unavailable. Set HIDS_BACKEND_URL to proxy to real backend.",
        503
    )


def create_proxy_blueprint(backend_url):
    proxy_bp = Blueprint("proxy_api", __name__)

    @proxy_bp.route("/api/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
    def proxy(path):
        url = f"{backend_url.rstrip('/')}/api/{path}"
        try:
            resp = requests.request(
                method=request.method,
                url=url,
                params=request.args,
                json=request.get_json(silent=True),
                headers={k: v for k, v in request.headers if k.lower() != "host"},
                timeout=10
            )
            return resp.content, resp.status_code, resp.headers.items()
        except requests.RequestException as e:
            return error_response(f"Proxy error: {str(e)}", 502)

    return proxy_bp
