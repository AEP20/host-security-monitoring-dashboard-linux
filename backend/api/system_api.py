# system_api.py

# /api/ports
# /api/processes
# → open ports, suspicious processes vs.

from flask import Blueprint, jsonify

system_api = Blueprint("system_api", __name__)

@system_api.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok"}), 200
