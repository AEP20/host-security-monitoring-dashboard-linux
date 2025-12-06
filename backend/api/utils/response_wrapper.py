import traceback
from flask import jsonify


def success(data=None, message="OK", status_code=200):
    """
    Unified success response for all API endpoints.
    Ensures consistent JSON structure across the project.
    """
    response = {
        "status": "success",
        "success": True,
        "message": message,
        "data": data
    }
    return jsonify(response), status_code


def error(message="An error occurred", status_code=400, exception: Exception = None):
    """
    Unified error response.
    Automatically captures traceback if exception is passed.
    """
    error_info = {
        "status": "error",
        "message": message
    }

    # Optional: include stack trace for debugging mode
    if exception is not None:
        error_info["exception"] = str(exception)
        # Uncomment this if you want the full traceback in UI (development only)
        # error_info["traceback"] = traceback.format_exc()

    return jsonify(error_info), status_code


def validate_params(required_params, request_args):
    """
    Helper: validates required query parameters.
    Used in logs_api, process_api, etc.
    Returns (bool, response) where:
    - bool = validation passed?
    - response = error message if failed
    """
    missing = [p for p in required_params if p not in request_args]

    if missing:
        return False, error(
            message=f"Missing required parameters: {', '.join(missing)}",
            status_code=422
        )

    return True, None
