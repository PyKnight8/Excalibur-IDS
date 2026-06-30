import json


MAX_MESSAGE_BYTES = 4096
ALLOWED_ACTIONS = {
    "sensor_status",
    "sensor_start",
    "sensor_stop",
    "sensor_restart",
}


class ProtocolError(ValueError):
    pass


def decode_request(data):
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError("Request too large.")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("Invalid JSON request.") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("Request must be a JSON object.")
    if set(payload.keys()) != {"action"}:
        raise ProtocolError("Request must contain only the action field.")
    action = payload.get("action")
    if action not in ALLOWED_ACTIONS:
        raise ProtocolError("Unsupported action.")
    return payload


def encode_response(payload):
    return (json.dumps(payload) + "\n").encode("utf-8")
