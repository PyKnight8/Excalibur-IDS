import json
import socketserver
import sys

from excalibur.services.windows_service_manager import (
    WindowsServiceManager,
    WindowsServiceManagerError,
)


HOST = "127.0.0.1"
PORT = 47653
SENSOR_SERVICE_NAME = "ExcaliburSensor"


class WindowsHelperHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            request = json.loads(self.rfile.readline(4097).decode("utf-8"))
            action = request.get("action") if isinstance(request, dict) else None
            response = self.server.dispatch(action)
        except (UnicodeDecodeError, json.JSONDecodeError):
            response = {"ok": False, "error": "Invalid JSON request."}
        except WindowsServiceManagerError as exc:
            response = {"ok": False, "error": str(exc)}
        except Exception as exc:
            response = {"ok": False, "error": f"Unexpected helper failure: {exc}"}
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


class WindowsHelperServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address=(HOST, PORT), service_manager=None):
        self.service_manager = service_manager or WindowsServiceManager()
        super().__init__(address, WindowsHelperHandler)

    def dispatch(self, action):
        if action == "sensor_status":
            return {
                "ok": True,
                "status": self.service_manager.status(SENSOR_SERVICE_NAME),
            }
        if action == "sensor_start":
            self.service_manager.start(SENSOR_SERVICE_NAME)
            return {"ok": True}
        if action == "sensor_stop":
            self.service_manager.stop(SENSOR_SERVICE_NAME)
            return {"ok": True}
        if action == "sensor_restart":
            self.service_manager.restart(SENSOR_SERVICE_NAME)
            return {"ok": True}
        raise ValueError("Unsupported action.")


def main():
    if sys.platform != "win32":
        raise RuntimeError("The Windows helper can only run on Windows.")
    with WindowsHelperServer() as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
