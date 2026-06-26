import json
import platform
import socket


class ServiceControllerError(RuntimeError):
    pass


class ServiceController:
    def status(self):
        raise NotImplementedError

    def restart(self):
        raise NotImplementedError


class LinuxServiceController(ServiceController):
    SOCKET_PATH = "/run/excalibur/helper.sock"
    SOCKET_TIMEOUT_SECONDS = 5

    def status(self):
        response = self._request({"action": "sensor_status"})
        if not response.get("ok", False):
            raise ServiceControllerError(
                response.get("error", "Sensor status request failed.")
            )
        return response.get("status", "unknown")

    def restart(self):
        response = self._request({"action": "sensor_restart"})
        if not response.get("ok", False):
            raise ServiceControllerError(
                response.get("error", "Sensor restart request failed.")
            )
        return True

    def _request(self, payload):
        request_bytes = (json.dumps(payload) + "\n").encode("utf-8")
        try:
            unix_family = getattr(socket, "AF_UNIX", 1)
            with socket.socket(unix_family, socket.SOCK_STREAM) as client:
                client.settimeout(self.SOCKET_TIMEOUT_SECONDS)
                client.connect(self.SOCKET_PATH)
                client.sendall(request_bytes)
                response_bytes = self._read_response(client)
        except socket.timeout as exc:
            raise ServiceControllerError("Sensor control request timed out.") from exc
        except FileNotFoundError as exc:
            raise ServiceControllerError("Sensor control helper socket is unavailable.") from exc
        except ConnectionRefusedError as exc:
            raise ServiceControllerError("Sensor control helper is not accepting connections.") from exc
        except OSError as exc:
            raise ServiceControllerError(f"Sensor control helper communication failed: {exc}") from exc

        try:
            return json.loads(response_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ServiceControllerError("Sensor control helper returned an invalid response.") from exc

    def _read_response(self, client):
        chunks = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        return b"".join(chunks).strip()


class WindowsServiceController(ServiceController):
    SERVICE_NAME = "ExcaliburSensor"

    def __init__(self, service_manager=None):
        if service_manager is None:
            from excalibur.services.windows_service_manager import WindowsServiceManager

            service_manager = WindowsServiceManager()
        self.service_manager = service_manager

    def status(self):
        try:
            return self.service_manager.status(self.SERVICE_NAME)
        except Exception as exc:
            from excalibur.services.windows_service_manager import (
                WindowsServiceManagerError,
            )

            if isinstance(exc, WindowsServiceManagerError):
                raise ServiceControllerError(str(exc)) from exc
            raise

    def restart(self):
        try:
            return self.service_manager.restart(self.SERVICE_NAME)
        except Exception as exc:
            from excalibur.services.windows_service_manager import (
                WindowsServiceManagerError,
            )

            if isinstance(exc, WindowsServiceManagerError):
                raise ServiceControllerError(str(exc)) from exc
            raise


class UnsupportedServiceController(ServiceController):
    def status(self):
        return "unknown"

    def restart(self):
        raise ServiceControllerError(
            "Sensor restart is not supported on this platform yet."
        )


def create_service_controller():
    system = platform.system().lower()
    if system == "linux":
        return LinuxServiceController()
    if system == "windows":
        return WindowsServiceController()
    return UnsupportedServiceController()
