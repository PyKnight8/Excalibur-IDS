import os
import socket
import socketserver
import stat
import struct
import sys

if sys.platform == "linux":
    import grp
    import pwd
else:
    grp = None
    pwd = None
    if not hasattr(os, "geteuid"):
        os.geteuid = lambda: -1
    if not hasattr(os, "chown"):
        def _unsupported_chown(*args, **kwargs):
            raise OSError("chown is unavailable on this platform.")

        os.chown = _unsupported_chown

from excalibur.helper.protocol import ProtocolError, decode_request, encode_response
from excalibur.helper.service_ops import ServiceOperations, ServiceOpsError


SOCKET_PATH = "/run/excalibur/helper.sock"
REQUIRED_USER = "excalibur"
REQUIRED_GROUP = "excalibur"
_ThreadingUnixStreamServer = getattr(
    socketserver,
    "ThreadingUnixStreamServer",
    socketserver.ThreadingTCPServer,
)


def _required_uid():
    if pwd is None:
        raise RuntimeError("Unix user lookup is unavailable on this platform.")
    return pwd.getpwnam(REQUIRED_USER).pw_uid


def _required_gid():
    if grp is None:
        raise RuntimeError("Unix group lookup is unavailable on this platform.")
    return grp.getgrnam(REQUIRED_GROUP).gr_gid


class HelperRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        if not self.server.is_authorized_peer(self.request):
            self.wfile.write(
                encode_response({"ok": False, "error": "Unauthorized peer."})
            )
            return

        request_bytes = self.rfile.readline(4097)
        try:
            payload = decode_request(request_bytes)
            response = self.server.dispatch(payload["action"])
        except ProtocolError as exc:
            response = {"ok": False, "error": str(exc)}
        except ServiceOpsError as exc:
            response = {"ok": False, "error": str(exc)}
        except Exception as exc:
            response = {"ok": False, "error": f"Unexpected helper failure: {exc}"}
        self.wfile.write(encode_response(response))


class HelperServer(_ThreadingUnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, service_operations=None):
        self.service_operations = service_operations or ServiceOperations()
        self.allowed_uid = _required_uid()
        self.allowed_gid = _required_gid()
        super().__init__(server_address, handler_class)
        os.chown(server_address, 0, self.allowed_gid)
        os.chmod(server_address, 0o660)

    def is_authorized_peer(self, connection):
        pid, uid, gid = self.get_peer_credentials(connection)
        return uid == self.allowed_uid

    def get_peer_credentials(self, connection):
        creds = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        return struct.unpack("3i", creds)

    def server_close(self):
        try:
            if self.server_address and os.path.exists(self.server_address):
                os.unlink(self.server_address)
        finally:
            super().server_close()

    def dispatch(self, action):
        if action == "sensor_status":
            return {"ok": True, "status": self.service_operations.sensor_status()}
        if action == "sensor_restart":
            self.service_operations.sensor_restart()
            return {"ok": True}
        raise ProtocolError("Unsupported action.")


def main():
    if sys.platform != "linux":
        raise RuntimeError("Excalibur helper is supported on Linux only.")
    if os.geteuid() != 0:
        raise RuntimeError("Excalibur helper must run as root.")
    runtime_dir = os.path.dirname(SOCKET_PATH)
    os.makedirs(runtime_dir, mode=0o750, exist_ok=True)
    os.chown(runtime_dir, 0, _required_gid())
    os.chmod(runtime_dir, 0o750)
    if os.path.exists(SOCKET_PATH):
        socket_stat = os.stat(SOCKET_PATH)
        if not stat.S_ISSOCK(socket_stat.st_mode):
            raise RuntimeError(
                f"Refusing to unlink non-socket path: {SOCKET_PATH}"
            )
        os.unlink(SOCKET_PATH)
    with HelperServer(SOCKET_PATH, HelperRequestHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
