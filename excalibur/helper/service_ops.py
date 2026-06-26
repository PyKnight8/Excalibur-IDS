import subprocess


class ServiceOpsError(RuntimeError):
    pass


class ServiceOperations:
    SYSTEMCTL_PATH = "/bin/systemctl"
    SERVICE_NAME = "excalibur-sniffer.service"
    COMMAND_TIMEOUT_SECONDS = 5

    def sensor_status(self):
        try:
            result = subprocess.run(
                [
                    self.SYSTEMCTL_PATH,
                    "is-active",
                    self.SERVICE_NAME,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise ServiceOpsError("Sensor status check timed out.") from exc
        except FileNotFoundError as exc:
            raise ServiceOpsError("systemctl is unavailable on this system.") from exc
        except OSError as exc:
            raise ServiceOpsError(f"Unexpected sensor status failure: {exc}") from exc

        output = (result.stdout or result.stderr or "").strip().lower()
        if result.returncode == 0 and output == "active":
            return "running"
        if output in {"inactive", "failed", "activating", "deactivating"}:
            return "stopped"
        if "could not be found" in output or "not found" in output:
            raise ServiceOpsError("Sensor service was not found.")
        return "unknown"

    def sensor_restart(self):
        try:
            result = subprocess.run(
                [
                    self.SYSTEMCTL_PATH,
                    "restart",
                    self.SERVICE_NAME,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise ServiceOpsError("Sensor restart timed out.") from exc
        except FileNotFoundError as exc:
            raise ServiceOpsError("systemctl is unavailable on this system.") from exc
        except OSError as exc:
            raise ServiceOpsError(f"Unexpected sensor restart failure: {exc}") from exc

        if result.returncode == 0:
            return True

        output = (result.stderr or result.stdout or "").strip()
        lowered = output.lower()
        if "could not be found" in lowered or "not found" in lowered:
            raise ServiceOpsError("Sensor service was not found.")
        raise ServiceOpsError(output or "Sensor restart failed.")
