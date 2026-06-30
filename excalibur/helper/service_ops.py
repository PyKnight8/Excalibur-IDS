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
        if output == "inactive":
            return "stopped"
        if output in {"activating", "deactivating", "reloading"}:
            return "starting"
        if output == "failed":
            return "error"
        if "could not be found" in output or "not found" in output:
            raise ServiceOpsError("Sensor service was not found.")
        return "unknown"

    def sensor_start(self):
        return self._run_action("start", "Sensor start")

    def sensor_stop(self):
        return self._run_action("stop", "Sensor stop")

    def sensor_restart(self):
        return self._run_action("restart", "Sensor restart")

    def _run_action(self, action, description):
        try:
            result = subprocess.run(
                [
                    self.SYSTEMCTL_PATH,
                    action,
                    self.SERVICE_NAME,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise ServiceOpsError(f"{description} timed out.") from exc
        except FileNotFoundError as exc:
            raise ServiceOpsError("systemctl is unavailable on this system.") from exc
        except OSError as exc:
            raise ServiceOpsError(f"Unexpected {description.lower()} failure: {exc}") from exc

        if result.returncode == 0:
            return True

        output = (result.stderr or result.stdout or "").strip()
        lowered = output.lower()
        if "could not be found" in lowered or "not found" in lowered:
            raise ServiceOpsError("Sensor service was not found.")
        raise ServiceOpsError(output or f"{description} failed.")
