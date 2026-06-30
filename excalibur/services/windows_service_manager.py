import subprocess


class WindowsServiceManagerError(RuntimeError):
    pass


class WindowsServiceManager:
    POWERSHELL_PATH = "powershell.exe"
    COMMAND_TIMEOUT_SECONDS = 15

    def status(self, service_name):
        script = (
            f"$service = Get-Service -Name '{self._quote(service_name)}' "
            "-ErrorAction Stop; $service.Status.ToString()"
        )
        result = self._run(script, f"status check for {service_name}")
        status = result.stdout.strip().lower()
        if status == "running":
            return "running"
        if status in {"startpending", "stoppending", "pausepending", "continuepending"}:
            return "starting"
        if status in {"stopped", "paused"}:
            return "stopped"
        return "unknown"

    def start(self, service_name):
        return self._service_action("Start-Service", service_name, "start")

    def stop(self, service_name):
        return self._service_action("Stop-Service", service_name, "stop")

    def restart(self, service_name):
        return self._service_action("Restart-Service", service_name, "restart")

    def _service_action(self, command, service_name, action):
        script = (
            f"{command} -Name '{self._quote(service_name)}' -ErrorAction Stop; "
            f"(Get-Service -Name '{self._quote(service_name)}').Status.ToString()"
        )
        self._run(script, f"{action} of {service_name}")
        return True

    def _run(self, script, description):
        try:
            result = subprocess.run(
                [
                    self.POWERSHELL_PATH,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise WindowsServiceManagerError(f"Service {description} timed out.") from exc
        except FileNotFoundError as exc:
            raise WindowsServiceManagerError("PowerShell is unavailable.") from exc
        except OSError as exc:
            raise WindowsServiceManagerError(
                f"Unexpected service {description} failure: {exc}"
            ) from exc

        if result.returncode != 0:
            output = (result.stderr or result.stdout or "").strip()
            if "cannot find any service" in output.lower():
                raise WindowsServiceManagerError("Service was not found.")
            raise WindowsServiceManagerError(output or f"Service {description} failed.")
        return result

    @staticmethod
    def _quote(value):
        return str(value).replace("'", "''")
