import os
import pwd
import subprocess


class PolicyKitError(RuntimeError):
    pass


class PolicyKitAuthorizer:
    PKCHECK_PATH = "/usr/bin/pkcheck"
    COMMAND_TIMEOUT_SECONDS = 15
    TRUSTED_SERVICE_USER = "excalibur"
    ACTION_IDS = {
        "sensor_start": "org.excalibur.sensor.start",
        "sensor_stop": "org.excalibur.sensor.stop",
        "sensor_restart": "org.excalibur.sensor.restart",
    }

    def __init__(self, trusted_service_uid=None):
        self.trusted_service_uid = (
            trusted_service_uid
            if trusted_service_uid is not None
            else pwd.getpwnam(self.TRUSTED_SERVICE_USER).pw_uid
        )

    def authorize(self, action, peer_pid, peer_uid):
        if action == "sensor_status":
            return True
        if peer_uid == self.trusted_service_uid:
            return True

        action_id = self.ACTION_IDS.get(action)
        if action_id is None:
            raise PolicyKitError("Unsupported PolicyKit action.")

        process_spec = f"{peer_pid},{self._process_start_ticks(peer_pid)},{peer_uid}"
        try:
            result = subprocess.run(
                [
                    self.PKCHECK_PATH,
                    "--action-id",
                    action_id,
                    "--process",
                    process_spec,
                    "--allow-user-interaction",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise PolicyKitError("Authentication request timed out.") from exc
        except FileNotFoundError as exc:
            raise PolicyKitError("PolicyKit check helper is unavailable.") from exc
        except OSError as exc:
            raise PolicyKitError(f"Unexpected PolicyKit failure: {exc}") from exc

        if result.returncode == 0:
            return True

        output = (result.stderr or result.stdout or "").strip()
        lowered = output.lower()
        if "dismissed" in lowered or "cancel" in lowered:
            raise PolicyKitError("Authentication was cancelled.")
        if "not authorized" in lowered or "authorization failed" in lowered:
            raise PolicyKitError("Authentication was denied.")
        if "no authentication agent found" in lowered:
            raise PolicyKitError("No PolicyKit authentication agent is available.")
        raise PolicyKitError(output or "PolicyKit authorization failed.")

    def _process_start_ticks(self, pid):
        stat_path = f"/proc/{pid}/stat"
        try:
            with open(stat_path, "r", encoding="utf-8") as handle:
                stat_data = handle.read().strip()
        except OSError as exc:
            raise PolicyKitError(
                f"Unable to read process metadata for PolicyKit authorization: {exc}"
            ) from exc

        try:
            after_comm = stat_data.rsplit(") ", 1)[1]
            fields = after_comm.split()
            return fields[19]
        except (IndexError, ValueError) as exc:
            raise PolicyKitError(
                "Unable to parse process metadata for PolicyKit authorization."
            ) from exc
