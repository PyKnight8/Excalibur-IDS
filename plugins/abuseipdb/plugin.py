import ipaddress
import os

import requests

from excalibur.plugins.base import Plugin


class Plugin(Plugin):
    name = "AbuseIPDB"
    API_URL = "https://api.abuseipdb.com/api/v2/check"
    API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
    TIMEOUT_SECONDS = 5

    def __init__(self):
        self.get_func = requests.get

    def handle_event(self, event, context):
        if event.event_type != "alert_event":
            return

        lookup_ip = self._select_lookup_ip(event)
        if lookup_ip is None:
            return

        if not self.API_KEY:
            context.logger.warning("skipping AbuseIPDB lookup because ABUSEIPDB_API_KEY is not set")
            return

        try:
            result = self._lookup_ip(lookup_ip)
        except requests.RequestException as exc:
            context.logger.warning(f"AbuseIPDB lookup failed for {lookup_ip}: {exc}")
            return
        except ValueError as exc:
            context.logger.warning(f"AbuseIPDB response parsing failed for {lookup_ip}: {exc}")
            return

        context.logger.info(
            f"lookup {lookup_ip} abuseConfidenceScore={result['abuseConfidenceScore']} "
            f"totalReports={result['totalReports']}"
        )

    def _select_lookup_ip(self, event):
        for candidate in (event.destination_ip, event.source_ip):
            if self._is_public_ip(candidate):
                return candidate
        return None

    def _is_public_ip(self, value):
        if not value:
            return False

        try:
            ip_obj = ipaddress.ip_address(value)
        except ValueError:
            return False

        if ip_obj.is_private:
            return False
        if ip_obj.is_loopback:
            return False
        if ip_obj.is_multicast:
            return False
        if ip_obj.is_reserved:
            return False
        if ip_obj.is_link_local:
            return False
        return True

    def _lookup_ip(self, ip_address):
        response = self.get_func(
            self.API_URL,
            headers={
                "Key": self.API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
            },
            timeout=self.TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("missing data object")
        return {
            "abuseConfidenceScore": int(data.get("abuseConfidenceScore", 0)),
            "totalReports": int(data.get("totalReports", 0)),
        }

