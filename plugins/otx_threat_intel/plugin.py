import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from excalibur.plugins.base import Plugin


class Plugin(Plugin):
    name = "OTX Threat Intel"
    API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    PAGE_SIZE = 50
    REQUEST_TIMEOUT_SECONDS = 60
    REPO_ROOT = Path(__file__).resolve().parents[2]
    DATA_DIR = REPO_ROOT / "data" / "threat_intel" / "otx"
    INDICATORS_PATH = DATA_DIR / "indicators.jsonl"
    METADATA_PATH = DATA_DIR / "metadata.json"

    def __init__(self):
        self.get_func = requests.get
        self.api_key = os.environ.get("OTX_API_KEY", "").strip()
        self.refresh_hours = self._parse_positive_int(
            os.environ.get("OTX_REFRESH_HOURS"),
            default=24,
        )
        self.max_indicators = self._parse_positive_int(
            os.environ.get("OTX_MAX_INDICATORS"),
            default=100000,
        )
        self.max_pulses = self._parse_positive_int(
            os.environ.get("OTX_MAX_PULSES"),
            default=100,
        )
        self.now_func = lambda: datetime.now(timezone.utc)
        self.ip_indicators = set()
        self.domain_indicators = set()
        self.url_indicators = set()
        self.metadata = self._default_metadata()
        self._last_loaded_count = 0

    def on_load(self):
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.metadata = self._load_metadata()
        self._load_cache_into_memory()

    def on_startup(self):
        self._log_cache_state(self.metadata)

        if not self.api_key:
            self._log_warning("OTX API key not configured; using cached indicators only")
            return

        if not self._should_refresh(self.metadata):
            self._log_info("cached indicators are fresh; skipping OTX refresh")
            return

        try:
            counts = self._refresh_cache()
        except requests.RequestException as exc:
            self._log_warning(f"OTX refresh failed; using cached indicators only: {exc}")
            return
        except ValueError as exc:
            self._log_warning(f"OTX refresh failed; using cached indicators only: {exc}")
            return

        self.metadata = self._load_metadata()
        self._load_cache_into_memory()
        self._log_info(
            "refreshed indicators "
            f"pulses={counts['processed_pulses']} indicators={counts['indicator_count']} "
            f"ips={counts['ip_count']} domains={counts['domain_count']} urls={counts['url_count']}"
        )

    def handle_event(self, event, context):
        self._context = context
        if event.event_type == "packet_event":
            self._handle_packet_event(event)
        elif event.event_type == "dns_event":
            self._handle_dns_event(event)
        elif event.event_type == "alert_event":
            self._handle_alert_event(event)

    def _handle_packet_event(self, event):
        for role, value in (("destination_ip", event.dst_ip), ("source_ip", event.src_ip)):
            ip_value = self._normalize_public_ip(value)
            if ip_value and ip_value in self.ip_indicators:
                self._log_info(
                    f"IOC match type=ip event=packet_event field={role} value={ip_value}"
                )

    def _handle_dns_event(self, event):
        domain = self._normalize_domain(event.query_name)
        if domain and domain in self.domain_indicators:
            self._log_info(
                f"IOC match type=domain event=dns_event field=query_name value={domain}"
            )

    def _handle_alert_event(self, event):
        for role, value in (
            ("destination_ip", event.destination_ip),
            ("source_ip", event.source_ip),
        ):
            ip_value = self._normalize_public_ip(value)
            if ip_value and ip_value in self.ip_indicators:
                self._log_info(
                    f"IOC match type=ip event=alert_event field={role} value={ip_value}"
                )

    def _refresh_cache(self):
        indicators = []
        page = 1
        processed_pulses = 0

        self._log_info(
            f"starting OTX refresh max_pulses={self.max_pulses} max_indicators={self.max_indicators}"
        )

        while processed_pulses < self.max_pulses and len(indicators) < self.max_indicators:
            payload = self._fetch_page(page)
            results = payload.get("results", [])
            if not isinstance(results, list):
                raise ValueError("OTX response missing results list")

            before_count = len(indicators)
            page_pulse_count = 0
            for pulse in results:
                if processed_pulses >= self.max_pulses:
                    break
                indicators.extend(self._indicators_from_pulse(pulse))
                processed_pulses += 1
                page_pulse_count += 1
                if len(indicators) >= self.max_indicators:
                    break

            self._log_info(
                f"refresh progress page={page} pulses_processed={processed_pulses} "
                f"page_pulses={page_pulse_count} indicators_collected={len(indicators)}"
            )

            next_page = payload.get("next")
            if (
                not next_page
                or len(indicators) == before_count
                or processed_pulses >= self.max_pulses
            ):
                break
            page += 1

        indicators = indicators[: self.max_indicators]
        counts = self._write_cache(indicators)
        counts["processed_pulses"] = processed_pulses
        counts["indicator_count"] = len(indicators)
        return counts

    def _fetch_page(self, page):
        response = self.get_func(
            self.API_URL,
            headers={
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json",
            },
            params={
                "limit": self.PAGE_SIZE,
                "page": page,
            },
            timeout=self.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("OTX response is not a JSON object")
        return payload

    def _indicators_from_pulse(self, pulse):
        if not isinstance(pulse, dict):
            return []

        normalized = []
        for indicator in pulse.get("indicators", []):
            normalized_indicator = self._normalize_indicator(indicator)
            if normalized_indicator is not None:
                normalized.append(normalized_indicator)
        return normalized

    def _normalize_indicator(self, indicator):
        if not isinstance(indicator, dict):
            return None

        indicator_type = str(indicator.get("type", "")).strip().lower()
        value = str(indicator.get("indicator", "")).strip()
        if not indicator_type or not value:
            return None

        if indicator_type in {"ipv4", "ipv6"}:
            normalized_ip = self._normalize_public_ip(value)
            if normalized_ip is None:
                return None
            return {"type": "ip", "value": normalized_ip}

        if indicator_type in {"domain", "hostname"}:
            normalized_domain = self._normalize_domain(value)
            if normalized_domain is None:
                return None
            return {"type": "domain", "value": normalized_domain}

        if indicator_type in {"url", "uri"}:
            normalized_url = self._normalize_url(value)
            if normalized_url is None:
                return None
            return {"type": "url", "value": normalized_url}

        return None

    def _load_cache_into_memory(self):
        self.ip_indicators = set()
        self.domain_indicators = set()
        self.url_indicators = set()
        self._last_loaded_count = 0

        if not self.INDICATORS_PATH.exists():
            return

        with self.INDICATORS_PATH.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                indicator_type = entry.get("type")
                value = entry.get("value")
                if indicator_type == "ip" and isinstance(value, str):
                    self.ip_indicators.add(value)
                elif indicator_type == "domain" and isinstance(value, str):
                    self.domain_indicators.add(value)
                elif indicator_type == "url" and isinstance(value, str):
                    self.url_indicators.add(value)

        self._last_loaded_count = (
            len(self.ip_indicators)
            + len(self.domain_indicators)
            + len(self.url_indicators)
        )

    def _write_cache(self, indicators):
        unique_indicators = []
        seen = set()
        counts = {"ip_count": 0, "domain_count": 0, "url_count": 0}

        for indicator in indicators:
            indicator_type = indicator["type"]
            value = indicator["value"]
            key = (indicator_type, value)
            if key in seen:
                continue
            seen.add(key)
            unique_indicators.append(indicator)
            counts[f"{indicator_type}_count"] += 1

        with self.INDICATORS_PATH.open("w", encoding="utf-8") as handle:
            for indicator in unique_indicators:
                handle.write(json.dumps(indicator, sort_keys=True) + "\n")

        metadata = {
            "last_successful_update": self.now_func().isoformat(),
            "indicator_count": len(unique_indicators),
            **counts,
        }
        self.METADATA_PATH.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return counts

    def _load_metadata(self):
        if not self.METADATA_PATH.exists():
            return self._default_metadata()
        try:
            data = json.loads(self.METADATA_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self._default_metadata()

        metadata = self._default_metadata()
        if isinstance(data, dict):
            metadata.update(
                {
                    "last_successful_update": data.get("last_successful_update"),
                    "indicator_count": int(data.get("indicator_count", 0) or 0),
                    "ip_count": int(data.get("ip_count", 0) or 0),
                    "domain_count": int(data.get("domain_count", 0) or 0),
                    "url_count": int(data.get("url_count", 0) or 0),
                }
            )
        return metadata

    def _should_refresh(self, metadata):
        last_successful_update = metadata.get("last_successful_update")
        if not last_successful_update:
            return True
        try:
            updated_at = datetime.fromisoformat(last_successful_update)
        except ValueError:
            return True
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=timezone.utc)
        return self.now_func() - updated_at >= timedelta(hours=self.refresh_hours)

    def _normalize_public_ip(self, value):
        if not value:
            return None
        try:
            ip_value = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return None
        if ip_value.is_private:
            return None
        if ip_value.is_loopback:
            return None
        if ip_value.is_multicast:
            return None
        if ip_value.is_reserved:
            return None
        if ip_value.is_link_local:
            return None
        return str(ip_value)

    def _normalize_domain(self, value):
        domain = str(value or "").strip().rstrip(".").lower()
        if not domain:
            return None
        if any(character.isspace() for character in domain):
            return None
        return domain

    def _normalize_url(self, value):
        url_value = str(value or "").strip()
        if not url_value:
            return None
        return url_value

    def _default_metadata(self):
        return {
            "last_successful_update": None,
            "indicator_count": 0,
            "ip_count": 0,
            "domain_count": 0,
            "url_count": 0,
        }

    def _parse_positive_int(self, value, default):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed > 0 else default

    def _log_cache_state(self, metadata):
        last_update = metadata.get("last_successful_update") or "never"
        self._log_info(
            "cache status "
            f"last_update={last_update} "
            f"ips={len(self.ip_indicators)} "
            f"domains={len(self.domain_indicators)} "
            f"urls={len(self.url_indicators)}"
        )

    def _log_info(self, message):
        if hasattr(self, "_context"):
            self._context.logger.info(message)
        else:
            print(f"[PLUGIN] {self.name} {message}", flush=True)

    def _log_warning(self, message):
        if hasattr(self, "_context"):
            self._context.logger.warning(message)
        else:
            print(f"[PLUGIN] {self.name} {message}", flush=True)
