from collections import deque
from datetime import datetime, timedelta, timezone


class RuleDetector:
    def __init__(self, database, rule, global_config=None, own_ips=None):
        self.database = database
        self.rule = rule or {}
        self.global_config = global_config or {}
        self.own_ips = {str(ip).strip() for ip in (own_ips or [])}
        self.excluded_sources = {
            str(source).strip()
            for source in self.global_config.get("excluded_sources", [])
        }
        self.name = self.rule.get("name", self.__class__.__name__)
        self.enabled = bool(self.rule.get("enabled", True))
        self.threshold = int(self.rule.get("threshold", 1))
        self.window_seconds = int(self.rule.get("window_seconds", 60))
        self.window = timedelta(seconds=self.window_seconds)
        self.cooldown = timedelta(seconds=int(self.rule.get("cooldown_seconds", 300)))
        self.severity = self.rule.get("severity", "Medium")
        self._last_alert_by_key = {}

    def _parse_timestamp(self, timestamp):
        if isinstance(timestamp, datetime):
            parsed = timestamp
        elif timestamp:
            parsed = datetime.fromisoformat(str(timestamp))
        else:
            parsed = datetime.now(timezone.utc)

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _prune(self, items, timestamp):
        cutoff = timestamp - self.window
        while items and items[0][0] < cutoff:
            items.popleft()

    def _is_in_cooldown(self, key, timestamp):
        last_alert = self._last_alert_by_key.get(key)
        return last_alert is not None and timestamp - last_alert < self.cooldown

    def _mark_alerted(self, key, timestamp):
        self._last_alert_by_key[key] = timestamp

    def _new_window(self):
        return deque()

    def _is_globally_excluded(self, source_ip):
        return str(source_ip).strip() in self.excluded_sources

    def _is_own_ip(self, source_ip):
        return str(source_ip).strip() in self.own_ips
