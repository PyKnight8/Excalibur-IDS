# Excalibur

Lightweight IDS written in Python.

## Features

- Local packet and DNS visibility with SQLite-backed dashboard storage.
- User-defined ERL rule packs for metadata-based behavioral detections.
- TCP Flag Awareness: ERL supports TCP flag matching through the `tcp_flags`
  field. Rules can detect SYN scans, connection anomalies, reset storms, and
  other TCP behaviors. Port scan detections use SYN-only connection attempts to
  reduce false positives from established TCP sessions.
- DNS Response Code Awareness: ERL supports DNS response-code matching through
  the `dns_rcode` field. Rules can detect NXDOMAIN bursts, failed DGA lookups,
  resolver failures, refused responses, and other DNS failure behaviors.
- Offline dashboard assets: Monaco Editor and Bootstrap are bundled locally with
  the dashboard, so YAML highlighting, completions, snippets, formatting,
  validation, saving, and core UI behavior work without internet access.

## Configuration

The SQLite database path is configured in `config.yaml`:

```yaml
database:
  path: excalibur.sqlite
```

`database.path` accepts either a relative path or an absolute path. If the
setting is missing, Excalibur defaults to `excalibur.sqlite`.

Environment-variable based settings for Excalibur core and official plugins are
documented in [.env.example](/home/ibrahim/Tools/Coding/Excalibur/.env.example:1).
This is the canonical list of currently supported environment variables.
Excalibur now automatically loads a repository-root `.env` file at startup for
both the sniffer and dashboard processes. Existing environment variables still
win over values from `.env`.

## Storage Behavior

Excalibur uses SQLite in WAL mode to support concurrent sensor writes and
dashboard reads during live capture.

Dashboard read telemetry in `system_metrics` is best-effort. If the database is
temporarily locked by an active writer, Excalibur skips that telemetry update
instead of failing the dashboard request.

## System Health

The `/system` page includes live Excalibur process metrics collected with
`psutil` on both Linux and Windows. It reports CPU usage, RSS memory usage,
memory percent, thread count, and process uptime for the running sensor process
to help diagnose host-specific performance issues. CPU usage is shown both as a
logical-CPU-normalized value intended to align with Task Manager/System Monitor
and as the raw per-process `psutil.Process.cpu_percent()` value for debugging.

The System Health page also keeps a lightweight in-memory history buffer for the
last 5 minutes of CPU, RSS memory, packets per second, DNS queries per second,
and alerts per second. Samples are taken every 5 seconds, are never written to
SQLite, and reset when the sensor or dashboard process restarts.

These process metrics and graphs refresh automatically from the existing System
Health page without requiring a manual browser reload.

## System Tray

Excalibur also includes an optional cross-platform tray app for Windows and
Linux. It can open the dashboard and start, stop, restart, or inspect the
sensor without opening a terminal. The tray app is not required for Excalibur
operation and is intended only for desktop use. See
[System Tray](docs/system-tray.md).

Desktop installations now enable the tray automatically:

- Windows installs add the tray to the current user's Startup folder and launch
  it immediately.
- Linux desktop installs detect a graphical environment, create
  `~/.config/autostart/excalibur-tray.desktop`, and launch the tray
  immediately when installation occurs inside an active session.
- Linux tray backend selection is automatic: Wayland prefers a native
  StatusNotifier/AppIndicator path, while X11 preserves the existing `pystray`
  behavior.
- Linux tray start/stop/restart actions use PolicyKit authentication through
  the root helper. Status checks remain read-only and do not require
  authentication.
- Linux headless or server installs skip tray setup automatically without
  affecting services.

## Alert Relay

Excalibur remains local-first. Alerts are still written to SQLite and managed
from the dashboard even if outbound notifications fail.

Optional outbound alert relay settings also live in `config.yaml`:

```yaml
notifications:
  enabled: false
  desktop:
    enabled: false
  ntfy:
    enabled: false
    url: "http://ntfyServer:5002/Excalibur-Relay-Notifications"
    timeout_seconds: 5
```

When enabled, Excalibur fans out each new alert to every enabled provider.
Native desktop notifications and NTFY relay notifications are configured
independently, and failure in one provider does not stop delivery to the
others. Failures are non-fatal: the sensor keeps running and alert storage
still completes locally. The Settings page can save both providers and send a
test notification using the current saved config.

## Detection Rules

Detection settings live in `rules.yaml`. The dashboard Settings page includes a
rules editor for this file. YAML is validated before saving, and edits are
limited to `rules.yaml`; restart the sensor for rule changes to fully apply.
The Rules Editor uses the locally bundled Monaco Editor distribution under
`excalibur/dashboard/static/vendor/monaco/`, and shared dashboard Bootstrap
assets are served from `excalibur/dashboard/static/vendor/bootstrap/`; no CDN or
internet access is required for the editor experience.

On Linux, the Rules page can also show sensor status and request a sensor
restart through the dedicated root helper socket at
`/run/excalibur/helper.sock`, which only exposes status and restart controls for
`excalibur-sniffer.service`.

User-defined ERL signatures are organized as rule packs under `rules/`.
`rules/*.yaml` is the only supported ERL rule source. If a legacy
`signatures.yaml` file is present and contains rules, sensor startup fails until
those rules are migrated into rule packs and the legacy file is removed. See
[ERL signature documentation](docs/signatures.md) for the complete YAML
signature reference and examples.

Browser Threat Protection v0.1 adds passive DNS/domain-risk analysis using
existing DNS visibility. It scores suspicious browser-related domains locally,
stores results in SQLite, exposes them on `/browser` and `/domain-risk`, and
adds browser-focused ERL rules in `rules/browser.yaml`. See
[Browser Threat Protection](docs/browser_threats.md) for configuration, scoring,
and limitations.

By default, `global.exclude_own_ips` is enabled. At startup Excalibur discovers
local interface IP addresses and suppresses Port Scan and Host Sweep alerts
where the source IP is the Excalibur machine itself. This avoids false positives
from local browser, scanner, or dashboard activity.

Manual source exclusions can be configured in `rules.yaml`:

```yaml
global:
  excluded_sources:
    - 192.168.x.x # Example
```

These exact IP exclusions suppress alerts only. They do not stop packet capture,
traffic storage, DNS logging, host discovery, or dashboard visibility.

## Alert Management

The Alerts page supports:

- exporting alerts as CSV or JSON
- deleting one alert
- clearing all alerts
- opening an Alert Investigation View for each alert

Alert deletion only removes rows from the `alerts` table. It does not delete
traffic, DNS queries, domains, or hosts.

The Alert Investigation View shows:

- alert metadata such as severity, time, source, and destination
- a rule snapshot captured at alert creation time, including rule name, pack,
  tags, and event type when available
- evidence explaining why the alert fired, such as observed counts, thresholds,
  and window
- related activity for the same source IP, limited to recent alerts, DNS
  queries, and traffic records
