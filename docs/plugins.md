# Excalibur Plugin Development Guide

Excalibur includes a lightweight in-process plugin framework for extending the sensor without modifying the core detector pipeline.

This document describes the plugin system that is implemented today. It does not describe the original Phase 4 design in the abstract. If the code and this guide ever disagree, the code is the source of truth.

Environment-variable based settings for Excalibur core and official plugins are
documented in [.env.example](../.env.example).
Excalibur automatically loads a repository-root `.env` file at startup for both
the sniffer and dashboard processes, without overriding already-set
environment variables.

## Overview

The current plugin framework is intentionally small:

- Plugins are local Python code.
- Plugins are discovered from `plugins/`.
- Plugins are loaded at sensor startup.
- Plugins receive events through a synchronous event bus.
- Plugins can log messages and emit additional events.
- Plugin enable or disable state is controlled by `plugin.yaml`.

Current built-in event flow looks like this:

```text
Packet -> existing packet handling -> PacketEvent -> EventBus -> Plugins
DNS    -> existing DNS handling    -> DnsEvent    -> EventBus -> Plugins
Alert  -> existing alert creation  -> AlertEvent  -> EventBus -> Plugins
```

The plugin layer is additive. Existing detector behavior, ERL behavior, dashboard behavior, and database behavior continue to run independently.

## Plugin Directory Structure

Each plugin lives in its own subdirectory under `plugins/`.

Example:

```text
plugins/
├── abuseipdb/
│   ├── plugin.yaml
│   └── plugin.py
├── alert_logger/
│   ├── plugin.yaml
│   └── plugin.py
└── hello_world/
    ├── plugin.yaml
    └── plugin.py
```

Notes:

- Excalibur looks for plugins in `plugins/` relative to the directory that contains `config.yaml`.
- Each plugin directory is expected to contain `plugin.yaml`.
- The Python entrypoint file is defined by `entrypoint:` in `plugin.yaml`.

## `plugin.yaml` Fields

The current loader expects a flat metadata file with top-level `key: value` pairs.

Required fields:

- `name`
- `id`
- `version`
- `entrypoint`

Supported optional fields:

- `author`
- `description`
- `enabled`

Example:

```yaml
name: AbuseIPDB
id: abuseipdb
version: 1.0.0
author: Excalibur
description: Looks up public alert IPs in AbuseIPDB and logs the response.
entrypoint: plugin.py
enabled: true
```

Current parser behavior:

- `true` and `false` are parsed as booleans.
- Single-quoted and double-quoted strings are supported.
- The file is parsed as simple line-based metadata, not full YAML.
- Nested objects and lists are not supported by the plugin loader today.

## Plugin Lifecycle

Plugins inherit from [excalibur/plugins/base.py](../excalibur/plugins/base.py):

```python
class Plugin:
    name = "Unnamed"

    def on_load(self):
        pass

    def on_startup(self):
        pass

    def on_shutdown(self):
        pass

    def handle_event(self, event, context):
        pass
```

### `on_load()`

Called once after:

1. the plugin module is imported
2. the `Plugin` class is instantiated
3. the plugin context is created

Use this for lightweight initialization.

### `on_startup()`

Called after all enabled plugins have been loaded and registered with the event bus.

Use this for startup actions that should happen when the sensor begins running.

### `on_shutdown()`

Called when Excalibur shuts down.

Use this for cleanup work.

### `handle_event(self, event, context)`

Called whenever the event bus delivers an event to the plugin.

Today, the plugin manager registers each loaded plugin with a wildcard subscription (`"*"`), so every loaded plugin receives every emitted event. Filtering is the plugin’s responsibility.

Example:

```python
from excalibur.plugins.base import Plugin


class Plugin(Plugin):
    name = "Alert Logger"

    def handle_event(self, event, context):
        if event.event_type != "alert_event":
            return
        context.logger.info(f"received alert_event for alert #{event.alert_id}")
```

## PluginContext API

Plugins receive a `PluginContext` object from [excalibur/plugins/context.py](../excalibur/plugins/context.py).

Current API:

- `context.logger.info(message)`
- `context.logger.warning(message)`
- `context.logger.error(message)`
- `context.emit_event(event)`

### Logger Methods

The logger writes directly to stdout with a `[PLUGIN]` prefix.

Example:

```python
context.logger.info("received alert_event")
```

Output:

```text
[PLUGIN] My Plugin received alert_event
```

### `emit_event()`

Plugins can emit additional events back into the event bus:

```python
context.emit_event(event)
```

This is synchronous and immediate. There is no queue, no worker thread, and no background dispatcher in the current implementation.

## EventBus Behavior

The event bus is implemented in [excalibur/plugins/event_bus.py](../excalibur/plugins/event_bus.py).

Current behavior:

- synchronous
- in-process
- multiple subscribers per event type
- supports exact event type subscriptions and wildcard `*`
- exceptions in one subscriber do not stop delivery to others

Example API:

```python
event_bus.subscribe("alert_event", callback)
event_bus.emit(event)
```

If a handler fails, Excalibur logs the failure and continues:

```text
[PLUGIN] Event handler '<callback>' failed for alert_event: <error>
```

A traceback is also printed.

## Event Types Available Today

The framework currently ships with these concrete event classes:

- `PacketEvent`
- `DnsEvent`
- `AlertEvent`
- `HostEvent` placeholder

### BaseEvent

All events inherit from `BaseEvent`:

```python
event.event_type
event.timestamp
```

### PacketEvent

From [excalibur/events/packet.py](../excalibur/events/packet.py):

- `event.event_type == "packet_event"`
- `timestamp`
- `src_ip`
- `dst_ip`
- `protocol`
- `src_port`
- `dst_port`
- `packet_size`
- `src_mac`
- `tcp_flags`

### DnsEvent

From [excalibur/events/dns.py](../excalibur/events/dns.py):

- `event.event_type == "dns_event"`
- `timestamp`
- `client_ip`
- `dns_server_ip`
- `query_name`
- `query_type`
- `dns_rcode`
- `risk_score`
- `risk_level`
- `risk_reasons`

### AlertEvent

From [excalibur/events/alert.py](../excalibur/events/alert.py):

- `event.event_type == "alert_event"`
- `timestamp`
- `alert_id`
- `title`
- `severity`
- `description`
- `source_ip`
- `destination_ip`
- `context_json`

`AlertEvent` is emitted after successful alert creation.

## How Plugins Are Loaded at Sensor Startup

Plugin startup happens in [excalibur/main.py](../excalibur/main.py).

At startup Excalibur:

1. creates the database
2. creates the event bus
3. attaches the event bus to the database
4. creates `PluginManager(event_bus, plugins_dir)`
5. calls `plugin_manager.load_plugins()`
6. calls `plugin_manager.startup_plugins()`
7. starts the packet sniffer

This means:

- plugins are loaded only when the sensor process starts
- dashboard enable or disable changes do not take effect until the sensor is restarted
- there is no hot reload today

## Plugin Discovery and Loading Process

The loader is implemented in [excalibur/plugins/manager.py](../excalibur/plugins/manager.py).

Discovery process:

1. read the configured `plugins/` directory
2. iterate immediate subdirectories
3. look for `plugin.yaml`
4. parse metadata
5. validate required fields
6. skip plugins with `enabled: false`
7. resolve the `entrypoint` path inside the plugin directory
8. import the module dynamically
9. locate the `Plugin` class in the module
10. instantiate it
11. call `on_load()`
12. register `handle_event()` on the wildcard event bus subscription
13. later call `on_startup()`

Important current details:

- the module must define a class named `Plugin`
- that class must inherit from `excalibur.plugins.base.Plugin`
- duplicate plugin IDs are not supported
- disabled plugins are skipped before import

Typical successful logs:

```text
[PLUGIN] Loaded plugin 'Hello World'
[PLUGIN] Registered plugin 'Hello World'
```

Typical failure logs:

```text
[PLUGIN] Skipping plugin at '/path/to/plugin': missing plugin.yaml
[PLUGIN] Skipping plugin at '/path/to/plugin': missing version
[PLUGIN] Skipping plugin 'My Plugin': invalid entrypoint
[PLUGIN] Failed to load plugin 'My Plugin': plugin.py must define a Plugin class
[PLUGIN] Startup failed for plugin 'My Plugin': <error>
[PLUGIN] Shutdown failed for plugin 'My Plugin': <error>
```

## Plugin Enable / Disable Behavior

Enable state is controlled exclusively by `enabled:` in `plugin.yaml`.

Example:

```yaml
enabled: true
```

or:

```yaml
enabled: false
```

Current behavior:

- `enabled: false` means the plugin is skipped and never imported
- `enabled: true` means the plugin is eligible for loading
- the dashboard changes only this field
- other metadata and plugin code are not modified

Changes require a sensor restart to take effect.

## Dashboard Plugin Management Workflow

Excalibur includes a lightweight Plugins page in the dashboard.

Current workflow:

1. open `Plugins` from the sidebar
2. view discovered plugins from `plugins/`
3. inspect:
   - Name
   - ID
   - Version
   - Author
   - Description
   - Enabled or Disabled
4. click `Enable` or `Disable`
5. Excalibur updates only the `enabled:` field in that plugin’s `plugin.yaml`
6. the page shows:

```text
Plugin updated. Restart sensor for changes to take effect.
```

7. click `Restart Sensor`

The Plugins page reuses the existing sensor control endpoints:

- `GET /sensor/status`
- `POST /sensor/restart`

It does not perform hot reload.

## Build Your First Plugin

This example builds a minimal plugin that logs every alert title.

### 1. Create the plugin directory

```text
plugins/
└── alert_printer/
    ├── plugin.yaml
    └── plugin.py
```

### 2. Create `plugin.yaml`

```yaml
name: Alert Printer
id: alert_printer
version: 1.0.0
author: Your Name
description: Logs alert titles when alerts are created.
entrypoint: plugin.py
enabled: true
```

### 3. Create `plugin.py`

```python
from excalibur.plugins.base import Plugin


class Plugin(Plugin):
    name = "Alert Printer"

    def on_load(self):
        pass

    def on_startup(self):
        pass

    def on_shutdown(self):
        pass

    def handle_event(self, event, context):
        if event.event_type != "alert_event":
            return
        context.logger.info(
            f"alert #{event.alert_id} severity={event.severity} title={event.title}"
        )
```

### 4. Restart the sensor

Plugins are loaded only at sensor startup, so restart the sensor after adding the plugin.

### 5. Trigger an alert

Once Excalibur creates an alert, the plugin should log something like:

```text
[PLUGIN] Alert Printer alert #12 severity=High title=SMB Recon Activity
```

## Example Walkthrough: AbuseIPDB Plugin

The AbuseIPDB proof-of-concept plugin is a good example of how to build a real plugin without changing the framework.

Source:

- [plugins/abuseipdb/plugin.yaml](../plugins/abuseipdb/plugin.yaml)
- [plugins/abuseipdb/plugin.py](../plugins/abuseipdb/plugin.py)

### What it does

- ignores every event except `alert_event`
- selects an IP for lookup
  - prefers `destination_ip`
  - falls back to `source_ip`
- ignores private, loopback, multicast, reserved, and link-local addresses
- queries AbuseIPDB using `requests.get(...)`
- logs:
  - IP
  - `abuseConfidenceScore`
  - `totalReports`

### Key pattern

```python
def handle_event(self, event, context):
    if event.event_type != "alert_event":
        return
```

This is the standard pattern in the current framework because all plugins receive wildcard event delivery.

### API key handling

The AbuseIPDB plugin currently reads its API key from:

```text
ABUSEIPDB_API_KEY
```

If the key is missing, it logs:

```text
[PLUGIN] AbuseIPDB skipping AbuseIPDB lookup because ABUSEIPDB_API_KEY is not set
```

### Successful log example

```text
[PLUGIN] AbuseIPDB lookup 8.8.8.8 abuseConfidenceScore=42 totalReports=7
```

### Failure log examples

```text
[PLUGIN] AbuseIPDB AbuseIPDB lookup failed for 8.8.8.8: network unavailable
[PLUGIN] AbuseIPDB AbuseIPDB response parsing failed for 8.8.8.8: missing data object
```

## Code Examples

### Minimal event logger

```python
from excalibur.plugins.base import Plugin


class Plugin(Plugin):
    name = "Hello World"

    def handle_event(self, event, context):
        context.logger.info(f"received {event.event_type}")
```

### Emitting a custom event

The current framework allows plugins to emit events, although there is not yet a formal custom event schema.

```python
from excalibur.events.base import BaseEvent
from excalibur.plugins.base import Plugin


class Plugin(Plugin):
    name = "Emitter"

    def handle_event(self, event, context):
        if event.event_type != "alert_event":
            return
        context.emit_event(
            BaseEvent(event_type="custom_event")
        )
```

This works today, but keep in mind the current framework does not provide validation or registration for custom event types.

## Troubleshooting

### Plugin does not appear in the dashboard

Check:

- the plugin directory exists under `plugins/`
- `plugin.yaml` exists
- `plugin.yaml` contains a valid `id`
- the dashboard is reading the same `config.yaml` location as the sensor

### Plugin appears in the dashboard but does not run

Check:

- `enabled: true` is set in `plugin.yaml`
- the sensor has been restarted since the last toggle
- the plugin entrypoint exists and matches `entrypoint:`

### Plugin is enabled but never logs anything

Check:

- the plugin filters for the right `event.event_type`
- Excalibur is currently emitting that event type
- the conditions that should produce the event have actually happened

### Plugin fails to load

Expected loader messages include:

```text
[PLUGIN] Skipping plugin 'My Plugin': invalid entrypoint
[PLUGIN] Failed to load plugin 'My Plugin': plugin.py must define a Plugin class
```

Common causes:

- `entrypoint` points outside the plugin directory
- entrypoint file does not exist
- module does not define `Plugin`
- `Plugin` does not inherit from the base class

### Plugin crashes while handling an event

The event bus catches the exception and keeps going. You should see a log like:

```text
[PLUGIN] Event handler '<callback>' failed for alert_event: <error>
```

Other subscribers continue receiving the event.

### AbuseIPDB plugin never performs lookups

Check:

- `ABUSEIPDB_API_KEY` is set in the environment
- the chosen IP is public
- network access to `https://api.abuseipdb.com/api/v2/check` works

## Security Model

Plugins are trusted code.

Installing a plugin is equivalent to running third-party Python inside the Excalibur sensor process on the host.

This means:

- plugins can execute arbitrary Python
- plugins are not sandboxed
- plugins are not isolated in separate processes
- there is no permission model
- there is no signature verification
- there is no plugin marketplace
- there is no automatic download

Only install plugins you trust.

## Current Limitations

The implemented framework is intentionally minimal. Current limitations include:

- all loaded plugins receive wildcard event delivery
- plugins must filter event types themselves
- no async execution
- no thread pool
- no queueing
- no rate limiting
- no plugin-specific configuration UI
- no plugin storage API
- no database helpers in `PluginContext`
- no plugin sandboxing
- no dependency isolation
- no hot reload
- no runtime unload
- no plugin upload from the dashboard
- no plugin deletion from the dashboard
- no plugin editing from the dashboard
- no formal custom event schema registry
- no enrichment event persistence
- plugin metadata parsing supports only simple flat `key: value` files

## Practical Recommendations

- Keep plugin code small and defensive.
- Always filter on `event.event_type`.
- Catch and handle external API failures inside the plugin.
- Use `context.logger` for operational visibility.
- Treat `enabled:` changes as pending until the sensor is restarted.
- Use the dashboard Plugins page only for enable or disable operations, not as a deployment mechanism.
