# OTX Threat Intel Plugin

The `otx_threat_intel` plugin is an optional Excalibur plugin that downloads public indicators of compromise from AlienVault OTX, stores them locally, loads them into memory, and performs local IOC matching against Excalibur events.

It is designed to behave like a lightweight local IOC matcher, not a full threat-intelligence platform.

## What It Does

On sensor startup the plugin:

1. reads the local OTX cache metadata
2. loads cached indicators into memory
3. checks whether the cache is older than the configured refresh interval
4. refreshes from OTX if needed
5. keeps stale cached indicators if refresh fails

At runtime the plugin:

- compares `packet_event` source and destination IPs against cached malicious IPs
- compares `dns_event` query names against cached malicious domains
- compares `alert_event` source and destination IPs as a fallback
- logs matches locally

It does not:

- call OTX per packet
- call OTX per DNS query
- call OTX per alert
- write to the Excalibur database
- create dashboard UI

## Files

```text
plugins/otx_threat_intel/
├── plugin.yaml
├── plugin.py
└── README.md
```

## Environment Variables

The plugin reads configuration from environment variables:

```text
# AlienVault OTX
OTX_API_KEY=
OTX_MAX_PULSES=100
OTX_REFRESH_HOURS=24
OTX_MAX_INDICATORS=100000
```

The repository root [.env.example](/home/ibrahim/Tools/Coding/Excalibur/.env.example:1)
is the canonical list of currently supported Excalibur environment variables.
Excalibur automatically loads a repository-root `.env` file at startup for both
the sniffer and dashboard processes.

Current behavior:

- `OTX_API_KEY`
  - optional but required for refresh
  - if missing, the plugin loads cached indicators only
- `OTX_REFRESH_HOURS`
  - defaults to `24`
- `OTX_MAX_PULSES`
  - defaults to `100`
  - only the most recent pulses are processed during refresh
- `OTX_MAX_INDICATORS`
  - defaults to `100000`

The plugin never logs the API key.

## No API Key Configured

If no API key is present, startup still succeeds.

Expected log message:

```text
[PLUGIN] OTX Threat Intel OTX API key not configured; using cached indicators only
```

Behavior:

- cached indicators are loaded if available
- no refresh is attempted
- the plugin continues running with zero indicators if no cache exists

## Obtaining an AlienVault OTX API Key

1. Create or sign in to an AlienVault OTX account.
2. Locate your API key in the OTX account or API settings area.
3. Provide it to the Excalibur sensor through environment variables.

Do not place the API key directly into plugin source code.

## Deployment Guidance

Excalibur’s current Linux deployment uses systemd services created by `setup.sh`.

For development or simple local deployments, placing these values in the
repository-root `.env` file is sufficient.

For production systemd deployments, the simplest production-safe approach is to
add the OTX variables to the sensor service environment through a systemd
override.

Example:

```bash
sudo systemctl edit excalibur-sniffer.service
```

Add:

```ini
[Service]
Environment="OTX_API_KEY=your_otx_api_key"
Environment="OTX_MAX_PULSES=100"
Environment="OTX_REFRESH_HOURS=24"
Environment="OTX_MAX_INDICATORS=100000"
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart excalibur-sniffer.service
```

If you prefer an environment file, you can use a systemd drop-in that adds:

```ini
[Service]
EnvironmentFile=/etc/excalibur/excalibur.env
```

and store:

```text
OTX_API_KEY=your_otx_api_key
OTX_MAX_PULSES=100
OTX_REFRESH_HOURS=24
OTX_MAX_INDICATORS=100000
```

in `/etc/excalibur/excalibur.env`.

## Refresh Behavior

The plugin checks refresh state during startup only.

Rules:

- if `metadata.json` is missing, refresh is attempted
- if `last_successful_update` is older than `OTX_REFRESH_HOURS`, refresh is attempted
- only the most recent `OTX_MAX_PULSES` pulses are processed
- if the cache is fresh, refresh is skipped
- if refresh fails, stale cached indicators remain usable

The plugin logs refresh progress, including pulse counts and collected indicator counts.

This means normal packet, DNS, and alert handling never performs network calls.

## Cache Behavior

The plugin stores data under:

```text
data/threat_intel/otx/
├── indicators.jsonl
└── metadata.json
```

`indicators.jsonl` stores normalized indicator records such as:

```json
{"type": "ip", "value": "8.8.8.8"}
{"type": "domain", "value": "bad.example"}
```

`metadata.json` stores refresh metadata such as:

```json
{
  "last_successful_update": "2026-06-19T10:00:00+00:00",
  "indicator_count": 1234,
  "ip_count": 400,
  "domain_count": 800,
  "url_count": 34
}
```

The plugin loads this cache into in-memory Python sets at startup.

## Matching Behavior

The plugin performs exact set membership checks.

Normalization rules:

- domains are lowercased
- trailing dots are stripped from domains
- IPs are validated with Python’s `ipaddress` module
- private, loopback, multicast, reserved, and link-local IPs are discarded

## Troubleshooting

### Plugin loads but shows zero indicators

Check:

- whether `OTX_API_KEY` is configured
- whether `data/threat_intel/otx/indicators.jsonl` exists
- whether the last refresh failed

### Plugin never refreshes

Check:

- `OTX_REFRESH_HOURS`
- `OTX_MAX_PULSES`
- `metadata.json` timestamps
- startup logs for `cached indicators are fresh; skipping OTX refresh`

### Plugin refresh fails

Expected behavior:

- Excalibur startup continues
- stale cache remains loaded
- a warning is logged

Example:

```text
[PLUGIN] OTX Threat Intel OTX refresh failed; using cached indicators only: <error>
```

### DNS matches are missed

Check:

- exact domain normalization
- case differences
- trailing dots in observed DNS names

The plugin normalizes domains to lowercase and strips trailing dots before lookup.
