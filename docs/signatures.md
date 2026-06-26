# Excalibur Rule Language v2.2

Excalibur Rule Language (ERL) v2.2 lets analysts define detection signatures in
YAML without writing Python detector classes.

Signatures are organized into rule packs under the `rules/` directory.
`rules/*.yaml` is the only supported runtime source for ERL signatures. Legacy
`signatures.yaml` files are rejected when they contain rules.
Signatures are intended for practical, metadata-based detections such as host
sweeps, port fanout, DNS volume, and unique-domain activity.

## Overview

A signature is a YAML rule that describes:

- what event type to inspect
- what fields must match
- what behavior to aggregate over time
- what alert to create when the threshold is reached

Signatures are different from built-in detectors:

- Built-in detectors are Python classes such as Port Scan, DNS Flood, Unique
  Domains, and Host Sweep.
- Signatures are user-defined YAML rules interpreted by the Signature Engine.
- Built-in detectors can contain specialized Python logic.
- Signatures are safer and simpler, but intentionally less expressive than
  Python detector classes.

At sensor startup, Excalibur loads every `*.yaml` file from `rules/`, validates
each file independently, and compiles valid signatures into runtime objects. It
does not parse YAML on every packet. Packet and DNS events are then evaluated
against the compiled rules. If `signatures.yaml` is present and contains rules,
startup fails with a migration error so legacy rules cannot run outside the
Rules UI.

Startup logs show which packs loaded:

```text
[RULES] Loaded recon.yaml (1 rules)
[RULES] Loaded dns.yaml (0 rules)
Legacy Signatures:
* 0 rules loaded
Rule Packs:
* recon.yaml (1)
* dns.yaml (0)
```

The sensor must currently be restarted after editing signatures because ERL v2.2
does not implement hot reload. Saving from the dashboard updates one selected
rule-pack file under `rules/`, but the running sensor keeps the signatures it
loaded at startup.

## Changelog

### ERL v2.2

#### Added

- New DNS event field: `dns_rcode`
- DNS response-code matching for ERL signatures
- NXDOMAIN Burst detection
- NXDOMAIN Fanout detection

#### Updated

- DNS rule coverage now includes failed DNS lookup behavior.

### ERL v2.1

#### Added

- New packet field: `tcp_flags`
- TCP flags available to all ERL match operators
- SYN-aware port scan detection
- Improved port scan false-positive resistance

#### Updated

- Port Scan rule now evaluates only SYN packets
- Port Scan rule ignores high ephemeral destination ports by default

## Rule Packs

Default rule-pack layout:

```text
rules/
├── recon.yaml
├── dns.yaml
├── ad.yaml
├── databases.yaml
└── web.yaml
```

Each rule-pack file uses the same top-level structure:

```yaml
signatures:
  - name: SMB Recon
    enabled: true
    event: packet
    tags:
      - recon
      - smb
      - mitre:T1595
    match:
      protocol: TCP
      dst_port: 445
    aggregate:
      unique_dst_ips:
        gte: 20
      within_seconds: 60
    alert:
      severity: High
      title: SMB Recon Activity
      description: Source contacted many hosts via SMB.
```

Empty rule packs are valid:

```yaml
signatures:
```

## Rule Structure

All signatures are placed under the top-level `signatures` list:

```yaml
signatures:
  - name: SMB Recon
    enabled: true
    event: packet
    match:
      protocol: TCP
      dst_port: 445
    aggregate:
      unique_dst_ips:
        gte: 20
      within_seconds: 60
    alert:
      severity: High
      title: SMB Recon Activity
      description: Source contacted many hosts via SMB.
```

Fields:

- `name`: Human-readable signature name. Required.
- `enabled`: Enables or disables the signature. Optional; defaults to enabled.
- `event`: Event type to inspect. Supported values are `packet` and `dns`.
- `tags`: Optional list of metadata tags for future dashboard workflows.
- `group_by`: Optional aggregation key. Supported values are `src_ip` and
  `dst_ip`.
- `cooldown_seconds`: Optional per-source alert suppression period after a
  signature triggers.
- `match`: Field conditions that must all match before aggregation.
- `exclude`: Optional per-rule suppression criteria evaluated after `match` and
  before aggregation.
- `aggregate`: Rolling-window behavior that must reach a threshold.
- `alert`: Alert metadata written when the signature triggers.

## Supported Events

### packet

Packet signatures evaluate packet metadata collected by the sensor.

Available fields:

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `packet_size`
- `tcp_flags`

Example:

```yaml
event: packet
match:
  protocol: TCP
  dst_port: 445
```

`tcp_flags` is available only on TCP packet events. It uses Scapy's
human-readable flag representation.

Common TCP flag values:

```text
S   = SYN
SA  = SYN+ACK
A   = ACK
PA  = PSH+ACK
FA  = FIN+ACK
R   = RST
```

### dns

DNS signatures evaluate DNS query metadata collected from observed DNS queries.

Available fields:

- `client_ip`
- `dns_server_ip`
- `query_name`
- `query_type`
- `dns_rcode`

Example:

```yaml
event: dns
match:
  query_type: A
```

`dns_rcode` is populated on DNS response events. Query events that do not carry
a response code use an empty value.

Common DNS response-code values:

```text
NOERROR
NXDOMAIN
SERVFAIL
REFUSED
```

## Match Operators

All conditions in `match` are combined with AND logic. Every listed field must
match for the event to be counted.

### Exact Match

Exact match compares a field to a single value.

```yaml
match:
  protocol: TCP
```

String matching is case-insensitive for scalar comparisons. This means `tcp`
and `TCP` match the same packet protocol value.

Use cases:

- matching `protocol: TCP`
- matching `tcp_flags: S`
- matching `dns_rcode: NXDOMAIN`
- matching `query_type: A`
- matching a specific `src_ip`

Limitations:

- No wildcard matching.

### OR Logic

Use `any` inside `match` to express OR conditions.

```yaml
match:
  protocol: TCP
  any:
    - dst_port: 445
    - dst_port: 389
    - dst_port: 636
```

Meaning:

```text
protocol == TCP
AND
(
  dst_port == 445
  OR dst_port == 389
  OR dst_port == 636
)
```

Each `any` entry is a normal match clause and can use exact, membership, or
network matching.

Example:

```yaml
match:
  any:
    - src_ip:
        in_networks:
          - 10.0.0.0/8
    - src_ip:
        in_networks:
          - 192.168.0.0/16
```

Limitations:

- Nested `any` blocks are not supported.
- There is no arbitrary expression language.

### ALL Logic

Use `all` to explicitly require multiple match clauses.

```yaml
match:
  all:
    - protocol: TCP
    - dst_port: 445
```

This is equivalent to the simpler implicit-AND syntax:

```yaml
match:
  protocol: TCP
  dst_port: 445
```

`all` is useful when composing future generated rules or when you want symmetry
with `any`.

### Numeric Operators

Numeric fields can use exact matching or comparison operators.

```yaml
match:
  dst_port: 445
```

```yaml
match:
  packet_size:
    gt: 1200
```

```yaml
match:
  dst_port:
    gte: 1024
```

Supported numeric operators:

- `gt`
- `gte`
- `lt`
- `lte`

Use cases:

- matching service ports
- matching packet sizes
- matching source ports when useful

Limitations:

- Numeric thresholds must be numbers.

### Membership Match

Membership match checks whether a field value is in a list.

```yaml
match:
  dst_port:
    in: [445, 389, 636]
```

Equivalent block-list format:

```yaml
match:
  dst_port:
    in:
      - 445
      - 389
      - 636
```

Use cases:

- matching multiple related service ports
- grouping protocols or DNS query types
- compactly expressing service families

Limitations:

- List items are exact values.
- No nested lists.
- No negation.

### TCP Flag Matching

TCP flags can use the same scalar, membership, and string operators as other
ERL fields.

Simple SYN match:

```yaml
match:
  tcp_flags: S
```

Membership match:

```yaml
match:
  tcp_flags:
    in:
      - S
      - SA
```

String contains match:

```yaml
match:
  tcp_flags:
    contains: S
```

Combined connection-attempt match:

```yaml
match:
  protocol: TCP
  tcp_flags: S
  dst_port:
    lte: 10000
```

Use cases:

- SYN scan detection
- connection anomaly detection
- reset storm detection
- separating established TCP sessions from connection attempts

### DNS Response-Code Matching

DNS response codes can use the same scalar, membership, and string operators as
other ERL fields.

Simple NXDOMAIN match:

```yaml
match:
  dns_rcode: NXDOMAIN
```

Membership match:

```yaml
match:
  dns_rcode:
    in:
      - NXDOMAIN
      - SERVFAIL
```

Common values:

```text
NOERROR
NXDOMAIN
SERVFAIL
REFUSED
```

Use cases:

- DGA failure detection
- malware beacon failure detection
- failed-domain fanout
- DNS resolver failure storms
- refused DNS response monitoring

### Network Match

Network match checks whether an IP address belongs to one of the configured
CIDR networks.

```yaml
match:
  src_ip:
    in_networks:
      - 10.0.0.0/8
      - 192.168.0.0/16
```

Use cases:

- matching internal source networks
- limiting signatures to lab, office, or server VLANs
- avoiding public internet traffic in internal recon rules

Limitations:

- Only IP fields should use `in_networks`.
- Invalid CIDR values fail validation.
- Use `not` with `in_networks` to negate a network match.

### String Operators

String operators are case-insensitive and intended for lightweight text fields
such as DNS names, analyzer reason strings, and TCP flags.

```yaml
match:
  query_name:
    contains: login
```

Quoted YAML strings are supported and are loaded as the raw value, not with
literal quote characters:

```yaml
match:
  query_name:
    contains: "xn--"
```

This matches query names containing `xn--`.

```yaml
match:
  query_name:
    startswith: api
```

```yaml
match:
  query_name:
    endswith: .xyz
```

```yaml
match:
  query_name:
    contains_any:
      - login
      - verify
      - wallet
```

Use cases:

- matching browser credential or account keywords
- matching suspicious DNS query names
- matching analyzer reason strings

Limitations:

- No wildcard matching.
- `contains_any` requires a non-empty list.
- `endswith_any` requires a non-empty list.

Supported forms:

```yaml
match:
  query_name:
    endswith: .zip
```

```yaml
match:
  query_name:
    endswith_any:
      - .zip
      - .mov
```

### Regex Matching

Use `regex` for compact pattern matching when literal string operators are not
enough.

```yaml
match:
  query_name:
    regex: "^[a-z0-9]{20,}\\."
```

```yaml
match:
  query_name:
    regex: ".*xn--.*"
```

Behavior:

- Regex matching is case-insensitive.
- ERL uses Python `re.search()` semantics, so the pattern can match anywhere
  unless anchored.
- Patterns are compiled during validation and invalid regex fails validation.

### NOT Logic

Use `not` inside `match` to negate a normal match clause.

```yaml
match:
  protocol: TCP
  not:
    dst_port:
      in:
        - 80
        - 443
```

Meaning:

```text
protocol == TCP
AND
NOT(dst_port in [80, 443])
```

`not` can use the same field operators as normal `match` clauses, including
network matches:

```yaml
match:
  not:
    src_ip:
      in_networks:
        - 10.0.0.0/8
```

Limitations:

- Nested `not` blocks are not supported.

### Numeric Threshold Match

`gte` can be used in `match` for numeric event fields such as browser domain
risk scores.

```yaml
match:
  risk_score:
    gte: 80
```

## Rule-Level Exclusions

Use `exclude` to ignore known-good activity for one rule without weakening other
rules. Evaluation order is:

1. `match`
2. `exclude`
3. `aggregate`
4. `alert`

If an event matches any configured exclude value, Excalibur does not count it,
does not aggregate it, and does not alert for that rule. Other rules still
evaluate the same event normally.

### IP Exclusions

Packet rules can exclude source or destination IPs:

```yaml
exclude:
  src_ip:
    - 10.0.2.10
  dst_ip:
    - 10.0.2.20
```

DNS rules can exclude DNS event IP fields:

```yaml
exclude:
  client_ip:
    - 10.0.2.10
  dns_server_ip:
    - 10.0.2.53
```

### Network Exclusions

CIDR networks are supported on IP fields:

```yaml
exclude:
  src_ip:
    - 10.0.2.0/24
  dst_ip:
    - 192.168.1.0/24
```

### Port Exclusions

Packet rules can exclude source or destination ports:

```yaml
exclude:
  dst_port:
    - 5985
  src_port:
    - 53
```

### Example: WinRM Allowed Targets

```yaml
signatures:
  - name: WinRM Activity
    enabled: true
    event: packet
    match:
      protocol: TCP
      dst_port:
        in:
          - 5985
          - 5986
    exclude:
      dst_ip:
        - 10.0.2.10
    aggregate:
      count:
        gte: 20
      within_seconds: 60
    alert:
      severity: High
      title: WinRM Activity Detected
      description: Significant WinRM traffic observed.
```

This rule ignores WinRM traffic to `10.0.2.10`, while still detecting WinRM
activity to other hosts.

## Aggregate Operators

Aggregation is what turns matching events into behavior. A matching event is
added to a rolling window. If the aggregate reaches the configured threshold
inside `within_seconds`, Excalibur creates an alert.

Each signature must define one or more aggregate thresholds plus
`within_seconds`. When multiple aggregate thresholds are present, all thresholds
must be satisfied. This is logical AND.

Example:

```yaml
aggregate:
  unique_dst_ips:
    gte: 20
  count:
    gte: 100
  within_seconds: 60
```

Meaning:

```text
unique_dst_ips >= 20
AND
count >= 100
within 60 seconds
```

### count

Counts matching events.

```yaml
aggregate:
  count:
    gte: 100
  within_seconds: 60
```

Behavior:

- Every matching event from the same source is counted.
- For packet events, the source key is `src_ip`.
- For DNS events, the source key is `client_ip`.
- Alerts when the count is greater than or equal to `gte`.

Common use cases:

- high DNS query rate
- high packet volume to a sensitive service
- repeated access to one service

### unique_dst_ips

Counts unique destination IPs contacted by a source.

```yaml
aggregate:
  unique_dst_ips:
    gte: 20
  within_seconds: 60
```

Behavior:

- Packet events only.
- Tracks distinct `dst_ip` values per `src_ip`.
- Alerts when one source reaches the unique host threshold.

Common use cases:

- SMB sweeps
- RDP sweeps
- internal host discovery
- service reconnaissance

### unique_dst_ports

Counts unique destination ports contacted by a source.

```yaml
aggregate:
  unique_dst_ports:
    gte: 30
  within_seconds: 60
```

Behavior:

- Packet events only.
- Tracks distinct `dst_port` values per `src_ip`.
- Alerts when one source reaches the unique port threshold.

Common use cases:

- port scan behavior
- unusual service enumeration
- noisy lateral movement tooling

### unique_domains

Counts unique DNS query names from a client.

```yaml
aggregate:
  unique_domains:
    gte: 100
  within_seconds: 60
```

Behavior:

- DNS events only.
- Tracks distinct normalized `query_name` values per `client_ip`.
- Domains are compared lowercase and without a trailing dot.

Common use cases:

- DNS tunneling suspicion
- malware domain generation activity
- unusually broad domain lookups

### within_seconds

Defines the rolling time window.

```yaml
aggregate:
  count:
    gte: 100
  within_seconds: 60
```

Behavior:

- Old events outside the window are pruned.
- The threshold must be reached inside the window.
- Smaller windows are more sensitive to bursts.
- Larger windows detect slower behavior but may increase false positives.

## Grouping

Use `group_by` to control which field owns aggregation state.

```yaml
group_by: src_ip
```

Supported values:

- `src_ip`
- `dst_ip`

For packet events:

- `src_ip` groups by packet source IP.
- `dst_ip` groups by packet destination IP.

For DNS events:

- `src_ip` maps to `client_ip`.
- `dst_ip` maps to `dns_server_ip`.

Without `group_by`, Excalibur preserves the previous behavior:

- packet signatures group by `src_ip`
- DNS signatures group by `client_ip`

Example:

```yaml
aggregate:
  unique_dst_ports:
    gte: 20
  within_seconds: 60
group_by: src_ip
```

Meaning: track unique destination ports independently for each source.

## Cooldowns

Use `cooldown_seconds` to suppress repeated alerts from the same source after a
signature triggers.

```yaml
signatures:
  - name: SMB Recon
    enabled: true
    event: packet
    cooldown_seconds: 300
    match:
      protocol: TCP
      dst_port: 445
    aggregate:
      unique_dst_ips:
        gte: 20
      within_seconds: 60
    alert:
      severity: High
      title: SMB Recon Activity
      description: Source contacted many hosts via SMB.
```

Behavior:

- Packet signatures apply cooldown per active group key.
- DNS signatures apply cooldown per active group key.
- Additional alerts from the same rule and group are suppressed until the
  cooldown expires.
- Different groups have independent cooldown timers.
- `cooldown_seconds` must be a positive integer.

Without `cooldown_seconds`, ERL suppresses repeated alerts while the same source
remains continuously above threshold and allows a new alert after the source
falls below threshold and later crosses it again.

## Rule Statistics

Excalibur stores rule statistics in SQLite for future dashboard use.

Tracked fields:

- rule name
- hits
- alerts generated
- last triggered

`hits` increment when a signature's aggregate thresholds are satisfied. Alerts
increment only when alert generation is not suppressed by cooldown behavior.

## Alert Section

Every signature must include an `alert` section.

```yaml
alert:
  severity: Medium
  title: Possible DNS Flood
  description: Source generated high DNS query volume.
```

### severity

Supported values:

- `Low`
- `Medium`
- `High`

Use `Low` for noisy or exploratory rules, `Medium` for suspicious behavior
that needs review, and `High` for activity that is likely malicious or highly
impactful in your environment.

### title

Short alert title displayed in the dashboard.

Example:

```yaml
title: SMB Recon Activity
```

### description

Analyst-facing explanation of the behavior.

Example:

```yaml
description: Source contacted many hosts via SMB.
```

## Validation

The dashboard validates signatures before saving. The sensor also validates
signatures at startup.

Required fields:

- `name`
- `aggregate`
- `alert`
- `alert.severity`
- `alert.title`
- `alert.description`
- one aggregate threshold
- `within_seconds`

Optional fields:

- `enabled`
- `event`
- `match`
- `cooldown_seconds`
- `group_by`
- `tags`

If `event` is omitted, Excalibur infers it from the signature. For clarity,
prefer setting `event` explicitly.

### Invalid: Unknown Aggregate

```yaml
signatures:
  - name: Broken Rule
    enabled: true
    event: packet
    aggregate:
      unique_potatoes:
        gte: 20
      within_seconds: 60
    alert:
      severity: Medium
      title: Broken Rule
      description: Invalid aggregate example.
```

Expected error:

```text
Rule 'Broken Rule': Unknown aggregate 'unique_potatoes'.
```

### Invalid: Unknown Operator

```yaml
signatures:
  - name: Broken Operator
    enabled: true
    event: packet
    match:
      dst_port:
        potato: 445
    aggregate:
      count:
        gte: 10
      within_seconds: 60
    alert:
      severity: Medium
      title: Broken Operator
      description: Invalid operator example.
```

Expected error:

```text
Rule 'Broken Operator': Unknown match operator 'potato'.
```

### Invalid: Missing Alert Section

```yaml
signatures:
  - name: Missing Alert
    enabled: true
    event: packet
    aggregate:
      count:
        gte: 10
      within_seconds: 60
```

Expected error:

```text
Rule 'Missing Alert': Missing alert section.
```

### Invalid: Bad Cooldown

```yaml
signatures:
  - name: Bad Cooldown
    enabled: true
    event: packet
    cooldown_seconds: 0
    aggregate:
      count:
        gte: 10
      within_seconds: 60
    alert:
      severity: Medium
      title: Bad Cooldown
      description: Invalid cooldown example.
```

Expected error:

```text
Rule 'Bad Cooldown': cooldown_seconds must be a positive integer.
```

## Examples

### 1. Port Scan

```yaml
signatures:
  - name: Port Scan
    enabled: true
    event: packet
    cooldown_seconds: 300
    match:
      protocol: TCP
      tcp_flags: S
      dst_port:
        lte: 10000
    aggregate:
      unique_dst_ports:
        gte: 30
      count:
        gte: 50
      within_seconds: 60
    alert:
      severity: High
      title: Port Scan Activity
      description: Source attempted connections to many service ports.
```

Explanation: Detects one source attempting connections to many lower service
ports.

Trigger behavior: One source sends at least 50 TCP SYN packets to 30 or more
unique destination ports at or below 10000 within 60 seconds. Established
session traffic such as ACK, PSH+ACK, FIN+ACK, and server SYN+ACK replies does
not match.

### 2. SMB Recon

```yaml
signatures:
  - name: SMB Recon
    enabled: true
    event: packet
    cooldown_seconds: 300
    match:
      protocol: TCP
      dst_port: 445
    aggregate:
      unique_dst_ips:
        gte: 20
      within_seconds: 60
    alert:
      severity: High
      title: SMB Recon Activity
      description: Source contacted many hosts via SMB.
```

Explanation: Detects a source contacting many hosts over SMB.

Trigger behavior: One `src_ip` contacts 20 or more unique `dst_ip` values on TCP
445 within 60 seconds. Repeated alerts from the same source are suppressed for
300 seconds.

### 3. RDP Sweep

```yaml
signatures:
  - name: RDP Sweep
    enabled: true
    event: packet
    match:
      protocol: TCP
      dst_port: 3389
    aggregate:
      unique_dst_ips:
        gte: 15
      within_seconds: 60
    alert:
      severity: High
      title: RDP Sweep Activity
      description: Source contacted many hosts via RDP.
```

Explanation: Detects broad RDP probing or lateral movement preparation.

Trigger behavior: One source contacts 15 or more unique hosts on TCP 3389 within
60 seconds.

### 4. HTTPS Fanout

```yaml
signatures:
  - name: HTTPS Fanout
    enabled: true
    event: packet
    match:
      protocol: TCP
      dst_port: 443
      src_ip:
        in_networks:
          - 10.0.0.0/8
          - 192.168.0.0/16
    aggregate:
      unique_dst_ips:
        gte: 100
      within_seconds: 60
    alert:
      severity: Medium
      title: High HTTPS Fanout
      description: Internal source contacted many HTTPS destinations.
```

Explanation: Detects an internal host making HTTPS connections to many distinct
destinations.

Trigger behavior: One internal source contacts 100 or more unique destination
IPs on TCP 443 within 60 seconds.

### 5. High DNS Activity

```yaml
signatures:
  - name: High DNS Activity
    enabled: true
    event: dns
    match:
      query_type: A
    aggregate:
      count:
        gte: 500
      within_seconds: 60
    alert:
      severity: Medium
      title: High DNS Query Volume
      description: Client generated high DNS A-record query volume.
```

Explanation: Detects a DNS client making many A-record queries.

Trigger behavior: One `client_ip` makes 500 or more matching DNS queries within
60 seconds.

### 6. NXDOMAIN Burst

```yaml
signatures:
  - name: NXDOMAIN Burst
    enabled: true
    event: dns
    cooldown_seconds: 300
    match:
      dns_rcode: NXDOMAIN
    aggregate:
      count:
        gte: 50
      within_seconds: 60
    alert:
      severity: Medium
      title: Excessive NXDOMAIN Responses
      description: Client generated many failed DNS lookups.
```

Explanation: Detects many failed DNS lookups from one client.

Trigger behavior: One `client_ip` receives 50 or more NXDOMAIN responses within
60 seconds.

### 7. NXDOMAIN Fanout

```yaml
signatures:
  - name: NXDOMAIN Fanout
    enabled: true
    event: dns
    cooldown_seconds: 300
    match:
      dns_rcode: NXDOMAIN
    aggregate:
      unique_domains:
        gte: 25
      within_seconds: 60
    alert:
      severity: High
      title: Excessive Failed Domain Lookups
      description: Client queried many unique non-existent domains.
```

Explanation: Detects a client receiving failures for many distinct domains.

Trigger behavior: One `client_ip` receives NXDOMAIN responses for 25 or more
unique domains within 60 seconds.

### 8. Excessive Unique Domains

```yaml
signatures:
  - name: Excessive Unique Domains
    enabled: true
    event: dns
    match:
      query_type:
        in: [A, AAAA]
    aggregate:
      unique_domains:
        gte: 100
      within_seconds: 60
    alert:
      severity: Medium
      title: Excessive Unique DNS Queries
      description: Client queried many unique domains.
```

Explanation: Detects clients querying a large number of distinct domains.

Trigger behavior: One `client_ip` queries 100 or more unique domain names using
query type `A` or `AAAA` within 60 seconds.

### 9. LDAP Recon

```yaml
signatures:
  - name: LDAP Recon
    enabled: true
    event: packet
    match:
      protocol: TCP
      any:
        - dst_port: 389
        - dst_port: 636
    aggregate:
      unique_dst_ips:
        gte: 10
      within_seconds: 60
    alert:
      severity: Medium
      title: LDAP Recon Activity
      description: Source contacted many LDAP services.
```

Explanation: Detects LDAP or LDAPS probing across multiple hosts. This example
uses OR logic through `any`.

Trigger behavior: One source contacts 10 or more unique hosts on TCP 389 or TCP
636 within 60 seconds.

### 10. SSH Recon

```yaml
signatures:
  - name: SSH Recon
    enabled: true
    event: packet
    match:
      protocol: TCP
      dst_port: 22
    aggregate:
      unique_dst_ips:
        gte: 20
      within_seconds: 120
    alert:
      severity: Medium
      title: SSH Recon Activity
      description: Source contacted many hosts via SSH.
```

Explanation: Detects broad SSH probing.

Trigger behavior: One source contacts 20 or more unique hosts on TCP 22 within
120 seconds.

### 11. Database Recon (3306)

```yaml
signatures:
  - name: Database Recon 3306
    enabled: true
    event: packet
    match:
      protocol: TCP
      dst_port: 3306
    aggregate:
      unique_dst_ips:
        gte: 10
      within_seconds: 60
    alert:
      severity: High
      title: MySQL Recon Activity
      description: Source contacted many MySQL database services.
```

Explanation: Detects scanning for MySQL-compatible database services.

Trigger behavior: One source contacts 10 or more unique hosts on TCP 3306 within
60 seconds.

### 12. WinRM Recon (5985)

```yaml
signatures:
  - name: WinRM Recon
    enabled: true
    event: packet
    match:
      protocol: TCP
      dst_port: 5985
    aggregate:
      unique_dst_ips:
        gte: 15
      within_seconds: 60
    alert:
      severity: High
      title: WinRM Recon Activity
      description: Source contacted many hosts via WinRM.
```

Explanation: Detects broad WinRM service probing.

Trigger behavior: One source contacts 15 or more unique hosts on TCP 5985 within
60 seconds.

### 13. Custom Internal Sweep

```yaml
signatures:
  - name: Custom Internal Sweep
    enabled: true
    event: packet
    match:
      protocol: TCP
      src_ip:
        in_networks:
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
      dst_port:
        in: [135, 139, 445, 3389, 5985]
    aggregate:
      unique_dst_ips:
        gte: 25
      count:
        gte: 50
      within_seconds: 120
    alert:
      severity: High
      title: Custom Internal Sweep
      description: Internal source contacted many hosts on administrative ports.
```

Explanation: Detects internal hosts touching many systems on common Windows
administration ports.

Trigger behavior: One internal source contacts 25 or more unique destination
IPs and makes at least 50 matching connections on one of the listed ports within
120 seconds.

## Current Limitations

ERL v2.2 intentionally keeps the language small and safe.

Current limitations:

- No nested boolean expressions.
- No payload inspection.
- No packet content matching.
- No hot reload.
- No dynamic alert descriptions.
- No arbitrary code execution.
- No Python execution from YAML.
- No custom aggregate plugins.

## Best Practices

Start with conservative thresholds. Low thresholds are useful in a lab, but can
create noisy alerts on real networks.

Tune by environment:

- Workstations may naturally contact many HTTPS destinations.
- Domain controllers may generate or receive high authentication traffic.
- Vulnerability scanners should be excluded or handled with dedicated rules.
- DNS resolvers and proxies may need different thresholds than endpoints.

Use `enabled: false` while drafting signatures. Validate and save the rule, then
enable it after reviewing the logic.

Prefer narrow `match` sections for high-severity alerts. For example, combine
`protocol`, `dst_port`, and `src_ip.in_networks` to avoid broad rules that match
normal internet activity.

Test signatures with synthetic or controlled traffic before relying on them in
production. Watch the Alerts page and System Health page after enabling new
rules.

Review signature quality over time:

- Does the signature produce actionable alerts?
- Does it repeatedly alert on known benign systems?
- Is the threshold too low for business hours?
- Should the window be shorter or longer?
- Should the rule severity be reduced?

## Future Features

Planned ERL improvements may include:

- nested expressions
- hot reload
- payload-aware rules
- richer alert templating
- signature testing tools
