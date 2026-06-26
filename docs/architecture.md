# Excalibur Architecture Intent

Excalibur is currently a per-host endpoint IDS. It runs individually on each machine and does not currently use a central server or agent fleet model.

The project may become open source. Its target users are the creator, homelab users, security practitioners, and blue teamers.

Excalibur exists because I want my own IDS system.

## Current Direction

Excalibur should remain simple, functional, and useful before becoming complex. The current implementation uses Python and Scapy because they are the simplest path to a working IDS.

Scapy is an MVP capture engine, not necessarily the final capture engine forever. If Excalibur reaches packet volume, performance, or environment limits, a Rust/libpcap-based capture engine may be introduced.

However, the normal Excalibur project should remain Python/Scapy-first. A high-performance Rust capture engine may become a separate component or product rather than replacing the simple default version.

## Deployment Model

Excalibur is local-first and per-host.

The dashboard binds to `127.0.0.1` by default for security reasons. Exposing it can be done intentionally by binding Flask to `0.0.0.0`, but remote exposure is not the default security posture.

There is currently no defined direction for multi-user support, RBAC, or centralized multi-agent reporting.

## Detection Philosophy

Excalibur should be a nice functional IDS with quality-of-life features.

The goal is not immediately to defeat Snort or Suricata, but to build a personal IDS that can grow in that direction over time.

ERL exists because Excalibur needs its own rule language so users can write custom detections. ERL should become more powerful over time and may eventually support features such as regex, payload matching, scripting, or plugin-style extensions.

ERL should never become messy, unsafe, confusing slop.

Payload inspection is desirable, but it must be handled carefully because full payload inspection can create performance, storage, and noise problems, especially on normal desktop traffic such as game downloads or large application updates.

## Database Direction

SQLite is acceptable for now.

The database architecture is not final and should be discussed further. SQLite may remain the main local database, but Excalibur may eventually use another database alongside SQLite for massive/high-volume data.

## Dashboard Role

The dashboard is for monitoring, rule setup, visibility, and operational control.

It is not only a debug UI. It is part of the product experience.

## Future Performance Path

Possible future capture/performance options include Rust, libpcap, eBPF, or other high-performance capture mechanisms.

These should not derail the current project.

The current goal is to keep building the working IDS first.
