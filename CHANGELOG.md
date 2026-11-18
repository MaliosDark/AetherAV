# Changelog

All notable changes to AetherAV are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); this project uses calendar-style
versions (e.g. `2026.1.0`).

## [Unreleased]
### Added
- Linux executable and fileless memory inspection with redacted Aegis triage.
- An on-disk SHA-256 catalog, incident signature review, and explicit write approval.
- SSH correlation for multi-host journal exports, a Linux SSH Sigma subset,
  and read-only host security auditing.
- 27 bundled SHA-256 signatures with source links in scan verdicts, plus authenticated
  recent MalwareBazaar and high-confidence ThreatFox hash imports.
- Behavioral trace correlation for temporary payload execution followed by a
  network connection, learned baselines and optional local Aegis triage.
- Detect changes to a learned per-program network endpoint profile and link
  temporary executable activity to Linux cron or systemd autostart changes.
- Behavior-review training records with typed activity counts and separate
  evaluation scenarios.
- 10 detection engines (hash, YARA, ClamAV patterns, parsers, heuristics, static
  ML, Aegis-50M on-device AI, sandbox/emulation, anomaly, threat-intel) + cache.
- Real-time protection: on-access blocking (fanotify), Process Sentinel, memory
  and fileless scanning, ransomware shield with rollback, network monitor.
- Network defense: threat-intelligence firewall (nftables/netsh/pf) and private
  web/phishing protection (hosts-file blocklist).
- Anti-theft: wallet/credential decoys, in-memory key-scraping detection, and a
  crypto clipboard-hijack guard.
- Anti-exploit indicators (NOP sleds, heap spray, stack pivots, egg-hunters).
- Authenticode publisher detection on PE files.
- Ed25519-signed feed and model updates with anti-rollback; reproducible builds.
- Desktop app (Tauri) with system tray and a status widget.
- Premium signed installers for Windows, macOS and Linux + release CI.
- VirusTotal-contributor scan format (`aether vt-scan`).

### Security
- Check signed feed fields for ambiguity, bound feed downloads and write the
  local signature databases atomically.
- Limit Aegis HTTP inference to loopback and bound completion size.
- Update YARA-X, ZIP, TLS dependencies and the 7z reader. Scan files via
  bounded reads to safely handle files modified during inspection.
