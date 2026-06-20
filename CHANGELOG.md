# Changelog

All notable changes to AetherAV are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); this project uses calendar-style
versions (e.g. `2026.1.0`).

## [Unreleased]
### Added
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
- Offline signing key model: a compromised server cannot push malicious updates.
