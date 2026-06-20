# AetherAV Roadmap

All 11 phases now have a working, tested implementation. Several are deliberately
"v1": real and demonstrable today, with a clearly-marked deeper version next
(e.g. eBPF kernel sources behind the real-time `EventSource` trait, WASM plugins
behind the subprocess protocol, a Tauri GUI atop the HTTP daemon). Each layer is
additive and, where it pulls heavy/native deps, gated behind a Cargo feature so
the engine stays buildable in constrained environments.

| Phase | Layer | Key tech (2026) | Outcome |
|---|---|---|---|
| **1 ✅** | Static + Signature | `goblin`, YARA-X, Bloom, SHA-256/BLAKE3 | Hash + rule + heuristic scanning, CLI |
| **2 ✅** | Universal Parser Layer | PE, ELF, Mach-O, PDF, OLE/OOXML, PS1/JS/VBA | Format-aware feature extraction + per-format heuristics |
| **3 ✅** | Static AI Engine | pure-Rust logistic now; ONNX/LightGBM/XGBoost backend (opt) | Learned PE classifier; Python training pipeline |
| 2.x | Parser depth | APK, WASM, full PDF object graph, deep OLE/VBA parse | Richer features for the carriers stubbed in Phase 2 |
| **5 ✅** | Behavioral + Graph | `petgraph`, MITRE ATT&CK, event-trace ingestion | Injection/ransomware/LOLBin/C2/persistence detection from telemetry |
| **4 ✅** | Dynamic Sandbox & Emulation | `iced-x86` static sweep; optional Unicorn CPU emulation | Anti-evasion (timing/VM/anti-debug) + shellcode (PEB/hash/GetPC) detection |
| 4.x | Sandbox depth | Unicorn API hooks -> behavioral events; QEMU user-mode; eBPF tracing | Full execution traces feeding the Phase-5 event stream |
| **6 ✅** | ML / Anomaly Detection | Welford online stats, per-host baseline, JSON persistence | Novel program/lineage/network/autostart + cmdline-outlier scoring |
| **7 ✅** | Real-time Protection | userspace `/proc` monitor now; eBPF/ETW/ESF slot into the `EventSource` trait | Live process events feed the behavioral + anomaly engines |
| **8 ✅** | Threat Intel & Updates | HMAC-signed feeds, MISP/VT import, delta merge | Hot signature reload (hash-DB export) without restart |
| **9 ✅** | Quarantine, Remediation, Forensics | ChaCha20-Poly1305 vault, timeline, IOC export | Safe encrypted isolation + restore + incident artifacts |
| **10 ✅** | Interfaces | std-only HTTP/JSON daemon (`/scan`, `/behavior`, …); Tauri GUI next | Engine exposed as a service |
| **11 ✅** | Plugin & Extension System | subprocess detector protocol now; WASM/capability sandbox next | Third-party detectors without recompiling core |

## Near-term (Phase 2 entry points already stubbed)

- `aether_parsers::FileFormat` already routes by magic bytes - ELF/Mach-O/PDF
  parsers slot in behind it with no orchestrator changes.
- `aether_common::EngineKind` reserves `Ml` and `Behavioral` so new engines emit
  verdicts through the existing aggregation path.
- `Verdict::mitre` already carries ATT&CK technique IDs end-to-end (the
  heuristic engine emits `T1055` for injection-import combos today).

## Design principles

1. **Local-first.** Every feature works offline; cloud is opt-in.
2. **Memory-safe core.** Rust everywhere in the hot path; `panic=abort`.
3. **Explainable verdicts.** Every detection records *why* (`Verdict::detail`).
4. **Feature-gated heavy deps.** YARA-X, ML runtime, sandbox each behind flags.
5. **Parallel by default.** `rayon` fan-out, engines are `Sync`, no global locks.
