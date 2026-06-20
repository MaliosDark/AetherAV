# Packaging & deployment

## Linux - systemd

Install the binary and assets, then enable the units:

```bash
sudo install -Dm755 target/release/aether /usr/local/bin/aether
sudo mkdir -p /usr/local/share/aether /var/lib/aether/quarantine
sudo cp -r assets /usr/local/share/aether/

# Real-time on-access protection
sudo cp packaging/systemd/aether-watch.service /etc/systemd/system/
sudo systemctl enable --now aether-watch

# Daily scheduled full scan
sudo cp packaging/systemd/aether-scan.{service,timer} /etc/systemd/system/
sudo systemctl enable --now aether-scan.timer

# Keep signatures fresh (cron or a systemd timer):
#   0 */6 * * *  cd /usr/local/share/aether && ABUSE_CH_AUTH_KEY=... ./tools/update-intel.sh
```

## Desktop GUI installers

The Tauri config (`desktop/src-tauri/tauri.conf.json`) already declares bundle
targets. Build native installers with the Tauri CLI:

```bash
cargo install tauri-cli --version "^2"
cd desktop/src-tauri && cargo tauri build      # -> .deb / .AppImage / .rpm (Linux)
```

* **Windows** (`.msi`/`.exe`): build on Windows; register the daemon as a
  Windows Service (e.g. via `sc create` or a WiX custom action).
* **macOS** (`.dmg`): build on macOS; run the daemon via a `launchd` plist.

### Code signing / notarization (required for distribution)

* Windows: Authenticode (`signtool`) with an EV/OV cert.
* macOS: `codesign` + `notarytool` with an Apple Developer ID.
* Tauri's updater supports signed app auto-updates (`tauri signer generate`).

These require certificates/secrets and the target OS, so they are CI/release
concerns rather than code - the configuration hooks are in place.

## Real-time kernel sources (production)

The userspace `aether watch` (cross-platform via `notify`) and `aether monitor`
(`/proc`) cover on-access scanning without privileges. For kernel-grade
telemetry, implement the `aether_realtime::EventSource` trait with:

* **Linux:** eBPF via `aya` (tracepoints `sched_process_exec`, LSM `file_open`).
* **Windows:** ETW + a minifilter driver.
* **macOS:** the EndpointSecurity framework.

All three emit `aether_behavior::Event`s into the same `Collector`, so they drop
straight into the existing behavioral + anomaly pipeline.
