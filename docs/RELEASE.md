# Releasing AetherAV (signed installers, all platforms)

AetherAV ships a premium installer for each OS. The detection content (feed +
model) is already Ed25519-signed; for *distribution* trust you additionally want
OS code-signing so Windows SmartScreen and macOS Gatekeeper don't warn users.

## One-shot: tag a release
Push a `vX.Y.Z` tag. `.github/workflows/release.yml` then builds on all three
runners, produces the installers, Ed25519-signs the `SHA256SUMS`, and publishes a
GitHub Release. Code-signing happens automatically when the secrets below exist.

## Per-platform (manual)

### Windows  ->  `dist\AetherAV-Setup-<ver>.exe`
Needs: Rust, NSIS (`choco install nsis`).
```powershell
./installer/windows/build.ps1
```
Builds `aether.exe` + `aether-desktop.exe`, stages `installer/windows/payload/`,
runs `makensis aetherav.nsi`. The wizard has: Welcome (branded) -> License (EULA)
-> Components (App / CLI+PATH / Real-Time Protection / shortcuts / context menu)
-> Directory -> Install -> Finish. Real-Time registers a logon scheduled task
running the on-access watcher.

### macOS  ->  `dist/AetherAV-<ver>.pkg`
Needs: Rust, Xcode command-line tools. Run on macOS:
```bash
bash installer/macos/build-pkg.sh
```
Universal (arm64+x86_64) CLI, an `AetherAV.app`, and a Real-Time LaunchDaemon,
wrapped by a branded `productbuild` wizard (welcome / license / conclusion).

### Linux  ->  `.deb` + tarball
```bash
bash installer/linux/build-deb.sh          # dist/aetherav_<ver>_amd64.deb
sudo ./installer/linux/install.sh          # or the interactive installer
```

## Code-signing (set as CI secrets)
| Secret | Purpose |
|--------|---------|
| `WIN_CERT_PFX_PATH` / `WIN_CERT_PASS` | Authenticode signing of the Windows binaries + installer (signtool). |
| `MAC_INSTALLER_IDENTITY` | "Developer ID Installer: ..." for `productsign`. |
| `MAC_NOTARY_PROFILE` | Stored `notarytool` profile for notarization + stapling. |
| `AETHER_FEED_PRIVATE_KEY` | Offline Ed25519 key to sign `SHA256SUMS` (keep this OUT of CI if you prefer to sign on the air-gapped signer instead). |

Without these, the build still produces working (unsigned) installers - good for
internal testing, but end users will see OS trust warnings until signed.

## Real-time protection status
The on-access watcher is cross-platform (file events via `notify` =
inotify / FSEvents / ReadDirectoryChanges) and is auto-started by each installer
(scheduled task on Windows, LaunchDaemon on macOS, systemd service on Linux).
True kernel pre-execution blocking exists today on Linux (fanotify, `aether
protect`); a Windows minifilter / macOS EndpointSecurity driver is future work
(needs a signed kernel/system extension).
