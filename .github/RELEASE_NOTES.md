## Install

Download the installer for your OS and CPU below.

| OS | File | Architectures |
|----|------|---------------|
| 🪟 Windows | `AetherAV-Setup-*.exe` | x86_64 · arm64 |
| 🍎 macOS | `AetherAV-*.pkg` / `AetherAV-*.dmg` | universal (Intel + Apple Silicon) |
| 🐧 Linux | `aetherav_*.deb` / `aetherav-linux-*.tar.gz` | x86_64 · aarch64 |

### ⚠️ Unsigned on purpose — needs admin/root, and your OS will warn you

AetherAV is **not** signed with a paid code-signing certificate. That's by design:
a paid cert only proves someone paid a CA — it says nothing about whether the code
is safe. Instead you get a **stronger, auditable trust path**: reproducible builds
plus an **Ed25519-signed `SHA256SUMS`** you can verify yourself. Installing a
real-time security service needs **administrator / root** on any OS.

- **🪟 Windows** — run `AetherAV-Setup-*.exe`. If SmartScreen warns
  (*"Windows protected your PC"*) → **More info → Run anyway**, then approve the
  **administrator (UAC)** prompt.
- **🍎 macOS** — *"unidentified developer"*: **right-click → Open → Open**
  (not double-click), or `xattr -dr com.apple.quarantine <file>`. It asks for your
  password to install the service.
- **🐧 Linux** — needs **`sudo`**: `sudo apt install ./aetherav_*.deb`
  (or `sudo ./install.sh`).

### ✅ Verify your download (5 seconds, beats any paid cert)

```bash
sha256sum -c SHA256SUMS          # bytes match the published hashes
aether verifyfile SHA256SUMS     # the hash list is Ed25519-signed by us -> TRUSTED
```
