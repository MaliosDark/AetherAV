#!/usr/bin/env bash
# Build a premium macOS installer (.pkg) for AetherAV. Run on macOS.
#
# Optional signing/notarization (set these to ship a trusted, Gatekeeper-clean pkg):
#   MAC_INSTALLER_IDENTITY="Developer ID Installer: Your Name (TEAMID)"
#   MAC_NOTARY_PROFILE="aether-notary"   # a stored notarytool keychain profile
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

VER="${VER:-2026.1.0}"
ID_INSTALLER="${MAC_INSTALLER_IDENTITY:-}"
B="installer/macos/build"
rm -rf "$B"; mkdir -p "$B" dist

echo ">> building universal (arm64 + x86_64) CLI"
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true
cargo build --release -p aether-cli --target aarch64-apple-darwin
cargo build --release -p aether-cli --target x86_64-apple-darwin
lipo -create -output "$B/aether" \
  target/aarch64-apple-darwin/release/aether \
  target/x86_64-apple-darwin/release/aether

# ---- CLI component -> /usr/local/bin ----
mkdir -p "$B/root_cli/usr/local/bin"
cp "$B/aether" "$B/root_cli/usr/local/bin/aether"
pkgbuild --root "$B/root_cli" --identifier org.aetherav.cli --version "$VER" \
  --install-location / "$B/cli.pkg"

# ---- App component -> /Applications/AetherAV.app ----
mkdir -p "$B/root_app/Applications"
TAURI_APP="desktop/src-tauri/target/release/bundle/macos/AetherAV.app"
if [ -d "$TAURI_APP" ]; then
  cp -R "$TAURI_APP" "$B/root_app/Applications/"
else
  echo ">> (no Tauri .app found; wrapping the desktop binary into a minimal bundle)"
  APP="$B/root_app/Applications/AetherAV.app"
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/assets"
  cp target/*/release/aether-desktop "$APP/Contents/MacOS/AetherAV" 2>/dev/null || \
    cp "$B/aether" "$APP/Contents/MacOS/AetherAV"
  cp -R assets/. "$APP/Contents/Resources/assets/" 2>/dev/null || true
  cp installer/windows/assets/aetherav.ico "$APP/Contents/Resources/aetherav.icns" 2>/dev/null || true
  cat > "$APP/Contents/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>AetherAV</string>
  <key>CFBundleIdentifier</key><string>org.aetherav.app</string>
  <key>CFBundleVersion</key><string>${VER}</string>
  <key>CFBundleShortVersionString</key><string>${VER}</string>
  <key>CFBundleExecutable</key><string>AetherAV</string>
  <key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
PL
fi
pkgbuild --root "$B/root_app" --identifier org.aetherav.app --version "$VER" \
  --install-location / "$B/app.pkg"

# ---- Real-time component -> LaunchDaemon ----
mkdir -p "$B/root_rt/Library/LaunchDaemons"
cp installer/macos/com.aetherav.realtime.plist \
  "$B/root_rt/Library/LaunchDaemons/org.aetherav.realtime.plist"
pkgbuild --root "$B/root_rt" --identifier org.aetherav.realtime --version "$VER" \
  --scripts installer/macos/scripts --install-location / "$B/realtime.pkg"

# ---- Product archive (the branded wizard) ----
productbuild --distribution installer/macos/distribution.xml \
  --resources installer/macos/resources --package-path "$B" \
  "$B/AetherAV-Installer.pkg"

# ---- Sign + notarize (optional but required for distribution) ----
OUT="dist/AetherAV-${VER}.pkg"
if [ -n "$ID_INSTALLER" ]; then
  productsign --sign "$ID_INSTALLER" "$B/AetherAV-Installer.pkg" "$OUT"
  if [ -n "${MAC_NOTARY_PROFILE:-}" ]; then
    xcrun notarytool submit "$OUT" --keychain-profile "$MAC_NOTARY_PROFILE" --wait
    xcrun stapler staple "$OUT"
  fi
  echo "built + signed: $OUT"
else
  cp "$B/AetherAV-Installer.pkg" "$OUT"
  echo "built (UNSIGNED): $OUT  -- set MAC_INSTALLER_IDENTITY to sign for distribution"
fi
