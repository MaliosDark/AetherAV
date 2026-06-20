#!/usr/bin/env bash
# Build a branded drag-to-install DMG for AetherAV. Run on macOS.
# (The .pkg from build-pkg.sh is the full wizard; this DMG is the lighter,
#  classic "drag the app to Applications" experience.)
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

VER="${VER:-2026.1.0}"
APP="desktop/src-tauri/target/release/bundle/macos/AetherAV.app"
if [ ! -d "$APP" ]; then
  echo "AetherAV.app not found at $APP"
  echo "Build it first (on macOS):  cargo tauri build   (or run build-pkg.sh)"
  exit 1
fi

STAGE="installer/macos/dmg"
rm -rf "$STAGE"; mkdir -p "$STAGE/.background"
cp -R "$APP" "$STAGE/AetherAV.app"
ln -s /Applications "$STAGE/Applications"
cp installer/macos/resources/dmg-background.png "$STAGE/.background/background.png"

# Optional: lay out the window (icon positions + background) if AppleScript is available.
TMP_DMG="installer/macos/AetherAV-tmp.dmg"
rm -f "$TMP_DMG"
hdiutil create -volname "AetherAV ${VER}" -srcfolder "$STAGE" -fs HFS+ \
  -format UDRW -ov "$TMP_DMG"

DEV="$(hdiutil attach -readwrite -noverify -noautoopen "$TMP_DMG" | awk '/Apple_HFS/{print $1; exit}')"
VOL="/Volumes/AetherAV ${VER}"
if command -v osascript >/dev/null 2>&1; then
  osascript <<OSA || true
tell application "Finder"
  tell disk "AetherAV ${VER}"
    open
    set current view of container window to icon view
    set bounds of container window to {200, 120, 820, 520}
    set arrangement of icon view options of container window to not arranged
    set icon size of icon view options of container window to 96
    set background picture of icon view options of container window to file ".background:background.png"
    set position of item "AetherAV.app" of container window to {150, 230}
    set position of item "Applications" of container window to {470, 230}
    update without registering applications
    close
  end tell
end tell
OSA
fi
sync
hdiutil detach "$DEV" >/dev/null || true

mkdir -p dist
hdiutil convert "$TMP_DMG" -format UDZO -ov -o "dist/AetherAV-${VER}.dmg"
rm -f "$TMP_DMG"; rm -rf "$STAGE"

# Sign + notarize + staple the DMG (for a Gatekeeper-clean download).
DMG="dist/AetherAV-${VER}.dmg"
if [ -n "${MAC_APP_IDENTITY:-}" ]; then
  codesign --sign "$MAC_APP_IDENTITY" "$DMG"
  if [ -n "${MAC_NOTARY_PROFILE:-}" ]; then
    echo ">> notarizing (this can take a few minutes)..."
    xcrun notarytool submit "$DMG" --keychain-profile "$MAC_NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
    echo ">> notarized + stapled"
  else
    echo ">> signed (set MAC_NOTARY_PROFILE to also notarize)"
  fi
else
  echo ">> UNSIGNED (set MAC_APP_IDENTITY to sign, MAC_NOTARY_PROFILE to notarize)"
fi
echo "built: $DMG"
