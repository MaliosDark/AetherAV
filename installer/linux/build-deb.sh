#!/usr/bin/env bash
# Build a Debian/Ubuntu .deb for the AetherAV CLI engine.
#   ./build-deb.sh            -> dist/aetherav_<ver>_amd64.deb
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

VER="${VER:-2026.1.0}"
ARCH="amd64"
BIN="$(ls target/release/aether 2>/dev/null || ls target/debug/aether 2>/dev/null || true)"
[ -n "$BIN" ] || { echo "build the engine first: cargo build --release -p aether-cli"; exit 1; }

STAGE="$(mktemp -d)"
PKG="$STAGE/aetherav"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/share/aetherav" "$PKG/usr/share/doc/aetherav"

install -Dm755 "$BIN" "$PKG/usr/bin/aether"
[ -d assets/signatures ] && cp -r assets/. "$PKG/usr/share/aetherav/" || true
cp installer/LICENSE_EULA.txt "$PKG/usr/share/doc/aetherav/copyright" 2>/dev/null || true

cat > "$PKG/DEBIAN/control" <<EOF
Package: aetherav
Version: ${VER}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: AetherAV <security@aetherav.org>
Depends: libc6
Description: AetherAV - open-source antivirus engine
 Modern, open-source antivirus with on-device AI (Aegis-50M), behavioral
 defense, anti-ransomware rollback, a threat-intelligence firewall, web
 protection and tamper-proof signed updates. Local-first and private.
EOF

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Grant fanotify/firewall capabilities so real-time works without full root.
if command -v setcap >/dev/null 2>&1; then
  setcap 'cap_sys_admin,cap_net_admin,cap_dac_read_search+ep' /usr/bin/aether 2>/dev/null || true
fi
echo "AetherAV installed. Try: aether scan ~/Downloads"
echo "Enable real-time: sudo aether protect /home --quarantine"
exit 0
EOF
chmod 755 "$PKG/DEBIAN/postinst"

mkdir -p dist
OUT="dist/aetherav_${VER}_${ARCH}.deb"
fakeroot dpkg-deb --build "$PKG" "$OUT" >/dev/null
rm -rf "$STAGE"
echo "built: $OUT"
dpkg-deb --info "$OUT" | sed -n '1,12p'
