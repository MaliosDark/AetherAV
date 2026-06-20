#!/usr/bin/env bash
# AetherAV - Linux / CLI installer.
#
#   sudo ./install.sh                 interactive install
#   sudo ./install.sh --yes           non-interactive (accept license + defaults)
#   sudo ./install.sh --uninstall     remove AetherAV
#
# Flags: --prefix DIR  --no-realtime  --no-autoupdate  --no-caps  --no-desktop
set -euo pipefail

# ---- options ----
PREFIX="${PREFIX:-/usr/local}"
ASSUME_YES=0; DO_RT=1; DO_UPDATE=1; DO_CAPS=1; DO_DESKTOP=1; UNINSTALL=0
for a in "$@"; do case "$a" in
  --yes|-y) ASSUME_YES=1;;
  --uninstall) UNINSTALL=1;;
  --no-realtime) DO_RT=0;;
  --no-autoupdate) DO_UPDATE=0;;
  --no-caps) DO_CAPS=0;;
  --no-desktop) DO_DESKTOP=0;;
  --prefix=*) PREFIX="${a#*=}";;
  *) echo "unknown option: $a"; exit 2;;
esac; done

C_CY=$'\033[36m'; C_GR=$'\033[32m'; C_DIM=$'\033[2m'; C_B=$'\033[1m'; C_R=$'\033[0m'
[ -t 1 ] || { C_CY=; C_GR=; C_DIM=; C_B=; C_R=; }

SHARE="$PREFIX/share/aetherav"
BINDIR="$PREFIX/bin"
CONFIG="/etc/aetherav/aether.toml"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

banner() {
  echo "${C_CY}${C_B}"
  echo "  =============================================================="
  echo "        _    _____ _____ _   _ _____ ____      _    _   _"
  echo "       / \\  | ____|_   _| | | | ____|  _ \\    / \\  | | | |"
  echo "      / _ \\ |  _|   | | | |_| |  _| | |_) |  / _ \\ | | | |"
  echo "     / ___ \\| |___  | | |  _  | |___|  _ <  / ___ \\| |_| |"
  echo "    /_/   \\_\\_____| |_| |_| |_|_____|_| \\_\\/_/   \\_\\\\___/"
  echo "${C_R}${C_DIM}    Open-source antivirus  *  on-device AI  *  local-first${C_R}"
  echo "${C_CY}${C_B}  ==============================================================${C_R}"
  echo
}

need_root() {
  if [ "$(id -u)" != "0" ]; then
    echo "${C_B}This step needs root.${C_R} Re-run with: ${C_CY}sudo $0 $*${C_R}"
    exit 1
  fi
}

ask() { # ask "question" default(y/n) -> returns 0 for yes
  local q="$1" def="${2:-y}" ans
  [ "$ASSUME_YES" = "1" ] && { [ "$def" = "y" ]; return; }
  read -r -p "  $q [$( [ "$def" = y ] && echo "Y/n" || echo "y/N")] " ans || true
  ans="${ans:-$def}"; [[ "$ans" =~ ^[Yy] ]]
}

find_bin() {
  for c in "$HERE/aether" "$HERE/../../target/release/aether" "$HERE/../../target/debug/aether"; do
    [ -x "$c" ] && { echo "$c"; return; }
  done
}
find_assets() {
  for c in "$HERE/assets" "$HERE/../../assets"; do
    [ -d "$c/signatures" ] && { echo "$c"; return; }
  done
}

# ---- uninstall ----
if [ "$UNINSTALL" = "1" ]; then
  banner; need_root "$@"
  echo "  Removing AetherAV..."
  systemctl disable --now aetherav-realtime.service 2>/dev/null || true
  systemctl disable --now aetherav-update.timer 2>/dev/null || true
  rm -f /etc/systemd/system/aetherav-realtime.service /etc/systemd/system/aetherav-update.service /etc/systemd/system/aetherav-update.timer
  systemctl daemon-reload 2>/dev/null || true
  rm -f "$BINDIR/aether" "$BINDIR/aether-desktop"
  rm -rf "$SHARE"
  echo "  ${C_GR}AetherAV removed.${C_R} (config at /etc/aetherav kept; delete manually if desired.)"
  exit 0
fi

# ---- install ----
banner
BIN="$(find_bin)"; ASSETS="$(find_assets)"
[ -n "$BIN" ] || { echo "  Could not find the 'aether' binary. Build it: cargo build --release -p aether-cli"; exit 1; }
echo "  Engine binary : ${C_CY}$BIN${C_R}"
echo "  Assets        : ${C_CY}${ASSETS:-<none found>}${C_R}"
echo "  Install prefix: ${C_CY}$PREFIX${C_R}"
echo

# License acceptance.
LIC="$HERE/../LICENSE_EULA.txt"; [ -f "$LIC" ] || LIC="$HERE/LICENSE_EULA.txt"
if [ -f "$LIC" ]; then
  echo "${C_B}  LICENSE AGREEMENT${C_R} (${C_DIM}$LIC${C_R})"
  echo "  ----------------------------------------------------------------"
  sed 's/^/  /' "$LIC" | head -28
  echo "  ----------------------------------------------------------------"
  if ! ask "Do you accept the license agreement?" y; then
    echo "  Installation cancelled."; exit 1
  fi
  echo
fi

# Need write access to the prefix (root for system locations).
mkdir -p "$BINDIR" 2>/dev/null || true
if [ ! -w "$BINDIR" ]; then need_root "$@"; fi
ROOT=0; [ "$(id -u)" = "0" ] && ROOT=1
[ "$ROOT" = "1" ] || echo "  ${C_DIM}(not root: system service / capabilities steps will be skipped)${C_R}"

echo "${C_B}  Select components${C_R}"
ask "Install real-time on-access protection (background service)?" y && DO_RT=1 || DO_RT=0
ask "Enable automatic signed signature updates (hourly)?" y && DO_UPDATE=1 || DO_UPDATE=0
[ "$DO_DESKTOP" = "1" ] && [ -x "$HERE/aether-desktop" ] && { ask "Install the desktop app?" y && DO_DESKTOP=1 || DO_DESKTOP=0; } || DO_DESKTOP=0
echo

# 1) binary + assets
echo "  Installing engine to $BINDIR ..."
install -Dm755 "$BIN" "$BINDIR/aether"
[ "$DO_DESKTOP" = "1" ] && install -Dm755 "$HERE/aether-desktop" "$BINDIR/aether-desktop"
if [ -n "$ASSETS" ]; then
  mkdir -p "$SHARE"
  cp -r "$ASSETS"/. "$SHARE/"
fi

# 2) config (system location; needs root)
if [ "$ROOT" = "1" ] && [ ! -f "$CONFIG" ]; then
  mkdir -p /etc/aetherav
  "$BINDIR/aether" config init --output "$CONFIG" >/dev/null 2>&1 || true
  echo "  Wrote default config: $CONFIG"
fi

# 3) capabilities so real-time works without full root each run
if [ "$DO_CAPS" = "1" ] && [ "$ROOT" = "1" ] && command -v setcap >/dev/null 2>&1; then
  setcap 'cap_sys_admin,cap_net_admin,cap_dac_read_search+ep' "$BINDIR/aether" 2>/dev/null \
    && echo "  Granted fanotify/firewall capabilities to aether" \
    || echo "  ${C_DIM}(could not set capabilities; real-time may need sudo)${C_R}"
fi

# 4) real-time service
if [ "$DO_RT" = "1" ] && [ "$ROOT" = "1" ]; then
  cat > /etc/systemd/system/aetherav-realtime.service <<EOF
[Unit]
Description=AetherAV real-time on-access protection
After=network.target

[Service]
Type=simple
ExecStart=$BINDIR/aether -c $CONFIG protect /home --quarantine /var/lib/aetherav/quarantine
Restart=on-failure
Nice=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now aetherav-realtime.service 2>/dev/null \
    && echo "  ${C_GR}Real-time protection enabled.${C_R}" \
    || echo "  ${C_DIM}(service installed; start with: systemctl start aetherav-realtime)${C_R}"
fi

# 5) auto-update timer
if [ "$DO_UPDATE" = "1" ] && [ "$ROOT" = "1" ]; then
  cat > /etc/systemd/system/aetherav-update.service <<EOF
[Unit]
Description=AetherAV signed signature update
[Service]
Type=oneshot
ExecStart=$BINDIR/aether -c $CONFIG update
EOF
  cat > /etc/systemd/system/aetherav-update.timer <<EOF
[Unit]
Description=AetherAV hourly signature update
[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now aetherav-update.timer 2>/dev/null \
    && echo "  ${C_GR}Automatic updates enabled (hourly).${C_R}" || true
fi

echo
echo "  ${C_GR}${C_B}AetherAV installed.${C_R}"
echo "  Try:  ${C_CY}aether scan ~/Downloads${C_R}"
echo "  GUI:  ${C_CY}aether-desktop${C_R}"
[ "$DO_RT" = "1" ] && echo "  Real-time: ${C_CY}systemctl status aetherav-realtime${C_R}"
echo "  Remove:   ${C_CY}sudo $0 --uninstall${C_R}"
